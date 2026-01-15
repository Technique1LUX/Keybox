import os
import time
import requests
import traceback
import logging
from threading import Lock
from functools import wraps
from secrets import token_urlsafe
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("keybox")

app.config.update(
    SESSION_COOKIE_SECURE=True,      # OK sur Render (https)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_only_change_me")

TZ = ZoneInfo("Europe/Luxembourg")

VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
PIN_DURATION_HOURS = int(os.getenv("PIN_DURATION_HOURS", "4"))

# Airtable
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")

T_KEYBOXES = os.getenv("AIRTABLE_TABLE_KEYBOXES", "Keyboxes")
T_USERS = os.getenv("AIRTABLE_TABLE_USERS", "Users")
T_PERMS = os.getenv("AIRTABLE_TABLE_PERMISSIONS", "Permissions")
T_LOG = os.getenv("AIRTABLE_TABLE_ACCESSLOG", "AccessLog")
T_REQUESTS = os.getenv("AIRTABLE_TABLE_REQUESTS", "Requests")

print("AIRTABLE_BASE_ID =", AIRTABLE_BASE_ID)
print("T_LOG =", T_LOG)
print("AIRTABLE_API_KEY prefix =", (AIRTABLE_API_KEY or "")[:6])


# Igloo
IGLOO_CLIENT_ID = os.getenv("IGLOO_CLIENT_ID")
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")
AUTH_URL = "https://auth.igloohome.co/oauth2/token"
API_BASE = "https://api.igloodeveloper.co/igloohome"

# Admin
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change_me")

# token cache + rate limit in memory
_token_cache = {"token": None, "exp": 0}
_rl = {}

_qr_locks = {}

def _get_lock(qrid: str) -> Lock:
    if qrid not in _qr_locks:
        _qr_locks[qrid] = Lock()
    return _qr_locks[qrid]


# ------------------ Time helpers ------------------
def now_lu():
    return datetime.now(TZ)

def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.astimezone(TZ).isoformat(timespec="seconds")

def parse_iso(s: str):
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)  # fallback Luxembourg si string sans offset
        return dt
    except Exception:
        return None

def is_active_window(start_iso: str, end_iso: str) -> bool:
    s = parse_iso(start_iso) if start_iso else None
    e = parse_iso(end_iso) if end_iso else None
    if not s or not e:
        return False
    now = now_lu()
    return s <= now < e

def round_down_hour(dt: datetime) -> datetime:
    dt = dt.astimezone(TZ)
    return dt.replace(minute=0, second=0, microsecond=0)

def next_hour(dt: datetime) -> datetime:
    return round_down_hour(dt) + timedelta(hours=1)
    
def get_current_pin_only(kb):
    """
    Retourne uniquement un PIN utilisable MAINTENANT.
    Ne génère PAS de nouveau PIN.
    Peut promouvoir Next->Active si la fenêtre a commencé.
    """
    if not kb:
        return None, None, None, None, "Keybox introuvable"

    rid = kb.get("id")
    f = kb.get("fields", {})

    # 1) ActivePin valable maintenant
    ap = f.get("ActivePin")
    apid = f.get("ActivePinId")
    a_s = f.get("ActiveStart")
    a_e = f.get("ActiveEnd")
    if ap and is_active_window(a_s, a_e):
        return ap, apid, a_s, a_e, None

    # 2) NextPin devenu actif ? -> promote vers Active
    np = f.get("NextPin")
    npid = f.get("NextPinId")
    n_s = f.get("NextStart")
    n_e = f.get("NextEnd")
    if np and is_active_window(n_s, n_e):
        at_update(T_KEYBOXES, rid, {
            "ActivePin": np,
            "ActivePinId": npid or None,
            "ActiveStart": n_s,
            "ActiveEnd": n_e,
            "NextPin": None,
            "NextPinId": None,
            "NextStart": None,
            "NextEnd": None
        })
        return np, npid, n_s, n_e, None

    # 3) NextPin existe mais pas encore actif => ne PAS l'afficher
    if f.get("NextPin") and f.get("NextStart"):
        return None, None, None, None, f"PIN prêt pour {f.get('NextStart')} (pas encore actif)."

    # 4) Rien du tout
    return None, None, None, None, "Aucun PIN actif disponible."
  

# ------------------ Airtable client ------------------
def at_url(table: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{table}"

def at_headers(json=False):
    h = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    if json:
        h["Content-Type"] = "application/json"
    return h

def at_get(table: str, formula: str = "", max_records: int = 50):
    params = {"maxRecords": max_records}
    if formula:
        params["filterByFormula"] = formula
    r = requests.get(at_url(table), headers=at_headers(), params=params, timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json().get("records", [])
    
def at_get_sorted(table: str, formula: str = "", max_records: int = 50, sort_field: str = "Timestamp", direction: str = "desc"):
    params = {
        "maxRecords": max_records,
        "sort[0][field]": sort_field,
        "sort[0][direction]": direction
    }
    if formula:
        params["filterByFormula"] = formula
    r = requests.get(at_url(table), headers=at_headers(), params=params, timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json().get("records", [])
    
    
def at_read(table: str, record_id: str):
    r = requests.get(
        f"{at_url(table)}/{record_id}",
        headers=at_headers(),
        timeout=20,
        verify=VERIFY_SSL
    )
    if r.status_code != 200:
        raise RuntimeError(f"Airtable read failed {r.status_code}: {r.text}")
    return r.json()

def at_create(table: str, fields: dict):
    r = requests.post(
        at_url(table),
        headers=at_headers(json=True),
        json={"fields": fields},
        timeout=20,
        verify=VERIFY_SSL
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Airtable create failed {r.status_code}: {r.text}")
    return r.json()

def at_update(table: str, record_id: str, fields: dict):
    r = requests.patch(
        f"{at_url(table)}/{record_id}",
        headers=at_headers(json=True),
        json={"fields": fields},
        timeout=20,
        verify=VERIFY_SSL
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Airtable update failed {r.status_code}: {r.text}")
    return r.json()

# ------------------ Igloo OAuth + AlgoPIN ------------------
def get_oauth_token() -> str:
    now_ts = int(time.time())
    if _token_cache["token"] and now_ts < (_token_cache["exp"] - 120):
        return _token_cache["token"]

    if not IGLOO_CLIENT_ID or not IGLOO_CLIENT_SECRET:
        raise RuntimeError("IGLOO_CLIENT_ID / IGLOO_CLIENT_SECRET manquants (env).")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "keybox/1.0",
    }

    r = requests.post(
        AUTH_URL,
        auth=(IGLOO_CLIENT_ID.strip(), IGLOO_CLIENT_SECRET.strip()),
        headers=headers,
        data="grant_type=client_credentials",
        timeout=20,
        verify=VERIFY_SSL,
    )
    if r.status_code != 200:
        raise RuntimeError(f"OAuth failed {r.status_code}: {r.text}")

    j = r.json()
    token = j.get("access_token")
    exp_in = int(j.get("expires_in", 3600))
    if not token:
        raise RuntimeError(f"OAuth token missing: {r.text}")

    _token_cache["token"] = token
    _token_cache["exp"] = now_ts + exp_in
    return token

def rotate_variance_hourly(cur: int) -> int:
    if cur not in (1, 2, 3):
        cur = 1
    return 1 if cur == 3 else cur + 1

def igloo_create_hourly_pin(kb, start_dt: datetime, end_dt: datetime):
    try:
        # Attention: adapter selon TON endpoint (igloodeveloper)
        device_id = kb.get("fields", {}).get("DeviceId") or kb.get("fields", {}).get("deviceId") or kb.get("fields", {}).get("LockID")
        if not device_id:
            return None, None, "DeviceId manquant"

        token = token = get_oauth_token()  # ta fonction existante OAuth (Bearer)
        url = f"https://api.igloodeveloper.co/igloohome/devices/{device_id}/algopin/hourly"

                # force timezone Luxembourg + arrondi propre
        start_dt = start_dt.astimezone(TZ).replace(minute=0, second=0, microsecond=0)
        end_dt = end_dt.astimezone(TZ).replace(minute=0, second=0, microsecond=0)

        payload = {
            "variance": int(kb.get("fields", {}).get("VarianceHourly", 1)),
            "startDate": start_dt.isoformat(timespec="seconds"),
            "endDate": end_dt.isoformat(timespec="seconds"),
            "accessName": "PREFILL"
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        r = requests.post(url, json=payload, headers=headers, timeout=20, verify=VERIFY_SSL)
        if r.status_code not in (200, 201):
            return None, None, f"Igloo {r.status_code}: {r.text}"

        j = r.json()
        return j.get("pin"), j.get("pinId"), None

    except Exception as e:
        return None, None, str(e)

# ------------------ Rate limit ------------------
def rate_limit(key: str, max_req=5, window_sec=600) -> bool:
    now = time.time()
    lst = _rl.get(key, [])
    lst = [t for t in lst if (now - t) < window_sec]
    if len(lst) >= max_req:
        _rl[key] = lst
        return False
    lst.append(now)
    _rl[key] = lst
    return True

# ------------------ Business: users/permissions ------------------
def norm_phone(p: str) -> str:
    return (p or "").strip().replace(" ", "")

def norm_email(e: str) -> str:
    return (e or "").strip().lower()

def find_user(email: str, phone: str):
    email = norm_email(email)
    phone = norm_phone(phone)
    parts = []
    if email:
        parts.append(f"{{Email}}='{email}'")
    if phone:
        parts.append(f"{{Phone}}='{phone}'")
    if not parts:
        return None
    formula = "OR(" + ",".join(parts) + ")" if len(parts) > 1 else parts[0]
    recs = at_get(T_USERS, formula=formula, max_records=5)
    return recs[0] if recs else None

def upsert_user(first, last, company, email, phone, status="approved"):
    email = norm_email(email)
    phone = norm_phone(phone)
    existing = find_user(email, phone)
    fields = {
        "FirstName": first,
        "LastName": last,
        "Company": company,
        "Email": email,
        "Phone": phone,
        "Status": status
    }
    if existing:
        return at_update(T_USERS, existing["id"], fields)
    return at_create(T_USERS, fields)

def create_permission(qrid: str, email: str, phone: str, active=True):
    fields = {
        "QRID": qrid,
        "Email": norm_email(email),
        "Phone": norm_phone(phone),
        "Active": bool(active)
    }
    return at_create(T_PERMS, fields)
    
def create_request(client: str, qrid: str, first: str, last: str, company: str, email: str, phone: str):
    return at_create(T_REQUESTS, {
        "Client": client or "",
        "QRID": qrid or "",
        "FirstName": first or "",
        "LastName": last or "",
        "Company": company or "",
        "Email": norm_email(email),
        "Phone": norm_phone(phone),
        "Status": "pending",
        "CreatedAt": iso(now_lu()),
    })

def set_permission_active(perm_record_id: str, active: bool):
    return at_update(T_PERMS, perm_record_id, {"Active": bool(active)})

def is_user_allowed(qrid: str, email: str, phone: str):
    email = norm_email(email)
    phone = norm_phone(phone)

    user = find_user(email, phone)
    if not user:
        return False, "Utilisateur non enregistré.", None

    status = (user.get("fields", {}).get("Status") or "").lower()
    if status != "approved":
        return False, f"Utilisateur non approuvé (status={status}).", user

    conds = [f"{{QRID}}='{qrid}'", "{Active}=1"]
    idconds = []
    if email:
        idconds.append(f"{{Email}}='{email}'")
    if phone:
        idconds.append(f"{{Phone}}='{phone}'")
    if not idconds:
        return False, "Aucun email/téléphone fourni.", user
    conds.append("OR(" + ",".join(idconds) + ")" if len(idconds) > 1 else idconds[0])

    formula = "AND(" + ",".join(conds) + ")"
    perms = at_get(T_PERMS, formula=formula, max_records=5)
    if not perms:
        return False, "Aucune permission active pour cette boîte.", user

    return True, None, user

def log_access(qrid: str, first: str, last: str, company: str, channel: str,
               pin_id: str = "", start: str = "", end: str = "", error: str = ""):
    try:
        at_create(T_LOG, {
            "Timestamp": iso(now_lu()),
            "QRID": qrid,
            "FirstName": first,
            "LastName": last,
            "Company": company,
            "Channel": channel,
            "PinId": pin_id or "",
            "Start": start or "",
            "End": end or "",
            "Error": error or ""
        })
    except Exception as e:
        print("LOG_ACCESS FAILED:", str(e))
def csrf_get_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = token_urlsafe(32)
        session["_csrf"] = tok
    return tok

def csrf_input() -> str:
    return f'<input type="hidden" name="csrf" value="{csrf_get_token()}">'

def csrf_check():
    sent = request.form.get("csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not sent or sent != expected:
        return False
    return True

def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            if not csrf_check():
                return "CSRF invalid", 403
        return fn(*args, **kwargs)
    return wrapper
 from secrets import token_urlsafe
from functools import wraps

def csrf_get_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = token_urlsafe(32)
        session["_csrf"] = tok
    return tok

def csrf_input() -> str:
    return f'<input type="hidden" name="csrf" value="{csrf_get_token()}">'

def csrf_check() -> bool:
    sent = (request.form.get("csrf") or "").strip()
    expected = (session.get("_csrf") or "").strip()
    return bool(sent) and bool(expected) and sent == expected

def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "POST" and not csrf_check():
            return "CSRF invalid", 403
        return fn(*args, **kwargs)
    return wrapper
  

# ------------------ Keyboxes ------------------
def get_keybox_by_qr(qrid: str):
    recs = at_get(T_KEYBOXES, formula=f"{{QRID}}='{qrid}'", max_records=5)
    return recs[0] if recs else None

def get_keyboxes_for_client(client: str):
    return at_get(T_KEYBOXES, formula=f"{{Client}}='{client}'", max_records=200)

def gerance_can_access_qr(qrid: str) -> bool:
    if session.get("role") not in ("gerance", "admin"):
        return False
    if session.get("role") == "admin":
        return True
    kb = get_keybox_by_qr(qrid)
    if not kb:
        return False
    return (kb.get("fields", {}).get("Client") == session.get("client"))

TZ = ZoneInfo("Europe/Luxembourg")

def ensure_active_or_next_pin(kb):
    """
    Garantit:
    - ActivePin = heure courante (Luxembourg)
    - NextPin = heure suivante
    Retourne: (active_pin, active_pin_id, active_start_iso, active_end_iso, err)
    """
    try:
        f = kb.get("fields", {})

        now = now_lu()  # doit être aware en Europe/Luxembourg
        cur_start = round_down_hour(now)
        cur_end = cur_start + timedelta(hours=1)

        cur_start_iso = iso(cur_start)
        cur_end_iso = iso(cur_end)

        # 0) Si Next correspond à l'heure courante => on "promote" Next -> Active
        if (
            f.get("NextPin")
            and f.get("NextStart") == cur_start_iso
            and f.get("NextEnd") == cur_end_iso
        ):
            at_update(T_KEYBOXES, kb["id"], {
                "ActivePin": f.get("NextPin"),
                "ActivePinId": f.get("NextPinId"),
                "ActiveStart": f.get("NextStart"),
                "ActiveEnd": f.get("NextEnd"),
            })
            # on met à jour localement aussi
            f["ActivePin"] = f.get("NextPin")
            f["ActivePinId"] = f.get("NextPinId")
            f["ActiveStart"] = f.get("NextStart")
            f["ActiveEnd"] = f.get("NextEnd")

        # 1) ActivePin OK seulement s'il couvre MAINTENANT ET correspond à la fenêtre courante
        active_ok = (
            f.get("ActivePin")
            and f.get("ActiveStart") == cur_start_iso
            and f.get("ActiveEnd") == cur_end_iso
            and is_active_window(f["ActiveStart"], f["ActiveEnd"])
        )

        if not active_ok:
            pin, pin_id, err = igloo_create_hourly_pin(kb, cur_start, cur_end)
            if err:
                # IMPORTANT: ne jamais retourner NextPin en fallback
                return None, None, None, None, err

            at_update(T_KEYBOXES, kb["id"], {
                "ActivePin": pin,
                "ActivePinId": pin_id,
                "ActiveStart": cur_start_iso,
                "ActiveEnd": cur_end_iso,
            })

            f["ActivePin"] = pin
            f["ActivePinId"] = pin_id
            f["ActiveStart"] = cur_start_iso
            f["ActiveEnd"] = cur_end_iso

        # 2) Préparer NextPin (heure suivante)
        next_start = cur_end
        next_end = next_start + timedelta(hours=1)
        next_start_iso = iso(next_start)
        next_end_iso = iso(next_end)

        next_ok = (
            f.get("NextPin")
            and f.get("NextStart") == next_start_iso
            and f.get("NextEnd") == next_end_iso
        )

        if not next_ok:
            pin2, pin2_id, err2 = igloo_create_hourly_pin(kb, next_start, next_end)
            if not err2:
                at_update(T_KEYBOXES, kb["id"], {
                    "NextPin": pin2,
                    "NextPinId": pin2_id,
                    "NextStart": next_start_iso,
                    "NextEnd": next_end_iso,
                })

        # ✅ reste dans le try
        print(
            "PIN_DEBUG now=", now.isoformat(), "cur=", cur_start_iso, cur_end_iso,
            "Active=", f.get("ActiveStart"), f.get("ActiveEnd"),
            "Next=", f.get("NextStart"), f.get("NextEnd")
        )

        return f["ActivePin"], f.get("ActivePinId"), f.get("ActiveStart"), f.get("ActiveEnd"), None

    except Exception as e:
        return None, None, None, None, str(e)


# =========================================================
# Routes
# =========================================================
def find_pending_request(qrid: str, email: str, phone: str):
    email = norm_email(email or "")
    phone = norm_phone(phone or "")

    conds = [f"{{QRID}}='{qrid}'", "{Status}='pending'"]

    idconds = []
    if email:
        idconds.append(f"{{Email}}='{email}'")
    if phone:
        idconds.append(f"{{Phone}}='{phone}'")

    if idconds:
        if len(idconds) == 1:
            conds.append(idconds[0])
        else:
            conds.append("OR(" + ",".join(idconds) + ")")

    formula = "AND(" + ",".join(conds) + ")"
    recs = at_get(T_REQUESTS, formula=formula, max_records=1)
    return recs[0] if recs else None

@app.route("/")
def home():
    return "OK"

# --- TECH QR ---
@app.route("/access/<qr_id>", methods=["GET", "POST"])
@require_csrf
def tech_access(qr_id):
    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return "QR Code inconnu", 404

    f = kb.get("fields", {})
    bat = f.get("Batiment", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if request.method == "GET":
        return render_template_string(HTML_TECH_FORM, batiment=bat)

    # ⚠️ IMPORTANT: pas de "@app.route" dans les arguments, juste window_sec
    if not rate_limit(f"{qr_id}:{ip}", max_req=5, window_sec=600):
        return render_template_string(
            HTML_TECH_RESULT,
            ok=False,
            msg="Trop de demandes",
            detail="Réessayez dans quelques minutes."
        )

    first = (request.form.get("first") or "").strip()
    last = (request.form.get("last") or "").strip()
    company = (request.form.get("company") or "").strip()
    email = norm_email(request.form.get("email") or "")
    phone = norm_phone(request.form.get("phone") or "")

    allowed, reason, _user = is_user_allowed(qr_id, email=email, phone=phone)

    # --- NON AUTORISÉ => créer demande gérance + refuser ---
    if not allowed:
        detail = reason

        if (reason == "Utilisateur non enregistré."
            or reason == "Aucune permission active pour cette boîte."
            or "status=pending" in reason):

            try:
                client = f.get("Client", "")

                # si inconnu -> user pending
                if reason == "Utilisateur non enregistré.":
                    upsert_user(first, last, company, email, phone, status="pending")

                existing = find_pending_request(qr_id, email, phone)
                if existing:
                    detail = f"Demande déjà en attente de validation. (ID={existing.get('id')})"
                else:
                    req = create_request(client, qr_id, first, last, company, email, phone)
                    detail = f"Demande envoyée à la gérance. (ID={req.get('id')})"

            except Exception as e:
                detail = f"Impossible de créer la demande: {e}"

        log_access(qr_id, first, last, company, channel="none", error=reason)
        return render_template_string(
            HTML_TECH_RESULT,
            ok=False,
            msg="Accès refusé",
            detail=detail
        )

    # --- AUTORISÉ => retourner PIN ---
    with _get_lock(qr_id):   # ou qr_id / qr_id variable de ta route
    pin, pin_id, s, e, err = ensure_active_or_next_pin(kb)
    if err:
        log_access(qr_id, first, last, company, channel="none", error=err)
        return render_template_string(
            HTML_TECH_RESULT,
            ok=False,
            msg="Service indisponible",
            detail=err
        )

    detail = f"Valide: {s} → {e}"
    log_access(qr_id, first, last, company, channel="screen", pin_id=pin_id, start=s, end=e, error="")
    return render_template_string(
        HTML_TECH_RESULT,
        ok=True,
        msg="Code prêt",
        detail=detail,
        pin=pin
    )

# --- GERANCE LOGIN ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client = request.form.get("client", "")
        pwd = request.form.get("pwd", "")
        recs = at_get(T_KEYBOXES, formula=f"AND({{Client}}='{client}', {{Password}}='{pwd}')", max_records=1)
        if recs:
            session["role"] = "gerance"
            session["client"] = client
            return redirect(url_for("gerance_portal"))
        return render_template_string(HTML_LOGIN, error="Identifiants incorrects")
    return render_template_string(HTML_LOGIN)

@app.route("/gerance")
def gerance_portal():
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    recs = get_keyboxes_for_client(client)

    rows = []
    for r in recs:
        f = r.get("fields", {})
        qr = f.get("QRID")
        bat = f.get("Batiment")
        emergency_set = bool(f.get("EmergencyCode"))

        # on prépare le prochain pin (pour fluidifier)
        _pin, _pid, s, e, err = ensure_active_or_next_pin(r)

        rows.append({
            "QRID": qr,
            "Batiment": bat,
            "EmergencySet": emergency_set,
            "NextStart": s,
            "NextEnd": e,
            "Err": err
        })

    return render_template_string(HTML_GERANCE, rows=rows, csrf=csrf_input())

# API: afficher code d'urgence (session gérance)
@app.route("/api/emergency/<qr_id>")
@require_csrf
def api_emergency(qr_id):
    if not gerance_can_access_qr(qr_id):
        return jsonify({"error": "unauthorized"}), 401
    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return jsonify({"error": "qr_unknown"}), 404
    code = kb.get("fields", {}).get("EmergencyCode")
    if not code:
        return jsonify({"error": "not_set"}), 404
    return jsonify({"emergencyCode": code})

# Gerance: set emergency code
@app.route("/gerance/keybox/<qr_id>/set_emergency", methods=["POST"])
@require_csrf
def set_emergency(qr_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    if not gerance_can_access_qr(qr_id):
        return "Unauthorized", 401
    kb = get_keybox_by_qr(qr_id)
    code = (request.form.get("code") or "").strip()
    if not code:
        return "Code vide", 400
    at_update(T_KEYBOXES, kb["id"], {"EmergencyCode": code})
    return redirect(url_for("gerance_keybox", qr_id=qr_id))

# Gerance: manage users for a keybox
@app.route("/gerance/keybox/<qr_id>")
def gerance_keybox(qr_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    if not gerance_can_access_qr(qr_id):
        return "Unauthorized", 401

    kb = get_keybox_by_qr(qr_id)
    kf = kb.get("fields", {})
    bat = kf.get("Batiment", "")

    # permissions for this QRID
    perms = at_get(T_PERMS, formula=f"{{QRID}}='{qr_id}'", max_records=200)

    # enrich with user status if possible
    perm_rows = []
    for p in perms:
        pf = p.get("fields", {})
        email = norm_email(pf.get("Email") or "")
        phone = norm_phone(pf.get("Phone") or "")
        active = bool(pf.get("Active"))

        user = find_user(email, phone)
        uf = user.get("fields", {}) if user else {}

        perm_rows.append({
            "perm_id": p["id"],
            "email": email,
            "phone": phone,
            "active": active,
            "name": (uf.get("FirstName","") + " " + uf.get("LastName","")).strip(),
            "company": uf.get("Company",""),
            "status": uf.get("Status","") if user else "unknown"
        })

    return render_template_string(
    HTML_KEYBOX,
    qr_id=qr_id, batiment=batiment,
    emergency=(kf.get("EmergencyCode") or ""),
    perms=perm_rows,
    csrf=csrf_input()
)

@app.route("/gerance/keybox/<qr_id>/add_user", methods=["POST"])
@require_csrf
def gerance_add_user(qr_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    if not gerance_can_access_qr(qr_id):
        return "Unauthorized", 401

    first = (request.form.get("first") or "").strip()
    last = (request.form.get("last") or "").strip()
    company = (request.form.get("company") or "").strip()
    email = norm_email(request.form.get("email") or "")
    phone = norm_phone(request.form.get("phone") or "")

    if not email and not phone:
        return "Email ou téléphone requis", 400

    try:
        upsert_user(first, last, company, email, phone, status="approved")
        create_permission(qr_id, email, phone, active=True)
        return redirect(url_for("gerance_keybox", qr_id=qr_id))
    except Exception as e:
        # Visible dans Render logs + dans la page
        print("ERROR add_user:", str(e))
        return f"Erreur création utilisateur: {e}", 500

@app.route("/gerance/perm/<perm_id>/toggle", methods=["POST"])
@require_csrf
def gerance_toggle_perm(perm_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    active = (request.form.get("active") == "1")
    set_permission_active(perm_id, active)
    back = request.form.get("back") or "/gerance"
    return redirect(back)

# Admin
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if request.form.get("pwd") == ADMIN_PASSWORD:
            session["role"] = "admin"
        else:
            return "Accès refusé", 403
    if session.get("role") != "admin":
        return '<form method="post">Pass Admin: <input type="password" name="pwd"><button>OK</button></form>'

    recs = at_get(T_KEYBOXES, max_records=200)
    return render_template_string(HTML_ADMIN, records=recs)
    
@app.route("/gerance/requests")
def gerance_requests():
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client") or ""

    # 1) Récupère les keyboxes de ce client (donc les QRID autorisés)
    keyboxes = get_keyboxes_for_client(client)
    qrids = { (kb.get("fields", {}) or {}).get("QRID") for kb in keyboxes }
    qrids.discard(None)
    qrids.discard("")

    # 2) Récupère toutes les demandes pending
    reqs = at_get(T_REQUESTS, formula="{Status}='pending'", max_records=200) or []

    # 3) Filtre côté serveur pour ne garder que les QRID de ce client
    reqs = [r for r in reqs if (r.get("fields", {}) or {}).get("QRID") in qrids]

    return render_template_string(HTML_REQUESTS, reqs=reqs, client=client, csrf=csrf_input())

    
@app.route("/gerance/requests/<req_id>/approve", methods=["POST"])
@require_csrf
def gerance_approve_request(req_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    req = at_read(T_REQUESTS, req_id)
    f = req.get("fields", {})

    if f.get("Client") != client:
        return "Unauthorized", 401

    qrid = f.get("QRID")
    email = f.get("Email","")
    phone = f.get("Phone","")

    # Approuver user + créer permission active
    upsert_user(f.get("FirstName",""), f.get("LastName",""), f.get("Company",""), email, phone, status="approved")
    create_permission(qrid, email, phone, active=True)

    at_update(T_REQUESTS, req_id, {"Status": "approved"})
    return redirect(url_for("gerance_requests"))
    
@app.route("/gerance/requests/<req_id>/deny", methods=["POST"])
@require_csrf
def gerance_deny_request(req_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    req = at_read(T_REQUESTS, req_id)
    f = req.get("fields", {})
    if f.get("Client") != client:
        return "Unauthorized", 401

    at_update(T_REQUESTS, req_id, {"Status": "denied"})
    return redirect(url_for("gerance_requests"))

@app.route("/prefill", strict_slashes=False)
def prefill():
    secret = request.args.get("secret", "")
    if secret != os.getenv("PREFILL_SECRET"):
        return "unauthorized", 401

    keyboxes = at_get(T_KEYBOXES, formula="{Enabled}=1", max_records=200)
    out = {"ok": 0, "err": 0, "results": []}

    for kb in keyboxes:
        qr = kb.get("fields", {}).get("QRID", "")
        try:
            with _get_lock(qr_id):
            pin, pin_id, s, e, err = ensure_active_or_next_pin(kb)
            out["results"].append({"qrid": qr, "start": s, "end": e, "error": err})
            if err:
                out["err"] += 1
            else:
                out["ok"] += 1
        except Exception as ex:
            out["results"].append({"qrid": qr, "error": str(ex)})
            out["err"] += 1

    return jsonify(out)
    
@app.route("/gerance/logs")
def gerance_logs():
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client") or ""

    # QRID autorisés
    keyboxes = get_keyboxes_for_client(client)
    qrids = { (kb.get("fields", {}) or {}).get("QRID") for kb in keyboxes }
    qrids.discard(None)
    qrids.discard("")

    # On récupère large puis on filtre "succès" (code délivré)
    logs = at_get_sorted(T_LOG, max_records=300, sort_field="Timestamp", direction="desc") or []

    def is_success(rec):
        f = (rec.get("fields", {}) or {})
        if f.get("QRID") not in qrids:
            return False
        if (f.get("Channel") or "") != "screen":
            return False
        return (f.get("Error") or "").strip() == ""

    logs = [r for r in logs if is_success(r)]
    logs = logs[:200]

    return render_template_string(HTML_LOGS, logs=logs, client=client)
    
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    return resp
    
# ------------------ HTML ------------------
HTML_LOGIN = """
<body style="font-family:sans-serif; background:#f4f7f9; display:flex; justify-content:center; padding-top:100px;">
  <div style="background:white; padding:40px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.1); width:350px; text-align:center;">
    <h2 style="color:#2563eb;">Connexion Gérance</h2>
    <form method="post">
      <input type="text" name="client" placeholder="Nom Gérance" style="width:100%; padding:12px; margin:10px 0; border:1px solid #ddd; border-radius:8px;">
      <input type="password" name="pwd" placeholder="Mot de passe" style="width:100%; padding:12px; margin:10px 0; border:1px solid #ddd; border-radius:8px;">
      <button style="width:100%; padding:12px; background:#2563eb; color:white; border:none; border-radius:8px; font-weight:bold; cursor:pointer;">Entrer</button>
    </form>
    {% if error %}<p style="color:red;">{{error}}</p>{% endif %}
  </div>
</body>
"""

HTML_GERANCE = """
<body style="font-family:sans-serif;background:#f4f7f9;padding:20px;">
  <div style="max-width:900px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <h2 style="color:#2563eb;margin-top:0;">Espace Gérance</h2>
    <p style="opacity:.75;margin-top:6px;">
      Code d’urgence = <b>EmergencyCode</b> (immédiat).<br>
      Sans bridge, les codes temporaires (AlgoPIN) démarrent à l’heure pile : on prépare automatiquement la prochaine fenêtre.
    </p>

    <table style="width:100%;border-collapse:collapse;margin-top:10px;">
      <tr style="text-align:left;border-bottom:1px solid #eee;">
        <th style="padding:10px;">Bâtiment</th>
        <th style="padding:10px;">QRID</th>
        <th style="padding:10px;">Urgence</th>
        <th style="padding:10px;">Prochaine fenêtre</th>
        <th style="padding:10px;">Actions</th>
      </tr>
      {% for r in rows %}
      <tr style="border-bottom:1px solid #f1f5f9;">
        <td style="padding:10px;">{{r.Batiment}}</td>
        <td style="padding:10px;">{{r.QRID}}</td>
        <td style="padding:10px;">
          {% if r.EmergencySet %}
            <button onclick="showEmergency('{{r.QRID}}')" style="padding:8px 10px;border:0;border-radius:10px;background:#0ea5e9;color:white;font-weight:700;cursor:pointer;">
              Afficher
            </button>
            <span id="em_{{r.QRID}}" style="margin-left:10px;font-weight:800;"></span>
          {% else %}
            <span style="color:#ef4444;">Non défini</span>
          {% endif %}
        </td>
        <td style="padding:10px;font-size:12px;opacity:.85;">
          {{r.NextStart}} → {{r.NextEnd}}
          {% if r.Err %}<div style="color:#ef4444;">{{r.Err}}</div>{% endif %}
        </td>
        <td style="padding:10px;">
          <a href="/gerance/keybox/{{r.QRID}}" style="text-decoration:none;">
            <button style="padding:8px 10px;border:0;border-radius:10px;background:#2563eb;color:white;font-weight:700;cursor:pointer;">
              Gérer utilisateurs
            </button>
          </a>
          <a href="/gerance/requests" style="text-decoration:none;">
  <button style="padding:10px 12px;border:0;border-radius:10px;background:#111827;color:white;font-weight:800;cursor:pointer;">
    Demandes en attente
  </button>
</a>
        <a href="/gerance/logs" style="text-decoration:none;">
  <button style="padding:10px 12px;border:0;border-radius:10px;background:#334155;color:white;font-weight:800;cursor:pointer;">
    Logs d'accès
  </button>
</a>

        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <script>
    function showEmergency(qrid){
      const el = document.getElementById('em_'+qrid);
      el.innerText = "...";
      fetch('/api/emergency/' + qrid)
        .then(r => r.json())
        .then(d => {
          if(d.emergencyCode){ el.innerText = d.emergencyCode; }
          else { el.innerText = (d.error || 'Erreur'); }
        });
    }
  </script>
</body>
"""

HTML_KEYBOX = """
<body style="font-family:sans-serif;background:#f4f7f9;padding:20px;">
  <div style="max-width:900px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <a href="/gerance" style="text-decoration:none;color:#2563eb;">← Retour</a>
    <h2 style="color:#2563eb;margin-top:10px;">{{batiment}} — Gestion</h2>

    <h3>Code d’urgence</h3>
    <form method="post" action="/gerance/keybox/{{qr_id}}/set_emergency" style="display:flex;gap:10px;align-items:center;">
       {{csrf|safe}} 
      <input name="code" value="{{emergency}}" placeholder="EmergencyCode" style="flex:1;padding:10px;border-radius:10px;border:1px solid #ddd;">
      <button style="padding:10px 14px;border:0;border-radius:10px;background:#0ea5e9;color:white;font-weight:700;cursor:pointer;">Enregistrer</button>
    </form>
    <p style="opacity:.7;font-size:12px;">Conseil: code unique par boîte, à garder strictement “secours”.</p>

    <h3>Ajouter un utilisateur autorisé</h3>
    <form method="post" action="/gerance/keybox/{{qr_id}}/add_user" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
        {{csrf|safe}}
      <input name="first" placeholder="Prénom" required style="padding:10px;border-radius:10px;border:1px solid #ddd;">
      <input name="last" placeholder="Nom" required style="padding:10px;border-radius:10px;border:1px solid #ddd;">
      <input name="company" placeholder="Entreprise" required style="padding:10px;border-radius:10px;border:1px solid #ddd;">
      <input name="email" placeholder="Email" style="padding:10px;border-radius:10px;border:1px solid #ddd;">
      <input name="phone" placeholder="Téléphone" style="grid-column:1/-1;padding:10px;border-radius:10px;border:1px solid #ddd;">
      <button style="grid-column:1/-1;padding:12px;border:0;border-radius:10px;background:#2563eb;color:white;font-weight:800;cursor:pointer;">
        Ajouter + Autoriser
      </button>
    </form>

    <h3 style="margin-top:20px;">Utilisateurs (Permissions)</h3>
    <table style="width:100%;border-collapse:collapse;margin-top:8px;">
      <tr style="text-align:left;border-bottom:1px solid #eee;">
        <th style="padding:10px;">Nom</th>
        <th style="padding:10px;">Entreprise</th>
        <th style="padding:10px;">Email</th>
        <th style="padding:10px;">Téléphone</th>
        <th style="padding:10px;">Status</th>
        <th style="padding:10px;">Actif</th>
      </tr>
      {% for p in perms %}
      <tr style="border-bottom:1px solid #f1f5f9;">
        <td style="padding:10px;">{{p.name}}</td>
        <td style="padding:10px;">{{p.company}}</td>
        <td style="padding:10px;">{{p.email}}</td>
        <td style="padding:10px;">{{p.phone}}</td>
        <td style="padding:10px;">{{p.status}}</td>
        <td style="padding:10px;">
          <form method="post" action="/gerance/perm/{{p.perm_id}}/toggle">
            {{csrf|safe}}
            <input type="hidden" name="back" value="/gerance/keybox/{{qr_id}}">
            <select name="active" onchange="this.form.submit()" style="padding:6px;border-radius:8px;">
              <option value="1" {% if p.active %}selected{% endif %}>ON</option>
              <option value="0" {% if not p.active %}selected{% endif %}>OFF</option>
            </select>
          </form>
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
"""

HTML_TECH_FORM = """
<body style="font-family:sans-serif;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
  <div style="width:420px;background:#111827;padding:24px;border-radius:16px;">
    <h2 style="margin:0 0 8px;color:#60a5fa;">Accès technique</h2>
    <p style="margin:0 0 16px;opacity:.85;">{{batiment}}</p>
    <form method="post">
      <input name="first" placeholder="Prénom" required style="width:100%;padding:12px;margin:6px 0;border-radius:10px;border:0;">
      <input name="last" placeholder="Nom" required style="width:100%;padding:12px;margin:6px 0;border-radius:10px;border:0;">
      <input name="company" placeholder="Entreprise" required style="width:100%;padding:12px;margin:6px 0;border-radius:10px;border:0;">
      <input name="phone" placeholder="Téléphone (SMS)" style="width:100%;padding:12px;margin:6px 0;border-radius:10px;border:0;">
      <input name="email" placeholder="Email" style="width:100%;padding:12px;margin:6px 0;border-radius:10px;border:0;">
      <button style="width:100%;padding:12px;margin-top:10px;border:0;border-radius:10px;background:#2563eb;color:white;font-weight:700;">
        Obtenir le code
      </button>
      <p style="font-size:12px;opacity:.7;margin-top:10px;">Si vous n’êtes pas approuvé ou pas autorisé sur cette boîte, accès refusé.</p>
    </form>
  </div>
</body>
"""

HTML_TECH_RESULT = """
<body style="font-family:sans-serif;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
  <div style="width:520px;background:#111827;padding:24px;border-radius:16px;text-align:center;">
    {% if ok %}
      <h2 style="color:#34d399;margin:0 0 8px;">{{msg}}</h2>
      <div style="font-size:64px;font-weight:800;background:white;color:#0f172a;padding:16px;border-radius:14px;letter-spacing:4px;margin:16px 0;">
        {{pin}}
      </div>
      <p style="opacity:.85;margin:0;">{{detail}}</p>
    {% else %}
      <h2 style="color:#fb7185;margin:0 0 8px;">{{msg}}</h2>
      <p style="opacity:.85;margin:0;">{{detail}}</p>
    {% endif %}
  </div>
</body>
"""

HTML_REQUESTS = """
<body style="font-family:sans-serif;background:#f4f7f9;padding:20px;">
  <div style="max-width:900px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <a href="/gerance" style="text-decoration:none;color:#2563eb;">← Retour</a>
    <h2 style="color:#2563eb;margin-top:10px;">Demandes en attente</h2>

    {% if not reqs %}
      <p>Aucune demande en attente ✅</p>
    {% else %}
      <table style="width:100%;border-collapse:collapse;margin-top:10px;">
        <tr style="text-align:left;border-bottom:1px solid #eee;">
          <th style="padding:10px;">QRID</th>
          <th style="padding:10px;">Nom</th>
          <th style="padding:10px;">Entreprise</th>
          <th style="padding:10px;">Email</th>
          <th style="padding:10px;">Téléphone</th>
          <th style="padding:10px;">Actions</th>
        </tr>
        {% for r in reqs %}
          {% set f = r['fields'] %}
          <tr style="border-bottom:1px solid #f1f5f9;">
            <td style="padding:10px;">{{f.get('QRID','')}}</td>
            <td style="padding:10px;">{{f.get('FirstName','')}} {{f.get('LastName','')}}</td>
            <td style="padding:10px;">{{f.get('Company','')}}</td>
            <td style="padding:10px;">{{f.get('Email','')}}</td>
            <td style="padding:10px;">{{f.get('Phone','')}}</td>
            <td style="padding:10px;display:flex;gap:8px;">
              <form method="post" action="/gerance/requests/{{r['id']}}/approve">
              {{csrf|safe}}
                <button style="padding:8px 10px;border:0;border-radius:10px;background:#22c55e;color:white;font-weight:700;cursor:pointer;">Valider</button>
              </form>
              <form method="post" action="/gerance/requests/{{r['id']}}/deny">
              {{csrf|safe}}
                <button style="padding:8px 10px;border:0;border-radius:10px;background:#ef4444;color:white;font-weight:700;cursor:pointer;">Refuser</button>
              </form>
            </td>
          </tr>
        {% endfor %}
      </table>
    {% endif %}
  </div>
</body>
"""

HTML_ADMIN = """
<body style="font-family:sans-serif;background:#f4f7f9;padding:20px;">
  <div style="max-width:900px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <h2 style="color:#2563eb;margin-top:0;">Admin — Keyboxes</h2>
    <table style="width:100%;border-collapse:collapse;">
      <tr style="text-align:left;border-bottom:1px solid #eee;">
        <th style="padding:10px;">Client</th>
        <th style="padding:10px;">Batiment</th>
        <th style="padding:10px;">QRID</th>
        <th style="padding:10px;">DeviceId</th>
        <th style="padding:10px;">EmergencyCode</th>
      </tr>
      {% for r in records %}
      <tr style="border-bottom:1px solid #f1f5f9;">
        <td style="padding:10px;">{{r.fields.get('Client','')}}</td>
        <td style="padding:10px;">{{r.fields.get('Batiment','')}}</td>
        <td style="padding:10px;">{{r.fields.get('QRID','')}}</td>
        <td style="padding:10px;">{{r.fields.get('DeviceId','')}}</td>
        <td style="padding:10px;">{{r.fields.get('EmergencyCode','')}}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
"""

HTML_LOGS = """
<body style="font-family:sans-serif;background:#f4f7f9;padding:20px;">
  <div style="max-width:1200px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <a href="/gerance" style="text-decoration:none;color:#2563eb;">← Retour</a>
    <h2 style="color:#2563eb;margin-top:10px;">Codes délivrés — {{client}}</h2>
    <p style="opacity:.7;margin:6px 0 14px;font-size:12px;">Uniquement les accès réussis (code affiché).</p>

    <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:13px;">
      <tr style="text-align:left;border-bottom:1px solid #eee;background:#f8fafc;">
        <th style="padding:10px;">Quand</th>
        <th style="padding:10px;">QRID</th>
        <th style="padding:10px;">Nom</th>
        <th style="padding:10px;">Entreprise</th>
        <th style="padding:10px;">Fenêtre</th>
        <th style="padding:10px;">PinId</th>
      </tr>

      {% for r in logs %}
        {% set f = r.get('fields', {}) %}
        <tr style="border-bottom:1px solid #f1f5f9;">
          <td style="padding:10px;">{{f.get('Timestamp','')}}</td>
          <td style="padding:10px;">{{f.get('QRID','')}}</td>
          <td style="padding:10px;">{{f.get('FirstName','')}} {{f.get('LastName','')}}</td>
          <td style="padding:10px;">{{f.get('Company','')}}</td>
          <td style="padding:10px;">{{f.get('Start','')}} → {{f.get('End','')}}</td>
          <td style="padding:10px;">{{f.get('PinId','')}}</td>
        </tr>
      {% endfor %}
    </table>
  </div>
</body>
"""


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))































