import os
import time
import requests
import logging
from threading import Lock
from functools import wraps
from secrets import token_urlsafe
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from db import q, q1, exec_sql
from flask import g


# =========================================================
# App + config
# =========================================================
app = Flask(__name__)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("keybox")

app.config.update(
    SESSION_COOKIE_SECURE=True,      # OK sur Render (https)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_only_change_me")

TZ = ZoneInfo(os.getenv("APP_TZ", "Europe/Luxembourg"))
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

# Igloo
IGLOO_CLIENT_ID = os.getenv("IGLOO_CLIENT_ID")
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")
AUTH_URL = "https://auth.igloohome.co/oauth2/token"
API_BASE = "https://api.igloodeveloper.co/igloohome"

# Admin
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change_me")

# in-memory caches
_token_cache = {"token": None, "exp": 0}
_rl = {}
_qr_locks = {}

def _get_lock(qrid: str) -> Lock:
    if qrid not in _qr_locks:
        _qr_locks[qrid] = Lock()
    return _qr_locks[qrid]
def tenant_from_host():
    host = (request.headers.get("X-Forwarded-Host") or request.host).split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3 and parts[0] not in ("www", "app"):
        return parts[0].lower()
    return (request.args.get("tenant") or "").lower()


def tenant_from_request():
    # 1) param ?tenant=demo (prioritaire pour debug)
    t = (request.args.get("tenant") or "").strip().lower()
    if t:
        return t

    # 2) sous-domaine demo.domaine.tld
    host = (request.headers.get("X-Forwarded-Host") or request.host or "").split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3:
        sub = parts[0].lower()
        if sub not in ("www", "app"):
            return sub

    return ""

@app.before_request
def load_tenant():
    slug = tenant_from_request()
    g.tenant_slug = slug
    g.tenant_id = None

    if not slug:
        return

    row = q1(
        "select id from tenants where slug=%s and status='active'",
        (slug,)
    )
    if row:
        g.tenant_id = row["id"]

# =========================================================
# Time helpers
# =========================================================
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
            dt = dt.replace(tzinfo=TZ)
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

# =========================================================
# CSRF (single implementation)
# =========================================================
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

# =========================================================
# Airtable client
# =========================================================
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
        "sort[0][direction]": direction,
    }
    if formula:
        params["filterByFormula"] = formula
    r = requests.get(at_url(table), headers=at_headers(), params=params, timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json().get("records", [])

def at_read(table: str, record_id: str):
    r = requests.get(f"{at_url(table)}/{record_id}", headers=at_headers(), timeout=20, verify=VERIFY_SSL)
    if r.status_code != 200:
        raise RuntimeError(f"Airtable read failed {r.status_code}: {r.text}")
    return r.json()

def at_create(table: str, fields: dict):
    r = requests.post(at_url(table), headers=at_headers(json=True), json={"fields": fields}, timeout=20, verify=VERIFY_SSL)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Airtable create failed {r.status_code}: {r.text}")
    return r.json()

def at_update(table: str, record_id: str, fields: dict):
    r = requests.patch(f"{at_url(table)}/{record_id}", headers=at_headers(json=True), json={"fields": fields}, timeout=20, verify=VERIFY_SSL)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Airtable update failed {r.status_code}: {r.text}")
    return r.json()

# =========================================================
# Igloo OAuth + AlgoPIN
# =========================================================
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

def igloo_create_hourly_pin(kb, start_dt: datetime, end_dt: datetime):
    try:
        # ✅ support Airtable record (kb["fields"]) ET Postgres dict (kb directement)
        f = (kb.get("fields") or kb or {})

        device_id = (
            f.get("device_id")      # Postgres
            or f.get("DeviceId")    # Airtable ancien champ
            or f.get("deviceId")
            or f.get("LockID")
        )
        if not device_id:
            return None, None, "DeviceId manquant"

        token = get_oauth_token()
        url = f"{API_BASE}/devices/{device_id}/algopin/hourly"

        start_dt = start_dt.astimezone(TZ).replace(minute=0, second=0, microsecond=0)
        end_dt = end_dt.astimezone(TZ).replace(minute=0, second=0, microsecond=0)

        payload = {
            "variance": int(f.get("variance_hourly") or f.get("VarianceHourly") or 1),
            "startDate": start_dt.isoformat(timespec="seconds"),
            "endDate": end_dt.isoformat(timespec="seconds"),
            "accessName": "PREFILL",
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

# =========================================================
# Rate limit
# =========================================================
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

# =========================================================
# Business: users / permissions / requests / logs
# =========================================================
def norm_phone(p: str) -> str:
    return (p or "").strip().replace(" ", "")

def norm_email(e: str) -> str:
    return (e or "").strip().lower()

def find_user(email: str, phone: str):
    email = at_escape(norm_email(email))
    phone = at_escape(norm_phone(phone))
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
        "Status": status,
    }
    if existing:
        return at_update(T_USERS, existing["id"], fields)
    return at_create(T_USERS, fields)

def create_permission(qrid: str, email: str, phone: str, active=True):
    fields = {"QRID": qrid, "Email": norm_email(email), "Phone": norm_phone(phone), "Active": bool(active)}
    return at_create(T_PERMS, fields)

def set_permission_active(perm_record_id: str, active: bool):
    return at_update(T_PERMS, perm_record_id, {"Active": bool(active)})

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

def is_user_allowed(qrid: str, email: str, phone: str):
    email = at_escape(norm_email(email))
    phone = at_escape(norm_phone(phone))
    qrid = at_escape(qrid)

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
# =========================================================
# Postgres auth (TEMP pour remplacer Airtable)
# =========================================================

def pg_find_user(email: str, phone: str):
    email = norm_email(email)
    phone = norm_phone(phone)

    if not g.get("tenant_id"):
        return None

    if email and phone:
        return q1(
            "select * from users where tenant_id=%s and (email=%s or phone=%s) limit 1",
            (g.tenant_id, email, phone),
        )
    if email:
        return q1(
            "select * from users where tenant_id=%s and email=%s limit 1",
            (g.tenant_id, email),
        )
    if phone:
        return q1(
            "select * from users where tenant_id=%s and phone=%s limit 1",
            (g.tenant_id, phone),
        )
    return None


def pg_is_user_allowed(qrid: str, email: str, phone: str):
    if not g.get("tenant_id"):
        return False, "Tenant manquant.", None

    email = norm_email(email)
    phone = norm_phone(phone)

    user = pg_find_user(email, phone)
    if not user:
        return False, "Utilisateur non enregistré.", None

    if (user.get("status") or "").lower() != "approved":
        return False, "Utilisateur non approuvé.", user

    kb = q1(
        "select id from keyboxes where tenant_id=%s and qrid=%s and enabled=true",
        (g.tenant_id, qrid),
    )
    if not kb:
        return False, "QR Code inconnu.", user

    perm = q1(
        """
        select id
        from permissions
        where tenant_id=%s
          and keybox_id=%s
          and user_id=%s
          and active=true
        """,
        (g.tenant_id, kb["id"], user["id"]),
    )
    if not perm:
        return False, "Aucune permission active.", user

    return True, None, user


def at_escape(s: str) -> str:
    # Airtable formule: string entre quotes simples
    # On échappe les backslashes + quotes simples
    return (s or "").replace("\\", "\\\\").replace("'", "\\'")


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
            "Error": error or "",
        })
    except Exception as e:
        logger.warning("LOG_ACCESS FAILED: %s", str(e))
              
def pg_keybox_update(keybox_id: int, fields: dict):
    """
    fields: dict de colonnes Postgres (snake_case) -> valeurs
    ex: {"active_pin": "1234", "active_start": "2026-02-10T12:00:00+01:00"}
    """
    if not fields:
        return

    cols = []
    params = []
    for col, val in fields.items():
        cols.append(f"{col}=%s")
        params.append(val)

    params.append(keybox_id)
    exec_sql(f"update keyboxes set {', '.join(cols)} where id=%s", tuple(params))

# =========================================================
# Keyboxes
# =========================================================
def get_keybox_by_qr(qrid):
    if not g.get("tenant_id"):
        return None

    return q1(
        "select * from keyboxes where tenant_id=%s and qrid=%s and enabled=true",
        (g.tenant_id, qrid),
    )

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

def ensure_active_or_next_pin(kb: dict):
    """
    Postgres-only.
    Garantit:
    - active_pin = heure courante (Luxembourg)
    - next_pin = heure suivante
    Retourne: (active_pin, active_pin_id, active_start_iso, active_end_iso, err)
    """
    try:
        f = kb  # kb est déjà le dict Postgres (select * from keyboxes)

        now = now_lu()
        cur_start = round_down_hour(now)
        cur_end = cur_start + timedelta(hours=1)

        # Si active_pin en DB correspond déjà à la fenêtre courante -> OK
        active_ok = (
            f.get("active_pin")
            and f.get("active_start") == cur_start
            and f.get("active_end") == cur_end
        )

        if not active_ok:
            pin, pin_id, err = igloo_create_hourly_pin(kb, cur_start, cur_end)
            if err:
                return None, None, None, None, err

            pg_keybox_update(f["id"], {
                "active_pin": pin,
                "active_pin_id": pin_id,
                "active_start": cur_start,
                "active_end": cur_end,
            })

            # maj cache local
            f["active_pin"] = pin
            f["active_pin_id"] = pin_id
            f["active_start"] = cur_start
            f["active_end"] = cur_end

        # Next = prochaine heure
        next_start = cur_end
        next_end = next_start + timedelta(hours=1)

        next_ok = (
            f.get("next_pin")
            and f.get("next_start") == next_start
            and f.get("next_end") == next_end
        )

        if not next_ok:
            pin2, pin2_id, err2 = igloo_create_hourly_pin(kb, next_start, next_end)
            if not err2:
                pg_keybox_update(f["id"], {
                    "next_pin": pin2,
                    "next_pin_id": pin2_id,
                    "next_start": next_start,
                    "next_end": next_end,
                })
                f["next_pin"] = pin2
                f["next_pin_id"] = pin2_id
                f["next_start"] = next_start
                f["next_end"] = next_end

        return (
            f.get("active_pin"),
            f.get("active_pin_id"),
            iso(f.get("active_start")),
            iso(f.get("active_end")),
            None
        )

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
        conds.append(idconds[0] if len(idconds) == 1 else "OR(" + ",".join(idconds) + ")")

    formula = "AND(" + ",".join(conds) + ")"
    recs = at_get(T_REQUESTS, formula=formula, max_records=1)
    return recs[0] if recs else None

@app.route("/")
def home():
    return "OK"
@app.route("/_pin_test/<qrid>")
def _pin_test(qrid):
    kb = get_keybox_by_qr(qrid)
    if not kb:
        return jsonify({"error": "qr_unknown"}), 404
    with _get_lock(qrid):
        pin, pin_id, s, e, err = ensure_active_or_next_pin(kb)
    return jsonify({"pin": pin, "pin_id": pin_id, "start": s, "end": e, "err": err})

@app.route("/access/<qr_id>", methods=["GET", "POST"])
@require_csrf
def tech_access(qr_id):
    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return "QR Code inconnu", 404

    f = kb
    bat = f.get("batiment", "")  # si tu as cette colonne en DB
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if request.method == "GET":
        return render_template_string(HTML_TECH_FORM, batiment=bat, csrf=csrf_input())

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

    allowed, reason, _user = pg_is_user_allowed(qr_id, email=email, phone=phone)

    if not allowed:
        detail = reason
        if (
            reason == "Utilisateur non enregistré."
            or reason == "Aucune permission active pour cette boîte."
            or "status=pending" in (reason or "")
        ):
            try:
                client = f.get("Client", "")
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
                # ... après avoir créé/confirmé la demande pending
        return render_template_string(
            HTML_PENDING,
            qr_id=qr_id,
            first=first,
            last=last,
            company=company,
            email=email,
            phone=phone,
            csrf=csrf_input(),
        )

    # IMPORTANT: re-fetch pour avoir la dernière version avant lock
    kb = get_keybox_by_qr(qr_id)

    with _get_lock(qr_id):
        pin, pin_id, s, e, err = ensure_active_or_next_pin(kb)

    if err:
        log_access(qr_id, first, last, company, channel="none", error=err)
        return render_template_string(HTML_TECH_RESULT, ok=False, msg="Service indisponible", detail=err)

    detail = f"Valide: {s} → {e}"
    log_access(qr_id, first, last, company, channel="screen", pin_id=pin_id, start=s, end=e, error="")
    return render_template_string(HTML_TECH_RESULT, ok=True, msg="Code prêt", detail=detail, pin=pin)

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
    
@app.route("/_debug_db")
def _debug_db():
    return jsonify({
        "MARKER": "DEBUG_DB_V2",
        "tenant_param": request.args.get("tenant"),
        "tenant_slug": getattr(g, "tenant_slug", None),
        "tenant_id": getattr(g, "tenant_id", None),
        "db": q1("select current_database() as db, current_user as usr"),
        "tenants": q("select id, slug, status from tenants order by id"),
        "keyboxes": q("select tenant_id, qrid, enabled from keyboxes order by id desc limit 20"),
    })

@app.route("/gerance")
def gerance_portal():
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    recs = get_keyboxes_for_client(client)

    rows = []
    for r in recs:
        f = r.get("fields", {}) or {}
        qr = f.get("QRID")
        bat = f.get("Batiment")
        emergency_set = bool(f.get("EmergencyCode"))

        _pin, _pid, s, e, err = ensure_active_or_next_pin(r)

        rows.append({
            "QRID": qr,
            "Batiment": bat,
            "EmergencySet": emergency_set,
            "NextStart": s,
            "NextEnd": e,
            "Err": err,
        })

    return render_template_string(HTML_GERANCE, rows=rows, csrf=csrf_input())

@app.route("/api/emergency/<qr_id>")
def api_emergency(qr_id):
    if not gerance_can_access_qr(qr_id):
        return jsonify({"error": "unauthorized"}), 401
    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return jsonify({"error": "qr_unknown"}), 404
    code = (kb.get("fields", {}) or {}).get("EmergencyCode")
    if not code:
        return jsonify({"error": "not_set"}), 404
    return jsonify({"emergencyCode": code})

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

    pg_keybox_update(kb["id"], {"emergency_code": code})
    return redirect(url_for("gerance_keybox", qr_id=qr_id))
@app.route("/_debug_tenant")
def _debug_tenant():
    host = (request.headers.get("X-Forwarded-Host") or request.host)
    return jsonify({
        "host": host,
        "tenant_param": request.args.get("tenant"),
        "tenant_id": getattr(g, "tenant_id", None),
        "tenants": q("select id, slug, status from tenants order by id"),
        "keyboxes": q("select tenant_id, qrid, enabled from keyboxes order by id desc limit 20"),
    })

@app.route("/gerance/keybox/<qr_id>")
def gerance_keybox(qr_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    if not gerance_can_access_qr(qr_id):
        return "Unauthorized", 401

    kb = get_keybox_by_qr(qr_id)
    kf = kb.get("fields", {}) or {}
    bat = kf.get("Batiment", "")

    perms = at_get(T_PERMS, formula=f"{{QRID}}='{qr_id}'", max_records=200)

    perm_rows = []
    for p in perms:
        pf = p.get("fields", {}) or {}
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
            "name": (uf.get("FirstName", "") + " " + uf.get("LastName", "")).strip(),
            "company": uf.get("Company", ""),
            "status": uf.get("Status", "") if user else "unknown",
        })

    return render_template_string(
    HTML_KEYBOX,
    qr_id=qr_id, batiment=bat,
    emergency=(kf.get("EmergencyCode") or ""),
    perms=perm_rows,
    csrf=csrf_input()
)
    
@app.route("/_igloo_check/<qrid>")
def _igloo_check(qrid):
    kb = get_keybox_by_qr(qrid)
    if not kb:
        return jsonify({"error": "qr_unknown"}), 404

    # support Airtable (kb["fields"]) ou Postgres (kb direct)
    f = (kb.get("fields") or kb or {})
    device_id = f.get("device_id") or f.get("DeviceId") or f.get("deviceId") or f.get("LockID")

    if not device_id:
        return jsonify({"error": "device_id_missing"}), 400

    token = get_oauth_token()

    # 1) check device existe ?
    url = f"{API_BASE}/devices/{device_id}"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20, verify=VERIFY_SSL)

    return jsonify({
        "device_id": device_id,
        "url": url,
        "status": r.status_code,
        "body": r.text[:500],
    })


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

    upsert_user(first, last, company, email, phone, status="approved")
    create_permission(qr_id, email, phone, active=True)
    return redirect(url_for("gerance_keybox", qr_id=qr_id))

@app.route("/gerance/perm/<perm_id>/toggle", methods=["POST"])
@require_csrf
def gerance_toggle_perm(perm_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))
    active = (request.form.get("active") == "1")
    set_permission_active(perm_id, active)
    back = request.form.get("back") or "/gerance"
    return redirect(back)

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

    keyboxes = get_keyboxes_for_client(client)
    qrids = {(kb.get("fields", {}) or {}).get("QRID") for kb in keyboxes}
    qrids.discard(None)
    qrids.discard("")

    reqs = at_get(T_REQUESTS, formula="{Status}='pending'", max_records=200) or []
    reqs = [r for r in reqs if (r.get("fields", {}) or {}).get("QRID") in qrids]

    return render_template_string(HTML_REQUESTS, reqs=reqs, client=client, csrf=csrf_input())

@app.route("/api/request_status/<qr_id>")
def api_request_status(qr_id):
    email = norm_email(request.args.get("email", ""))
    phone = norm_phone(request.args.get("phone", ""))

    allowed, reason, _ = pg_is_user_allowed(qr_id, email=email, phone=phone)
    if allowed:
        return jsonify({"status": "approved"})

    pending = find_pending_request(qr_id, email, phone)
    if pending:
        return jsonify({"status": "pending"})

    return jsonify({"status": "denied", "reason": reason})


@app.route("/gerance/requests/<req_id>/approve", methods=["POST"])
@require_csrf
def gerance_approve_request(req_id):
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    req = at_read(T_REQUESTS, req_id)
    f = req.get("fields", {}) or {}

    if f.get("Client") != client:
        return "Unauthorized", 401

    qrid = f.get("QRID")
    email = f.get("Email", "")
    phone = f.get("Phone", "")

    upsert_user(f.get("FirstName", ""), f.get("LastName", ""), f.get("Company", ""), email, phone, status="approved")
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
    f = req.get("fields", {}) or {}

    if f.get("Client") != client:
        return "Unauthorized", 401

    at_update(T_REQUESTS, req_id, {"Status": "denied"})
    return redirect(url_for("gerance_requests"))

@app.route("/prefill", strict_slashes=False)
def prefill():
    return jsonify({"error": "prefill disabled during postgres migration"}), 200


    keyboxes = at_get(T_KEYBOXES, formula="{Enabled}=1", max_records=200)
    out = {"ok": 0, "err": 0, "results": []}

    for kb in keyboxes:
        qr = (kb.get("fields", {}) or {}).get("QRID", "")
        try:
            with _get_lock(qr):
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

    keyboxes = get_keyboxes_for_client(client)
    qrids = {(kb.get("fields", {}) or {}).get("QRID") for kb in keyboxes}
    qrids.discard(None)
    qrids.discard("")

    logs = at_get_sorted(T_LOG, max_records=300, sort_field="Timestamp", direction="desc") or []

    def is_success(rec):
        f = (rec.get("fields", {}) or {})
        if f.get("QRID") not in qrids:
            return False
        if (f.get("Channel") or "") != "screen":
            return False
        return (f.get("Error") or "").strip() == ""

    logs = [r for r in logs if is_success(r)][:200]
    return render_template_string(HTML_LOGS, logs=logs, client=client)

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    return resp


# =========================================================
# HTML templates (from your version)
# =========================================================
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
        {{csrf|safe}}
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

HTML_PENDING = """
<body style="font-family:sans-serif;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
  <div style="width:520px;background:#111827;padding:24px;border-radius:16px;text-align:center;">
    <h2 style="color:#fbbf24;margin:0 0 8px;">Demande en attente</h2>
    <p style="opacity:.85;margin:0;">La gérance doit valider votre accès…</p>
    <p id="st" style="opacity:.7;font-size:12px;margin-top:12px;">Vérification automatique…</p>

    <script>
      const qr = "{{qr_id}}";
      const email = encodeURIComponent("{{email}}");
      const phone = encodeURIComponent("{{phone}}");

      async function tick(){
        const r = await fetch(`/api/request_status/${qr}?email=${email}&phone=${phone}`);
        const j = await r.json();

        if(j.status === "approved"){
          document.getElementById("st").innerText = "Validé ✅ Redirection…";
          window.location.href = `/access/${qr}`;
          return;
        }
        if(j.status === "denied"){
          document.getElementById("st").innerText = "Refusé ❌";
          return;
        }
        setTimeout(tick, 3000);
      }
      tick();
    </script>
  </div>
</body>
"""
HTML_PENDING = """
<body style="font-family:sans-serif;background:#0f172a;color:white;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">
  <div style="width:520px;background:#111827;padding:24px;border-radius:16px;text-align:center;">
    <h2 style="color:#fbbf24;margin:0 0 8px;">Demande en attente</h2>
    <p style="opacity:.85;margin:0 0 14px;">
      La gérance doit valider l’accès. Cette page se met à jour automatiquement.
    </p>

    <div id="status" style="opacity:.85;font-size:13px;">Vérification…</div>

    <form id="autoForm" method="post" action="/access/{{qr_id}}" style="display:none;">
      {{csrf|safe}}
      <input type="hidden" name="first" value="{{first}}">
      <input type="hidden" name="last" value="{{last}}">
      <input type="hidden" name="company" value="{{company}}">
      <input type="hidden" name="email" value="{{email}}">
      <input type="hidden" name="phone" value="{{phone}}">
    </form>

    <script>
      const qrId = "{{qr_id}}";
      const email = encodeURIComponent("{{email}}");
      const phone = encodeURIComponent("{{phone}}");
      const statusEl = document.getElementById("status");
      const form = document.getElementById("autoForm");

      async function check(){
        try{
          const r = await fetch(`/api/request_status/${qrId}?email=${email}&phone=${phone}`);
          const d = await r.json();

          if(d.status === "approved"){
            statusEl.innerText = "✅ Accès validé — récupération du code…";
            form.submit(); // <- recharge la page avec le code
            return;
          }

          if(d.status === "pending"){
            statusEl.innerText = "⏳ Toujours en attente…";
            return;
          }

          statusEl.innerText = "❌ Demande refusée ou introuvable.";
        }catch(e){
          statusEl.innerText = "Erreur réseau, nouvelle tentative…";
        }
      }

      check();
      setInterval(check, 3000); // toutes les 3s
    </script>
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


































