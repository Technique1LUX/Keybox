import os
import time
import requests
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_only_change_me")

TZ = ZoneInfo("Europe/Luxembourg")

# -------------------------
# Render / Env
# -------------------------
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"  # Render: true ; Local debug: false
PIN_DURATION_HOURS = int(os.getenv("PIN_DURATION_HOURS", "4"))
EMERGENCY_DURATION_HOURS = int(os.getenv("EMERGENCY_DURATION_HOURS", "4"))  # même logique que hourly

# -------------------------
# Airtable
# -------------------------
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")

T_KEYBOXES = os.getenv("AIRTABLE_TABLE_KEYBOXES", "Keyboxes")
T_USERS = os.getenv("AIRTABLE_TABLE_USERS", "Users")
T_PERMS = os.getenv("AIRTABLE_TABLE_PERMISSIONS", "Permissions")
T_LOG = os.getenv("AIRTABLE_TABLE_ACCESSLOG", "AccessLog")

# -------------------------
# Igloo OAuth + API
# -------------------------
IGLOO_CLIENT_ID = os.getenv("IGLOO_CLIENT_ID")
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")

AUTH_URL = "https://auth.igloohome.co/oauth2/token"
API_BASE = "https://api.igloodeveloper.co/igloohome"

# -------------------------
# Admin / Auth
# -------------------------
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change_me")

# -------------------------
# Token cache (mémoire)
# -------------------------
_token_cache = {"token": None, "exp": 0}

# -------------------------
# Rate limit (mémoire simple)
# -------------------------
_rl = {}  # key -> list[timestamps]


# =========================================================
# Helpers time
# =========================================================
def now_lu():
    return datetime.now(TZ)

def iso(dt: datetime) -> str:
    return dt.astimezone(TZ).isoformat(timespec="seconds")

def parse_iso(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def round_down_hour(dt: datetime) -> datetime:
    dt = dt.astimezone(TZ)
    return dt.replace(minute=0, second=0, microsecond=0)

def next_hour(dt: datetime) -> datetime:
    return round_down_hour(dt) + timedelta(hours=1)

def is_active_window(start_iso: str, end_iso: str) -> bool:
    if not start_iso or not end_iso:
        return False
    s = parse_iso(start_iso)
    e = parse_iso(end_iso)
    if not s or not e:
        return False
    n = now_lu()
    return s <= n < e


# =========================================================
# Airtable minimal client
# =========================================================
def at_url(table: str) -> str:
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{table}"

def at_headers(json=False):
    h = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    if json:
        h["Content-Type"] = "application/json"
    return h

def at_get(table: str, formula: str = "", max_records: int = 50):
    if not (AIRTABLE_API_KEY and AIRTABLE_BASE_ID):
        return []
    params = {}
    if formula:
        params["filterByFormula"] = formula
    params["maxRecords"] = max_records
    r = requests.get(at_url(table), headers=at_headers(), params=params, timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json().get("records", [])

def at_create(table: str, fields: dict):
    r = requests.post(at_url(table), headers=at_headers(json=True), json={"fields": fields},
                      timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json()

def at_update(table: str, record_id: str, fields: dict):
    r = requests.patch(f"{at_url(table)}/{record_id}", headers=at_headers(json=True),
                       json={"fields": fields}, timeout=20, verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json()


# =========================================================
# Igloo OAuth + AlgoPIN
# =========================================================
def get_oauth_token() -> str:
    # cache (refresh 2 min avant)
    now_ts = int(time.time())
    if _token_cache["token"] and now_ts < (_token_cache["exp"] - 120):
        return _token_cache["token"]

    if not IGLOO_CLIENT_ID or not IGLOO_CLIENT_SECRET:
        raise RuntimeError("IGLOO_CLIENT_ID / IGLOO_CLIENT_SECRET manquants (env vars).")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "curl/8.0",
    }

    # IMPORTANT: même format que curl
    data = "grant_type=client_credentials"

    r = requests.post(
        AUTH_URL,
        auth=(IGLOO_CLIENT_ID.strip(), IGLOO_CLIENT_SECRET.strip()),
        headers=headers,
        data=data,
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
    # hourly: 1..3
    if cur not in (1, 2, 3):
        cur = 1
    return 1 if cur == 3 else cur + 1

def create_algopin_hourly(device_id: str, start_dt: datetime, end_dt: datetime, variance: int, access_name: str):
    token = get_oauth_token()
    url = f"{API_BASE}/devices/{device_id}/algopin/hourly"
    payload = {
        "variance": variance,
        "startDate": iso(start_dt),
        "endDate": iso(end_dt),
        "accessName": access_name
    }
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "curl/8.0"
        },
        json=payload,
        timeout=20,
        verify=VERIFY_SSL,
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"AlgoPIN failed {r.status_code}: {r.text}")
    return r.json()  # {pin, pinId}


# =========================================================
# Business: users / permissions / logs
# =========================================================
def norm_phone(p: str) -> str:
    return (p or "").strip().replace(" ", "")

def norm_email(e: str) -> str:
    return (e or "").strip().lower()

def find_user(email: str, phone: str):
    email = norm_email(email)
    phone = norm_phone(phone)
    if not email and not phone:
        return None

    parts = []
    if email:
        parts.append(f"{{Email}} = '{email}'")
    if phone:
        parts.append(f"{{Phone}} = '{phone}'")
    formula = "OR(" + ",".join(parts) + ")" if len(parts) > 1 else parts[0]
    recs = at_get(T_USERS, formula=formula, max_records=5)
    return recs[0] if recs else None

def create_pending_user(first, last, company, email, phone):
    fields = {
        "FirstName": first,
        "LastName": last,
        "Company": company,
        "Email": norm_email(email) if email else "",
        "Phone": norm_phone(phone) if phone else "",
        "Status": "pending"
    }
    return at_create(T_USERS, fields)

def is_user_allowed(qrid: str, email: str, phone: str):
    """
    Autorisé si:
    - user existe et Status == 'approved'
    - permission Active pour (QRID + contact)
    """
    email = norm_email(email)
    phone = norm_phone(phone)

    user = find_user(email, phone)
    if not user:
        return False, "Utilisateur non enregistré (créé en pending).", None

    status = (user.get("fields", {}).get("Status") or "").lower()
    if status != "approved":
        return False, f"Utilisateur non approuvé (status={status}).", user

    # Permissions: champs texte QRID, Email, Phone, Active (checkbox)
    conds = [f"{{QRID}} = '{qrid}'", "{Active} = 1"]
    idconds = []
    if email:
        idconds.append(f"{{Email}} = '{email}'")
    if phone:
        idconds.append(f"{{Phone}} = '{phone}'")
    if not idconds:
        return False, "Aucun email/téléphone fourni.", user

    if len(idconds) == 1:
        conds.append(idconds[0])
    else:
        conds.append("OR(" + ",".join(idconds) + ")")

    formula = "AND(" + ",".join(conds) + ")"
    perms = at_get(T_PERMS, formula=formula, max_records=5)
    if not perms:
        return False, "Aucune permission active pour cette boîte.", user

    return True, None, user

def log_access(qrid: str, first: str, last: str, company: str, channel: str,
               pin_id: str = "", start: str = "", end: str = "", error: str = ""):
    fields = {
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
    }
    try:
        at_create(T_LOG, fields)
    except Exception:
        pass


# =========================================================
# Business: PIN active / urgence (stocké dans Keyboxes)
# =========================================================
def get_keybox_by_qr(qrid: str):
    recs = at_get(T_KEYBOXES, formula=f"{{QRID}} = '{qrid}'", max_records=5)
    return recs[0] if recs else None

def ensure_active_pin_for_keybox(keybox_record: dict, for_emergency: bool = False):
    """
    Sans cron: on utilise des champs stockés en Airtable.
    Champs utilisés (Keyboxes):
      - DeviceId (IGK...)
      - VarianceHourly (num 1..3)
      - ActivePin, ActivePinId, ActiveStart, ActiveEnd
      - NextPin, NextPinId, NextStart, NextEnd

    Logique:
      - si Active est actif -> ok
      - si Next est devenu actif -> on "promote"
      - sinon on s'assure qu'un Next existe pour la prochaine heure
    """
    fields = keybox_record.get("fields", {})
    rid = keybox_record.get("id")
    device_id = fields.get("DeviceId")
    if not device_id:
        return None, None, None, None, "DeviceId manquant dans Keyboxes."

    # Durée
    duration = EMERGENCY_DURATION_HOURS if for_emergency else PIN_DURATION_HOURS

    active_pin = fields.get("ActivePin")
    active_pid = fields.get("ActivePinId")
    active_s = fields.get("ActiveStart")
    active_e = fields.get("ActiveEnd")

    next_pin = fields.get("NextPin")
    next_pid = fields.get("NextPinId")
    next_s = fields.get("NextStart")
    next_e = fields.get("NextEnd")

    # 1) Active OK ?
    if active_pin and is_active_window(active_s, active_e):
        return active_pin, active_pid, active_s, active_e, None

    # 2) Next est-il maintenant actif ? -> promote
    if next_pin and is_active_window(next_s, next_e):
        try:
            at_update(T_KEYBOXES, rid, {
                "ActivePin": next_pin,
                "ActivePinId": next_pid or "",
                "ActiveStart": next_s,
                "ActiveEnd": next_e,
                "NextPin": "",
                "NextPinId": "",
                "NextStart": "",
                "NextEnd": ""
            })
        except Exception:
            pass
        return next_pin, next_pid, next_s, next_e, None

    # 3) s'assurer qu'un Next existe pour prochaine heure
    n = now_lu()
    start_dt = next_hour(n)  # prochaine heure pile
    end_dt = start_dt + timedelta(hours=duration)

    expected_s = iso(start_dt)
    expected_e = iso(end_dt)

    # si next déjà bon, renvoyer (pas actif mais prêt)
    if next_pin and next_s == expected_s and next_e == expected_e:
        return next_pin, next_pid, next_s, next_e, None

    # sinon, créer un Next
    variance = fields.get("VarianceHourly") or 1
    try:
        variance = int(variance)
    except Exception:
        variance = 1
    if variance not in (1, 2, 3):
        variance = 1

    try:
        j = create_algopin_hourly(
            device_id=device_id,
            start_dt=start_dt,
            end_dt=end_dt,
            variance=variance,
            access_name="EMERGENCY" if for_emergency else "ACCESS"
        )
        pin = j.get("pin")
        pin_id = j.get("pinId")

        # rotate variance
        next_var = rotate_variance_hourly(variance)

        # stocker Next
        at_update(T_KEYBOXES, rid, {
            "NextPin": pin,
            "NextPinId": pin_id or "",
            "NextStart": expected_s,
            "NextEnd": expected_e,
            "VarianceHourly": next_var
        })

        return pin, pin_id, expected_s, expected_e, None

    except Exception as e:
        return None, None, expected_s, expected_e, str(e)


# =========================================================
# Sending (optional)
# =========================================================
def send_sms(to_phone: str, text: str):
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    tok = os.getenv("TWILIO_AUTH_TOKEN")
    from_ = os.getenv("TWILIO_FROM")
    if not (sid and tok and from_):
        return "SMS non configuré (Twilio)."

    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    r = requests.post(url, data={"From": from_, "To": to_phone, "Body": text},
                      auth=(sid, tok), timeout=20)
    if r.status_code not in (200, 201):
        return f"Erreur SMS: {r.status_code} {r.text}"
    return None

def send_email(to_email: str, subject: str, content: str):
    api_key = os.getenv("SENDGRID_API_KEY")
    from_email = os.getenv("EMAIL_FROM")
    if not (api_key and from_email):
        return "Email non configuré (SendGrid)."

    r = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
            "from": {"email": from_email},
            "content": [{"type": "text/plain", "value": content}]
        },
        timeout=20
    )
    if r.status_code not in (200, 202):
        return f"Erreur email: {r.status_code} {r.text}"
    return None


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
# Routes
# =========================================================
@app.route("/")
def home():
    return "OK"

@app.route("/access/<qr_id>", methods=["GET", "POST"])
def tech_access(qr_id):
    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return "QR Code inconnu", 404

    fields = kb.get("fields", {})
    bat = fields.get("Batiment", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if request.method == "GET":
        return render_template_string(HTML_TECH_FORM, batiment=bat)

    if not rate_limit(f"{qr_id}:{ip}", max_req=5, window_sec=600):
        return render_template_string(HTML_TECH_RESULT, ok=False, msg="Trop de demandes",
                                      detail="Réessayez dans quelques minutes.")

    first = (request.form.get("first") or "").strip()
    last = (request.form.get("last") or "").strip()
    company = (request.form.get("company") or "").strip()
    email = norm_email(request.form.get("email") or "")
    phone = norm_phone(request.form.get("phone") or "")

    # 1) user + permission
    allowed, reason, user = is_user_allowed(qr_id, email=email, phone=phone)

    if not allowed:
        # si user absent: créer pending
        if user is None:
            try:
                create_pending_user(first, last, company, email, phone)
            except Exception:
                pass

        log_access(qr_id, first, last, company, channel="none", error=reason)
        return render_template_string(
            HTML_TECH_RESULT,
            ok=False,
            msg="Accès refusé",
            detail=reason or "Non autorisé"
        )

    # 2) PIN (actif si disponible, sinon next)
    pin, pin_id, start_iso, end_iso, err = ensure_active_pin_for_keybox(kb, for_emergency=False)
    if err:
        log_access(qr_id, first, last, company, channel="none", error=err)
        return render_template_string(HTML_TECH_RESULT, ok=False, msg="Service indisponible", detail=err)

    # 3) envoi
    channel = "screen"
    send_err = None
    message = f"Code accès {bat}: {pin}\nActif: {start_iso} → {end_iso}"

    # priorité SMS si téléphone présent, sinon email
    if phone:
        send_err = send_sms(phone, message)
        if not send_err:
            channel = "sms"
    elif email:
        send_err = send_email(email, "Votre code d'accès", message)
        if not send_err:
            channel = "email"

    log_access(qr_id, first, last, company, channel=channel, pin_id=pin_id, start=start_iso, end=end_iso, error=send_err or "")

    # Si l'envoi a marché, on n'affiche pas forcément le code (sécurité)
    shown = pin if (channel == "screen" or send_err) else "Envoyé"

    detail = f"Actif: {start_iso} → {end_iso}"
    if not is_active_window(start_iso, end_iso):
        detail += " (Ce code est préparé pour la prochaine fenêtre à l’heure pile.)"

    return render_template_string(
        HTML_TECH_RESULT,
        ok=True,
        msg="Code prêt",
        detail=(detail + (f" — Envoi: {channel}" if channel != "screen" else "")),
        pin=shown
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client = request.form.get("client", "")
        pwd = request.form.get("pwd", "")
        recs = at_get(T_KEYBOXES, formula=f"AND({{Client}}='{client}', {{Password}}='{pwd}')", max_records=50)
        if recs:
            session["role"] = "gerance"
            session["client"] = client
            return redirect(url_for("gerance"))
        return render_template_string(HTML_LOGIN, error="Identifiants incorrects")
    return render_template_string(HTML_LOGIN)

@app.route("/gerance")
def gerance():
    if session.get("role") != "gerance":
        return redirect(url_for("login"))

    client = session.get("client")
    recs = at_get(T_KEYBOXES, formula=f"{{Client}}='{client}'", max_records=50)

    # Préparer un "code urgence" (en pratique: on affiche le Next/Active)
    view = []
    for r in recs:
        f = r.get("fields", {})
        qr = f.get("QRID")
        bat = f.get("Batiment")
        # emergency pin = même logique hourly ici (tu peux séparer plus tard)
        pin, pid, s, e, err = ensure_active_pin_for_keybox(r, for_emergency=True)
        view.append({
            "QRID": qr,
            "Batiment": bat,
            "pin": pin if pin and is_active_window(s, e) else "(prêt)",
            "start": s,
            "end": e,
            "error": err
        })

    return render_template_string(HTML_GERANCE, rows=view)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if request.form.get("pwd") == ADMIN_PASSWORD:
            session["role"] = "admin"
        else:
            return "Accès refusé", 403

    if session.get("role") != "admin":
        return '<form method="post">Pass Admin: <input type="password" name="pwd"><button>OK</button></form>'

    recs = at_get(T_KEYBOXES, max_records=100)
    return render_template_string(HTML_ADMIN, records=recs)

@app.route("/api/get_pin/<qr_id>")
def api_get_pin(qr_id):
    # gérance/admin seulement
    if session.get("role") not in ("gerance", "admin"):
        return jsonify({"error": "unauthorized"}), 401

    kb = get_keybox_by_qr(qr_id)
    if not kb:
        return jsonify({"error": "qr_unknown"}), 404

    pin, pin_id, s, e, err = ensure_active_pin_for_keybox(kb, for_emergency=True)
    return jsonify({"pin": pin, "pinId": pin_id, "startDate": s, "endDate": e, "error": err})


# =========================================================
# Templates
# =========================================================
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
      <p style="font-size:12px;opacity:.7;margin-top:10px;">Si vous êtes enregistré, le code est envoyé par SMS ou email.</p>
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
  <div style="max-width:700px;margin:auto;background:white;padding:24px;border-radius:20px;box-shadow:0 10px 25px rgba(0,0,0,0.1);">
    <h2 style="color:#2563eb;margin-top:0;">Portail Gérance — Codes d’urgence</h2>
    <p style="opacity:.75;">Sans bridge, les codes sont valables sur des fenêtres à l’heure pile (hourly). Si un code n’est pas encore actif, il est “prêt” pour la prochaine fenêtre.</p>
    <table style="width:100%;border-collapse:collapse;">
      <tr style="text-align:left;border-bottom:1px solid #eee;">
        <th style="padding:10px;">Bâtiment</th>
        <th style="padding:10px;">QRID</th>
        <th style="padding:10px;">Code</th>
        <th style="padding:10px;">Fenêtre</th>
      </tr>
      {% for r in rows %}
      <tr style="border-bottom:1px solid #f1f5f9;">
        <td style="padding:10px;">{{r.Batiment}}</td>
        <td style="padding:10px;">{{r.QRID}}</td>
        <td style="padding:10px;font-weight:700;">{{r.pin}}</td>
        <td style="padding:10px;font-size:12px;opacity:.85;">
          {{r.start}} → {{r.end}}
          {% if r.error %}<div style="color:#ef4444;">{{r.error}}</div>{% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
    <p style="margin-top:14px;font-size:12px;opacity:.7;">Astuce: le QR technicien est /access/&lt;QRID&gt;.</p>
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
      </tr>
      {% for r in records %}
      <tr style="border-bottom:1px solid #f1f5f9;">
        <td style="padding:10px;">{{r.fields.get('Client','')}}</td>
        <td style="padding:10px;">{{r.fields.get('Batiment','')}}</td>
        <td style="padding:10px;">{{r.fields.get('QRID','')}}</td>
        <td style="padding:10px;">{{r.fields.get('DeviceId','')}}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
"""


# =========================================================
# Local run
# =========================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
