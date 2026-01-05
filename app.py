import os
import requests
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# =========================
# CONFIG APP
# =========================
app = Flask(__name__)

# Mets ceci en variable d'env sur Render (RECOMMANDÉ)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "nanas_ultra_secret_2026")

TZ = ZoneInfo("Europe/Luxembourg")

# =========================
# CONFIG AIRTABLE
# =========================
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Table 1")

# =========================
# CONFIG IGLOO
# =========================
IGLOO_CLIENT_ID = os.getenv("IGLOO_CLIENT_ID", "xprluqseolemaoc3l3hu9d2zlt")
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")  # obligatoire sur Render

AUTH_URL = "https://auth.igloohome.co/oauth2/token"
API_BASE = "https://api.igloodeveloper.co/igloohome"

PIN_DURATION_HOURS = int(os.getenv("PIN_DURATION_HOURS", "4"))  # durée d'accès
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"  # sur Render: true

# =========================
# CONFIG ACCÈS
# =========================
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "TON_MOT_DE_PASSE_PERSO")  # À changer

# =========================
# TOKEN CACHE (évite de retoken à chaque click)
# =========================
_token_cache = {
    "access_token": None,
    "expires_at": 0
}


# =========================
# AIRTABLE HELPERS
# =========================
def airtable_url():
    return f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"

def airtable_headers():
    return {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}

def get_airtable_records(formula=""):
    if not (AIRTABLE_API_KEY and AIRTABLE_BASE_ID):
        return []
    url = airtable_url()
    params = {"filterByFormula": formula} if formula else {}
    try:
        res = requests.get(url, headers=airtable_headers(), params=params, timeout=20)
        res.raise_for_status()
        return res.json().get("records", [])
    except Exception:
        return []

def update_airtable_record(record_id: str, fields: dict) -> bool:
    """PATCH Airtable record (pour stocker VarianceHourly etc.)"""
    if not (AIRTABLE_API_KEY and AIRTABLE_BASE_ID and record_id):
        return False
    url = f"{airtable_url()}/{record_id}"
    try:
        res = requests.patch(url, headers={**airtable_headers(), "Content-Type": "application/json"},
                             json={"fields": fields}, timeout=20)
        return res.status_code in (200, 201)
    except Exception:
        return False


# =========================
# IGLOO HELPERS
# =========================
def round_up_to_next_hour(dt: datetime) -> datetime:
    # prochaine heure pile (HH:00:00)
    dt = dt.astimezone(TZ)
    return dt.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)

def iso_with_offset(dt: datetime) -> str:
    # ex: 2026-01-05T16:00:00+01:00
    return dt.astimezone(TZ).isoformat(timespec="seconds")

def get_oauth_token() -> str:
    """Récupère un token OAuth avec Basic Auth (comme curl -u). Cache en mémoire."""
    now_ts = int(datetime.now(TZ).timestamp())
    if _token_cache["access_token"] and now_ts < (_token_cache["expires_at"] - 120):
        return _token_cache["access_token"]

    if not IGLOO_CLIENT_SECRET:
        raise RuntimeError("IGLOO_CLIENT_SECRET manquant (variable d'environnement).")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        # parfois utile :
        "User-Agent": "curl/8.0"
    }

    # EXACTEMENT comme curl: grant_type=client_credentials
    data = "grant_type=client_credentials"

    r = requests.post(
        AUTH_URL,
        auth=(IGLOO_CLIENT_ID.strip(), IGLOO_CLIENT_SECRET.strip()),
        headers=headers,
        data=data,
        verify=VERIFY_SSL,
        timeout=20,
    )

    # Si erreur, on remonte un message clair
    if r.status_code != 200:
        raise RuntimeError(f"OAuth failed {r.status_code}: {r.text}")

    j = r.json()
    token = j.get("access_token")
    expires_in = int(j.get("expires_in", 3600))

    if not token:
        raise RuntimeError(f"OAuth token missing: {r.text}")

    _token_cache["access_token"] = token
    _token_cache["expires_at"] = now_ts + expires_in
    return token

def choose_variance_hourly(fields: dict) -> int:
    """
    Hourly variance: 1..3
    Si Airtable a un champ 'VarianceHourly', on l'utilise et on tourne.
    Sinon, on revient à 1.
    """
    v = fields.get("VarianceHourly")
    try:
        v = int(v) if v is not None else 1
    except Exception:
        v = 1
    if v < 1 or v > 3:
        v = 1
    return v

def rotate_variance_hourly(current: int) -> int:
    return 1 if current >= 3 else current + 1

def generate_igloo_hourly_algopin(device_id: str, record_id: str = None, record_fields: dict = None):
    """
    Génère un AlgoPIN Hourly via api.igloodeveloper.co.
    Retourne: (pin, pinId, startDate, endDate, error)
    """
    try:
        token = get_oauth_token()

        start_dt = round_up_to_next_hour(datetime.now(TZ))
        end_dt = start_dt + timedelta(hours=PIN_DURATION_HOURS)

        # variance 1..3 (hourly)
        variance = 1
        if record_fields:
            variance = choose_variance_hourly(record_fields)

        payload = {
            "variance": variance,
            "startDate": iso_with_offset(start_dt),
            "endDate": iso_with_offset(end_dt),
            "accessName": "Nanas_Access"
        }

        url = f"{API_BASE}/devices/{device_id}/algopin/hourly"

        r = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "curl/8.0"
            },
            json=payload,
            verify=VERIFY_SSL,
            timeout=20,
        )

        if r.status_code not in (200, 201):
            return ("ERREUR_PIN", None, payload["startDate"], payload["endDate"], f"{r.status_code}: {r.text}")

        j = r.json()
        pin = j.get("pin")
        pin_id = j.get("pinId")

        if not pin:
            return ("ERREUR_PIN", None, payload["startDate"], payload["endDate"], f"Réponse inattendue: {r.text}")

        # Rotation variance stockée dans Airtable (optionnel)
        if record_id and record_fields is not None:
            next_v = rotate_variance_hourly(variance)
            update_airtable_record(record_id, {"VarianceHourly": next_v})

        return (pin, pin_id, payload["startDate"], payload["endDate"], None)

    except Exception as e:
        return ("INDISPONIBLE", None, None, None, str(e))


# =========================
# ROUTES
# =========================

@app.route('/access/<qr_id>')
def tech_access(qr_id):
    res = get_airtable_records(f"{{QRID}} = '{qr_id}'")
    if not res:
        return "QR Code Inconnu", 404

    record = res[0]
    fields = record.get("fields", {})

    # DeviceId = IGK... (OBLIGATOIRE)
    device_id = fields.get("DeviceId") or fields.get("LockID")
    if not device_id:
        return "DeviceId manquant dans Airtable (champ DeviceId).", 500

    pin, pin_id, startDate, endDate, err = generate_igloo_hourly_algopin(
        device_id=device_id,
        record_id=record.get("id"),
        record_fields=fields
    )

    return render_template_string(
        HTML_TECH,
        batiment=fields.get('Batiment', ''),
        pin=pin,
        startDate=startDate,
        endDate=endDate,
        err=err
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client = request.form.get('client', '')
        pwd = request.form.get('pwd', '')
        records = get_airtable_records(f"AND({{Client}} = '{client}', {{Password}} = '{pwd}')")
        if records:
            session['user'] = client
            session['role'] = 'gerance'
            return redirect(url_for('gerance_portal'))
        return render_template_string(HTML_LOGIN, error="Identifiants incorrects")
    return render_template_string(HTML_LOGIN)


@app.route('/gerance')
def gerance_portal():
    if session.get('role') != 'gerance':
        return redirect(url_for('login'))
    records = get_airtable_records(f"{{Client}} = '{session['user']}'")
    return render_template_string(HTML_PORTAL, title="Portail Gérance", records=records)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if request.form.get('pwd') == ADMIN_PASSWORD:
            session['role'] = 'admin'
        else:
            return "Accès refusé", 403

    if session.get('role') != 'admin':
        return '<form method="post">Pass Admin: <input type="password" name="pwd"><button>OK</button></form>'

    records = get_airtable_records()
    return render_template_string(HTML_PORTAL, title="FULL ADMIN", records=records)


@app.route('/api/get_pin/<qr_id>')
def api_pin(qr_id):
    if not session.get('role'):
        return jsonify({"pin": "Non autorisé"}), 401

    res = get_airtable_records(f"{{QRID}} = '{qr_id}'")
    if not res:
        return jsonify({"pin": "QR inconnu"}), 404

    record = res[0]
    fields = record.get("fields", {})
    device_id = fields.get("DeviceId") or fields.get("LockID")
    if not device_id:
        return jsonify({"pin": "DeviceId manquant (champ DeviceId)"}), 500

    pin, pin_id, startDate, endDate, err = generate_igloo_hourly_algopin(
        device_id=device_id,
        record_id=record.get("id"),
        record_fields=fields
    )

    return jsonify({
        "pin": pin,
        "pinId": pin_id,
        "startDate": startDate,
        "endDate": endDate,
        "error": err
    })


# =========================
# TEMPLATES
# =========================
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

HTML_PORTAL = """
<body style="font-family:sans-serif; background:#f4f7f9; padding:20px;">
    <div style="max-width:500px; margin:auto; background:white; padding:30px; border-radius:20px; box-shadow:0 10px 25px rgba(0,0,0,0.1); text-align:center;">
        <h2 style="color:#2563eb;">{{title}}</h2>
        <select id="sel" style="width:100%; padding:12px; margin:20px 0; border-radius:8px; border:1px solid #ddd;">
            <option value="">-- Choisir un bâtiment --</option>
            {% for r in records %}
            <option value="{{r['fields']['QRID']}}">{{r['fields'].get('Batiment','?')}} ({{r['fields'].get('Client','?')}})</option>
            {% endfor %}
        </select>
        <button onclick="getPin()" style="width:100%; padding:15px; background:#2563eb; color:white; border:none; border-radius:8px; font-weight:bold; cursor:pointer;">GÉNÉRER CODE</button>

        <div id="pin" style="font-size:50px; font-weight:bold; margin:20px 0; color:#1e293b;">----</div>
        <div id="meta" style="font-size:12px; opacity:0.8; color:#334155;"></div>
        <div id="err" style="font-size:12px; color:#ef4444;"></div>
    </div>
    <script>
        function getPin(){
            const id = document.getElementById('sel').value;
            if(!id) return;
            document.getElementById('pin').innerText = "...";
            document.getElementById('meta').innerText = "";
            document.getElementById('err').innerText = "";

            fetch('/api/get_pin/'+id)
              .then(r=>r.json())
              .then(d=>{
                document.getElementById('pin').innerText = d.pin || "ERREUR";
                if(d.startDate && d.endDate){
                  document.getElementById('meta').innerText = `Actif: ${d.startDate} → ${d.endDate}`;
                }
                if(d.error){
                  document.getElementById('err').innerText = d.error;
                }
              });
        }
    </script>
</body>
"""

HTML_TECH = """
<body style="font-family:sans-serif; background:#1e293b; color:white; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;">
    <div style="text-align:center; padding:20px; max-width:520px;">
        <h2 style="color:#60a5fa;">ACCÈS TECHNIQUE</h2>
        <p style="opacity:0.9;">{{batiment}}</p>

        <div style="font-size:64px; font-weight:bold; background:white; color:#1e293b; padding:18px; border-radius:15px; margin:18px 0; letter-spacing:5px;">
            {{pin}}
        </div>

        {% if startDate and endDate %}
        <p style="font-size:12px; opacity:0.85;">
          Actif: <b>{{startDate}}</b> → <b>{{endDate}}</b><br>
          (Sans bridge: début à l’heure pile. Le code doit être utilisé au moins une fois dans les 24h après le début, sinon il expire.)
        </p>
        {% endif %}

        {% if err %}
        <p style="font-size:12px; color:#fca5a5;">Erreur: {{err}}</p>
        {% endif %}
    </div>
</body>
"""

# =========================
# MAIN (local seulement)
# =========================
if __name__ == '__main__':
    app.run(debug=True)
