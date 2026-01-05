import os, requests, urllib3
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "nanas_ultra_secret_2026"

# Configuration
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = "Table 1"
IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")
ADMIN_PASSWORD = "TON_MOT_DE_PASSE_PERSO" # À changer

def get_airtable_records(formula=""):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    params = {"filterByFormula": formula} if formula else {}
    try:
        res = requests.get(url, headers=headers, params=params)
        return res.json().get('records', [])
    except: return []

def generate_igloo_pin(lock_id):
    try:
        # 1. Tentative d'obtention du Token avec une méthode alternative
        auth_url = "https://auth.igloohome.co/oauth2/token"
        payload_auth = {
            "grant_type": "client_credentials",
            "client_id": IGLOO_CLIENT_ID,
            "client_secret": IGLOO_CLIENT_SECRET
        }
        
        # On essaie d'envoyer les identifiants en direct dans le JSON
        auth_res = requests.post(auth_url, data=payload_auth, verify=False)
        
        if auth_res.status_code != 200:
            # Si ça échoue encore, on tente la méthode "Header" classique
            auth_res = requests.post(auth_url, auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET), 
                                     data={"grant_type": "client_credentials"}, verify=False)

        token = auth_res.json().get('access_token')
        if not token:
            return "TOKEN_FAIL"

        # 2. Demande du PIN
        pin_url = f"https://api.igloohome.co/v2/locks/{lock_id}/pins"
        now = datetime.utcnow() + timedelta(minutes=5)
        payload_pin = {
            "name": "Nanas_Access",
            "type": "duration",
            "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "endDate": (now + timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = requests.post(pin_url, json=payload_pin, headers=headers, verify=False)
        
        return r.json().get('pin', "ERREUR_PIN")

    except Exception as e:
        return "INDISPONIBLE"

# --- 1. PAGE TECH (Accès Direct QR) ---
@app.route('/access/<qr_id>')
def tech_access(qr_id):
    res = get_airtable_records(f"{{QRID}} = '{qr_id}'")
    if not res: return "QR Code Inconnu", 404
    fields = res[0]['fields']
    pin = generate_igloo_pin(fields.get('LockID'))
    return render_template_string(HTML_TECH, batiment=fields.get('Batiment'), pin=pin)

# --- 2. PAGE GÉRANCE (Login Commun) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client = request.form.get('client')
        pwd = request.form.get('pwd')
        records = get_airtable_records(f"AND({{Client}} = '{client}', {{Password}} = '{pwd}')")
        if records:
            session['user'] = client
            session['role'] = 'gerance'
            return redirect(url_for('gerance_portal'))
        return render_template_string(HTML_LOGIN, error="Identifiants incorrects")
    return render_template_string(HTML_LOGIN)

@app.route('/gerance')
def gerance_portal():
    if session.get('role') != 'gerance': return redirect(url_for('login'))
    records = get_airtable_records(f"{{Client}} = '{session['user']}'")
    return render_template_string(HTML_PORTAL, title="Portail Gérance", records=records)

# --- 3. PAGE FULL ADMIN (Toi) ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if request.form.get('pwd') == ADMIN_PASSWORD:
            session['role'] = 'admin'
        else: return "Accès refusé"
    
    if session.get('role') != 'admin':
        return '<form method="post">Pass Admin: <input type="password" name="pwd"><button>OK</button></form>'
    
    records = get_airtable_records() # On prend TOUT
    return render_template_string(HTML_PORTAL, title="FULL ADMIN", records=records)

# --- API PIN ---
@app.route('/api/get_pin/<qr_id>')
def api_pin(qr_id):
    if not session.get('role'): return jsonify({"pin": "Non autorisé"})
    res = get_airtable_records(f"{{QRID}} = '{qr_id}'")
    pin = generate_igloo_pin(res[0]['fields'].get('LockID'))
    return jsonify({"pin": pin})

# --- TEMPLATES ---
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
            <option value="{{r['fields']['QRID']}}">{{r['fields']['Batiment']}} ({{r['fields']['Client']}})</option>
            {% endfor %}
        </select>
        <button onclick="getPin()" style="width:100%; padding:15px; background:#2563eb; color:white; border:none; border-radius:8px; font-weight:bold; cursor:pointer;">GÉNÉRER CODE</button>
        <div id="pin" style="font-size:50px; font-weight:bold; margin:20px 0; color:#1e293b;">----</div>
    </div>
    <script>
        function getPin(){
            const id = document.getElementById('sel').value;
            if(!id) return;
            document.getElementById('pin').innerText = "...";
            fetch('/api/get_pin/'+id).then(r=>r.json()).then(d=>{ document.getElementById('pin').innerText = d.pin; });
        }
    </script>
</body>
"""

HTML_TECH = """
<body style="font-family:sans-serif; background:#1e293b; color:white; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;">
    <div style="text-align:center; padding:20px;">
        <h2 style="color:#60a5fa;">ACCÈS TECHNIQUE</h2>
        <p>{{batiment}}</p>
        <div style="font-size:70px; font-weight:bold; background:white; color:#1e293b; padding:20px; border-radius:15px; margin:20px 0; letter-spacing:5px;">
            {{pin}}
        </div>
        <p style="font-size:12px; opacity:0.7;">Code valable 4 heures. Appuyez sur 'Unlocked' après avoir tapé le code.</p>
    </div>
</body>
"""

if __name__ == '__main__':
    app.run()

