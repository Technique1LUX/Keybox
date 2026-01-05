from flask import Flask, render_template_string, request, session, jsonify
import os, requests, urllib3
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
app.secret_key = "cle_secrete_nanas_2026"

# Config
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = "Table 1"
IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")

def get_airtable_records(filter_formula):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    params = {"filterByFormula": filter_formula}
    res = requests.get(url, headers=headers, params=params)
    return res.json().get('records', [])

@app.route('/portal/<client_name>', methods=['GET', 'POST'])
def portal(client_name):
    # 1. Récupérer les infos du client
    records = get_airtable_records(f"{{Client}} = '{client_name}'")
    if not records: return "Client inconnu", 404
    
    # 2. Gérer la connexion
    expected_pwd = records[0]['fields'].get('Password')
    if request.method == 'POST' and 'pwd' in request.form:
        if request.form.get('pwd') == expected_pwd:
            session[f'auth_{client_name}'] = True
        else:
            return render_template_string(HTML_LAYOUT, content=HTML_LOGIN, client=client_name, error="Mauvais mot de passe")

    if not session.get(f'auth_{client_name}'):
        return render_template_string(HTML_LAYOUT, content=HTML_LOGIN, client=client_name)

    # 3. Afficher le menu déroulant
    return render_template_string(HTML_LAYOUT, content=HTML_SELECTOR, client=client_name, records=records)

# Route API pour générer le PIN sans recharger la page
@app.route('/get_pin/<qr_id>')
def api_get_pin(qr_id):
    # On vérifie d'abord l'ID dans Airtable pour avoir le LockID
    res = get_airtable_records(f"{{QRID}} = '{qr_id}'")
    if not res: return jsonify({"pin": "Erreur ID"})
    
    lock_id = res[0]['fields'].get('LockID')
    
    # Appel Igloohome (On réutilise ta logique avec verify=False)
    try:
        auth = requests.post("https://auth.igloohome.co/oauth2/token",
                             auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET),
                             data={"grant_type": "client_credentials"}, verify=False).json()
        token = auth.get('access_token')
        
        now = datetime.utcnow() + timedelta(minutes=2)
        payload = {"name": "Portal_Access", "type": "duration",
                   "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                   "endDate": (now + timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        
        pin_res = requests.post(f"https://api.igloohome.co/v2/locks/{lock_id}/pins", 
                                json=payload, headers={"Authorization": f"Bearer {token}"}, verify=False).json()
        return jsonify({"pin": pin_res.get('pin', "Erreur Serveur")})
    except:
        return jsonify({"pin": "Indisponible"})

# --- DESIGN ---

HTML_LAYOUT = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: sans-serif; background: #f4f7f6; display: flex; justify-content: center; padding-top: 50px; }
        .card { background: white; width: 90%; max-width: 400px; padding: 30px; border-radius: 20px; box-shadow: 0 10px 20px rgba(0,0,0,0.05); text-align: center; }
        select, input { width: 100%; padding: 12px; margin: 10px 0; border-radius: 8px; border: 1px solid #ddd; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; padding: 12px; border-radius: 8px; border: none; background: #1a73e8; color: white; font-weight: bold; cursor: pointer; }
        #pin_display { font-size: 40px; font-weight: bold; color: #1a73e8; margin-top: 20px; letter-spacing: 4px; }
    </style>
</head>
<body>
    <div class="card">
        <h2 style="color:#333;">NANAS PORTAL</h2>
        {{content | safe}}
    </div>
</body>
</html>
"""

HTML_LOGIN = """
<p>Client : <strong>{{client}}</strong></p>
<form method="post">
    <input type="password" name="pwd" placeholder="Mot de passe" required>
    <button type="submit">Se connecter</button>
</form>
{% if error %}<p style="color:red;">{{error}}</p>{% endif %}
"""

HTML_SELECTOR = """
<p>Bienvenue, <strong>{{client}}</strong></p>
<label>Sélectionnez un bâtiment :</label>
<select id="lock_select">
    <option value="">-- Choisir --</option>
    {% for r in records %}
    <option value="{{r['fields']['QRID']}}">{{r['fields']['Batiment']}}</option>
    {% endfor %}
</select>
<button onclick="generatePIN()">Générer le code</button>
<div id="pin_display">----</div>
<p id="status" style="font-size:12px; color:#666;"></p>

<script>
function generatePIN() {
    var qrid = document.getElementById('lock_select').value;
    if(!qrid) return alert('Sélectionnez un bâtiment');
    
    document.getElementById('pin_display').innerText = "....";
    document.getElementById('status').innerText = "Connexion à la serrure...";
    
    fetch('/get_pin/' + qrid)
        .then(response => response.json())
        .then(data => {
            document.getElementById('pin_display').innerText = data.pin;
            document.getElementById('status').innerText = "Code valable 4 heures";
        });
}
</script>
"""

if __name__ == '__main__':
    app.run()
