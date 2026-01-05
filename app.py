from flask import Flask, render_template_string, request
import requests
import time
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURATION (À REMPLIR) ---
AIRTABLE_API_KEY = "TA_CLE_API_AIRTABLE"
AIRTABLE_BASE_ID = "TON_BASE_ID"
AIRTABLE_TABLE_NAME = "Table 1"

IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = "daaefy6m1ml1mc08jkhnpuwbryrpbb2xsqkgyflif4dha8tapem"

# --- LOGIQUE DE RÉCUPÉRATION AIRTABLE ---
def get_lock_info(qr_id):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    params = {"filterByFormula": f"{{Identifiant QR}} = '{qr_id}'"}
    
    res = requests.get(url, headers=headers, params=params)
    records = res.json().get('records', [])
    if records:
        return records[0]['fields'] # Retourne Nom, LOCK_ID, etc.
    return None

# --- LOGIQUE IGLOOHOME (VERSION STOPLIGHT) ---
def get_igloo_pin(lock_id):
    # 1. Auth
    auth_res = requests.post(
        "https://auth.igloohome.co/oauth2/token",
        auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET),
        data={"grant_type": "client_credentials"}
    )
    token = auth_res.json().get('access_token')

    # 2. Pin (Format ISO 8601 pour 4 heures d'accès)
    now = datetime.utcnow()
    end = now + timedelta(hours=4)
    
    payload = {
        "name": "Acces_Technicien_MVP",
        "type": "duration",
        "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "endDate": end.strftime('%Y-%m-%dT%H:%M:%SZ')
    }
    
    url = f"https://api.igloohome.co/v2/locks/{lock_id}/pins"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    res = requests.post(url, json=payload, headers=headers)
    return res.json().get('pin')

# --- ROUTE WEB POUR LE TECHNICIEN ---
@app.route('/access/<qr_id>')
def access_page(qr_id):
    lock_info = get_lock_info(qr_id)
    
    if not lock_info:
        return "<h1>Erreur : Bâtiment inconnu</h1>", 404
        
    batiment_nom = lock_info.get('Nom du batiment')
    lock_id = lock_info.get('LOCK_ID')
    
    # Génération réelle du PIN
    pin = get_igloo_pin(lock_id)
    
    # HTML simple affiché sur le téléphone
    html_template = f"""
    <html>
        <head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
        <body style="text-align:center; font-family:sans-serif; padding:50px;">
            <h2>{batiment_nom}</h2>
            <p>Votre code d'accès temporaire :</p>
            <div style="font-size:40px; font-weight:bold; color:#2ecc71; margin:20px;">{pin if pin else 'Erreur API'}</div>
            <p style="color:#666;">Valable 4 heures</p>
        </body>
    </html>
    """
    return render_template_string(html_template)

if __name__ == '__main__':
    app.run(debug=True)