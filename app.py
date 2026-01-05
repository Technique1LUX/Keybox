import os
import requests
import urllib3
from flask import Flask, render_template_string
from datetime import datetime, timedelta

# On ignore les erreurs de certificat SSL d'Igloohome
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Config
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = "Table 1"
IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")

def get_lock_info(qr_id):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    params = {"filterByFormula": f"{{QRID}} = '{qr_id}'"}
    try:
        res = requests.get(url, headers=headers, params=params)
        records = res.json().get('records', [])
        if records:
            print(f"DEBUG: Airtable a trouvé {qr_id}")
            return records[0]['fields']
        return None
    except Exception as e:
        print(f"DEBUG ERROR Airtable: {e}")
        return None

def get_igloo_pin(lock_id):
    print(f"DEBUG: Tentative PIN pour la serrure {lock_id}")
    try:
        # 1. AUTH
        auth_url = "https://auth.igloohome.co/oauth2/token"
        auth_res = requests.post(
            auth_url,
            auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            verify=False,
            timeout=10
        )
        print(f"DEBUG: Auth Igloo Status = {auth_res.status_code}")
        token = auth_res.json().get('access_token')
        
        if not token:
            print("DEBUG: Pas de token reçu d'Igloo")
            return "ERREUR_AUTH"

        # 2. PIN (On met des dates fixes simples pour tester)
        now = datetime.utcnow() + timedelta(minutes=5)
        end = now + timedelta(hours=3)
        
        payload = {
            "name": "Visiteur",
            "type": "duration",
            "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "endDate": end.strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        res_pin = requests.post(
            f"https://api.igloohome.co/v2/locks/{lock_id}/pins",
            json=payload,
            headers=headers,
            verify=False,
            timeout=10
        )
        
        print(f"DEBUG: Réponse PIN Igloo = {res_pin.status_code}")
        print(f"DEBUG: Contenu PIN = {res_pin.text}")
        
        return res_pin.json().get('pin')
    except Exception as e:
        print(f"DEBUG ERROR IGLOO: {e}")
        return None

@app.route('/access/<qr_id>')
def access_page(qr_id):
    lock_info = get_lock_info(qr_id)
    if not lock_info:
        return "ID inconnu dans Airtable", 404
        
    batiment = lock_info.get('Batiment', 'Bâtiment')
    lock_id = lock_info.get('LockID')
    
    # APPEL IGLOO
    pin = get_igloo_pin(lock_id)
    
    return render_template_string("""
        <body style="text-align:center; font-family:sans-serif; padding-top:100px; background:#f4f4f4;">
            <div style="background:white; display:inline-block; padding:40px; border-radius:20px; box-shadow:0 4px 10px rgba(0,0,0,0.1);">
                <h1 style="color:#333;">{{batiment}}</h1>
                <p style="color:#666;">Code d'accès temporaire :</p>
                <div style="font-size:50px; font-weight:bold; color:#1a73e8; letter-spacing:5px; margin:20px 0;">
                    {{pin if pin else "---"}}
                </div>
                {% if not pin or pin == "---" %}
                    <p style="color:red;">Erreur de connexion avec la serrure.</p>
                {% endif %}
                <p style="font-size:12px; color:#999;">ID: {{lock_id}}</p>
            </div>
        </body>
    """, batiment=batiment, pin=pin, lock_id=lock_id)

if __name__ == '__main__':
    app.run()
