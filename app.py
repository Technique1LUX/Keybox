import os
from flask import Flask, render_template_string
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURATION VIA VARIABLES D'ENVIRONNEMENT ---
# Render ira chercher ces valeurs dans ses réglages "Environment"
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = "Table 1"

IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")

def get_lock_info(qr_id):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    params = {"filterByFormula": f"{{Identifiant QR}} = '{qr_id}'"}
    
    try:
        res = requests.get(url, headers=headers, params=params)
        records = res.json().get('records', [])
        return records[0]['fields'] if records else None
    except:
        return None

def get_igloo_pin(lock_id):
    try:
        # Auth
        auth_res = requests.post(
            "https://auth.igloohome.co/oauth2/token",
            auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET),
            data={"grant_type": "client_credentials"}
        )
        token = auth_res.json().get('access_token')

        # Génération du PIN (Format ISO 8601 conforme à la doc d'Ann)
        now = datetime.utcnow()
        end = now + timedelta(hours=4)
        
        payload = {
            "name": "Acces_Technicien",
            "type": "duration",
            "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "endDate": end.strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        url = f"https://api.igloohome.co/v2/locks/{lock_id}/pins"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        res = requests.post(url, json=payload, headers=headers)
        return res.json().get('pin')
    except:
        return None

@app.route('/access/<qr_id>')
def access_page(qr_id):
    lock_info = get_lock_info(qr_id)
    if not lock_info:
        return "<h1>Erreur : QR Code non répertorié</h1>", 404
        
    batiment = lock_info.get('Nom du batiment', 'Bâtiment Inconnu')
    lock_id = lock_info.get('LOCK_ID')
    
    pin = get_igloo_pin(lock_id)
    
    # Design simple pour smartphone
    return render_template_string(f"""
    <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: sans-serif; text-align: center; padding-top: 50px; background: #f8f9fa; }}
                .card {{ background: white; margin: auto; width: 80%; padding: 20px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
                .pin {{ font-size: 48px; color: #2ecc71; font-weight: bold; margin: 20px 0; letter-spacing: 5px; }}
                .btn {{ background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>{batiment}</h2>
                <p>Code d'accès technicien :</p>
                <div class="pin">{pin if pin else "SERVICE INDISPONIBLE"}</div>
                <p>Valable 4 heures</p>
            </div>
        </body>
    </html>
    """, pin=pin)

if __name__ == '__main__':
    app.run()
