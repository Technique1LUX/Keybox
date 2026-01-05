import os
import requests
import urllib3
from flask import Flask, render_template_string
from datetime import datetime, timedelta

# Désactive les avertissements SSL dans les logs (puisque le certificat d'Igloohome est expiré)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configuration via les variables d'environnement Render
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = "Table 1"
IGLOO_CLIENT_ID = "xprluqseolemaoc3l3hu9d2zlt"
IGLOO_CLIENT_SECRET = os.getenv("IGLOO_CLIENT_SECRET")

def get_lock_info(qr_id):
    url = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}
    # Recherche dans la colonne QRID
    params = {"filterByFormula": f"{{QRID}} = '{qr_id}'"}
    try:
        res = requests.get(url, headers=headers, params=params)
        records = res.json().get('records', [])
        return records[0]['fields'] if records else None
    except:
        return None

def get_igloo_pin(lock_id):
    try:
        # 1. Authentification (OAuth2) - On force verify=False à cause du bug SSL d'Igloo
        auth_url = "https://auth.igloohome.co/oauth2/token"
        auth_res = requests.post(
            auth_url,
            auth=(IGLOO_CLIENT_ID, IGLOO_CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            verify=False
        )
        token = auth_res.json().get('access_token')
        
        if not token:
            return None

        # 2. Création du PIN (Valide 4 heures)
        now = datetime.utcnow()
        end = now + timedelta(hours=4)
        payload = {
            "name": "Acces_Technicien",
            "type": "duration",
            "startDate": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "endDate": end.strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        res = requests.post(
            f"https://api.igloohome.co/v2/locks/{lock_id}/pins", 
            json=payload, 
            headers=headers,
            verify=False
        )
        return res.json().get('pin')
    except Exception as e:
        print(f"Erreur Igloo: {e}")
        return None

@app.route('/access/<qr_id>')
def access_page(qr_id):
    lock_info = get_lock_info(qr_id)
    if not lock_info:
        return f"<div style='text-align:center;padding:50px;'><h1>QR Code '{qr_id}' inconnu</h1><p>Veuillez contacter l'administrateur.</p></div>", 404
        
    batiment = lock_info.get('Batiment', 'Bâtiment Partenaire')
    lock_id = lock_info.get('LockID')
    pin = get_igloo_pin(lock_id)
    
    # Heure d'expiration pour l'affichage (Heure locale estimée)
    expire_time = (datetime.now() + timedelta(hours=4)).strftime('%H:%M')

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Accès KeyBox</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f9; margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
            .container { background: white; padding: 40px; border-radius: 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); text-align: center; width: 90%; max-width: 400px; border: 1px solid #e1e8ed; }
            .header { margin-bottom: 30px; }
            .logo { font-size: 28px; font-weight: 800; color: #1a73e8; letter-spacing: -1px; }
            .location { color: #5f6368; font-size: 16px; margin-top: 5px; font-weight: 500; }
            .pin-container { background: #f8f9fa; border: 2px solid #e8eaed; border-radius: 16px; padding: 25px; margin: 25px 0; position: relative; }
            .pin-label { font-size: 12px; text-transform: uppercase; color: #70757a; letter-spacing: 1px; margin-bottom: 10px; }
            .pin-value { font-size: 48px; font-weight: bold; color: #202124; letter-spacing: 5px; }
            .status { font-size: 13px; margin-top: 10px; color: #d93025; font-weight: 600; }
            .instructions { font-size: 14px; color: #3c4043; line-height: 1.5; }
            .footer { margin-top: 30px; font-size: 11px; color: #9aa0a6; }
            .btn-copy { background: #1a73e8; color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">NANAS ACCESS</div>
                <div class="location">📍 {{batiment}}</div>
            </div>
            
            <div class="pin-container">
                <div class="pin-label">Votre Code PIN</div>
                <div class="pin-value">{{pin if pin else "---"}}</div>
                {% if pin %}
                <div class="status">Valide jusqu'à {{expire}}</div>
                {% else %}
                <div class="status" style="color:orange;">Génération en cours ou Erreur serveur</div>
                {% endif %}
            </div>

            <div class="instructions">
                Tapez le code sur le boîtier,<br>puis validez avec la touche <strong>UNLOCKED</strong>.
            </div>

            <div class="footer">
                ID Serrure : {{lock_id}}<br>
                &copy; 2026 Nanas Lab Security
            </div>
        </div>
    </body>
    </html>
    """, batiment=batiment, pin=pin, expire=expire_time, lock_id=lock_id)

if __name__ == '__main__':
    app.run()
