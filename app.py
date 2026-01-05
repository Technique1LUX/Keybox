import os
import requests
from flask import Flask, render_template_string
from datetime import datetime, timedelta

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
    # On cherche dans la colonne QRID
    params = {"filterByFormula": f"{{QRID}} = '{qr_id}'"}
    
    print(f"DEBUG: Appel Airtable pour ID: {qr_id}")
    try:
        res = requests.get(url, headers=headers, params=params)
        print(f"DEBUG: Status Airtable: {res.status_code}")
        data = res.json()
        records = data.get('records', [])
        if records:
            print(f"DEBUG: Record trouvé: {records[0]['fields']}")
            return records[0]['fields']
        print("DEBUG: Aucun record correspondant trouvé.")
        return None
    except Exception as e:
        print(f"DEBUG: Erreur Airtable: {e}")
        return None

@app.route('/access/<qr_id>')
def access_page(qr_id):
    lock_info = get_lock_info(qr_id)
    if not lock_info:
        return f"<h1>Erreur : QR Code '{qr_id}' non répertorié</h1>", 404
        
    # On utilise les nouveaux noms simplifiés
    batiment = lock_info.get('Batiment', 'Bâtiment Inconnu')
    lock_id = lock_info.get('LockID')
    
    # Pour l'instant on simule le PIN car Igloo est en 503
    pin = "503_ERROR" 
    
    return render_template_string(f"""
        <html>
            <body style="text-align:center;font-family:sans-serif;padding-top:50px;">
                <div style="border:1px solid #ccc; display:inline-block; padding:20px; border-radius:10px;">
                    <h2>{batiment}</h2>
                    <p>ID Serrure : {lock_id}</p>
                    <div style="font-size:30px; color:red;">En attente serveur Igloohome</div>
                </div>
            </body>
        </html>
    """)

if __name__ == '__main__':
    app.run()
