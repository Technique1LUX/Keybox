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
    Si Airtable a un champ 'VarianceHourly', on l'utilise et on tour
