import os
import requests
import base64
import json
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REFRESH_TOKEN = os.environ.get("REFRESH_TOKEN")
API_KEY = os.environ.get("API_KEY")
TOKEN_FILE = "tokens.json"  # Opcional: pode usar só memória se preferir

def refresh_tokens(client_id, client_secret, refresh_token):
    encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    url = "https://www.bling.com.br/Api/v3/oauth/token"
    headers = {"Authorization": f"Basic {encoded}",
               "Content-Type": "application/x-www-form-urlencoded"}
    payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=15)
        if resp.status_code != 200:
            # LOG detalhado pra aparecer no Render
            print("Refresh falhou:", resp.status_code, resp.text)
            return None
        data = resp.json()
        return {
            "access_token": data.get("access_token"),
            "refresh_token": data.get("refresh_token"),
            "expires_in": data.get("expires_in"),
        }
    except Exception as e:
        print("Exceção no refresh:", type(e).__name__, e)
        return None

@app.route("/api/token_bling", methods=["GET"])
def api_token_bling():
    # Auth do endpoint
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized: missing bearer"}), 401
    if auth.split(" ", 1)[1] != API_KEY:
        return jsonify({"error": "Unauthorized: bad key"}), 401

    # Sanity check de envs
    missing = [n for n,v in {
        "CLIENT_ID": CLIENT_ID, "CLIENT_SECRET": CLIENT_SECRET,
        "REFRESH_TOKEN": REFRESH_TOKEN
    }.items() if not v]
    if missing:
        print("ENV faltando:", missing)
        return jsonify({"error": f"Server misconfigured: missing {missing}"}), 500

    result = refresh_tokens(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)
    if not result or not result.get("access_token"):
        return jsonify({"error": "Refresh failed; check logs"}), 502  # 502 ajuda a diferenciar
    # (Opcional) salvar em arquivo/log
    try:
        with open("tokens.json","w") as f:
            json.dump({**result, "updated_at": datetime.now().isoformat()}, f, indent=2)
    except Exception as e:
        print("Falha salvando tokens.json:", e)

    return jsonify({"token": result["access_token"]})

@app.route("/", methods=["GET"])
def home():
    return "API de Token Bling Online!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
