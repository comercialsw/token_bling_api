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
    encoded_credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    api_url = "https://www.bling.com.br/Api/v3/oauth/token"
    headers = {
        "Authorization": "Basic " + encoded_credentials,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
    response = requests.post(api_url, headers=headers, data=payload)

    if response.status_code == 200:
        data = response.json()
        access_token = data.get("access_token")
        expires_in = data.get("expires_in")
        updated_at = datetime.now()
        # Salvar/atualizar o arquivo de tokens, se desejar (ou pode só retornar)
        token_data = {
            "access_token": access_token,
            "refresh_token": data.get("refresh_token"),
            "expires_in": expires_in,
            "updated_at": updated_at.isoformat()
        }
        with open(TOKEN_FILE, "w") as f:
            json.dump(token_data, f, indent=4)
        return access_token
    else:
        print("Erro ao atualizar tokens:", response.status_code, response.text)
        return None

def get_bling_token():
    # Sempre faz refresh ao receber chamada (ou pode adicionar lógica de checagem de expiração)
    access_token = refresh_tokens(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)
    if not access_token:
        raise Exception("Não foi possível atualizar o token.")
    return access_token

@app.route("/api/token_bling", methods=["GET"])
def api_token_bling():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    api_key = auth_header.split(" ")[1]
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        access_token = get_bling_token()
        return jsonify({"token": access_token})
    except Exception as e:
        print("Erro ao buscar token:", e)
        return jsonify({"error": "Erro ao obter token"}), 500

@app.route("/", methods=["GET"])
def home():
    return "API de Token Bling Online!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
