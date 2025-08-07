import os
import json
import base64
from datetime import datetime
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ===== Variáveis de ambiente =====
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REFRESH_TOKEN_ENV = os.environ.get("REFRESH_TOKEN")  # fallback (apenas para primeiro seed)
API_KEY = os.environ.get("API_KEY")
PORT = int(os.environ.get("PORT", 5000))

TOKEN_FILE = "tokens.json"

# ===== Utilidades de arquivo =====
def _load_tokens():
    if os.path.isfile(TOKEN_FILE) and os.path.getsize(TOKEN_FILE) > 0:
        try:
            with open(TOKEN_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print("Falha lendo tokens.json:", e)
            return None
    return None

def _save_tokens(access_token, refresh_token, updated_at=None):
    data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        # ignoramos expires_in do provedor e controlamos por janela fixa
        "updated_at": (updated_at or datetime.now()).isoformat()
    }
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("Falha salvando tokens.json:", e)
    return data

# ===== Controle de expiração fixa (4 horas) =====
FOUR_HOURS_SECONDS = 4 * 60 * 60  # 14400s

def _expired_by_4h(data):
    """Força refresh a cada 4 horas (renova com margem de 60s)."""
    try:
        updated_at = datetime.fromisoformat(data["updated_at"])
    except Exception:
        return True
    delta = (datetime.now() - updated_at).total_seconds()
    return delta > (FOUR_HOURS_SECONDS - 60)

# ===== Chamada ao Bling para refresh =====
def _refresh_with(refresh_token):
    """
    Faz refresh no Bling usando refresh_token atual.
    Retorna dict { access_token, refresh_token } ou None em caso de falha.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        print("ENV faltando:", {"CLIENT_ID": CLIENT_ID, "CLIENT_SECRET": "****" if CLIENT_SECRET else None})
        return None

    try:
        encoded = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        url = "https://www.bling.com.br/Api/v3/oauth/token"
        headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
        resp = requests.post(url, headers=headers, data=payload, timeout=20)

        if resp.status_code != 200:
            print("Refresh falhou:", resp.status_code, resp.text[:600])
            return None

        j = resp.json()
        return {
            "access_token": j.get("access_token"),
            # alguns provedores podem ou não rotacionar o refresh_token:
            "refresh_token": j.get("refresh_token") or refresh_token
        }

    except Exception as e:
        print("Exceção no refresh:", type(e).__name__, e)
        return None

# ===== Lógica principal para obter token válido =====
def get_bling_token():
    # sanity check de envs essenciais
    missing = [k for k, v in {"CLIENT_ID": CLIENT_ID, "CLIENT_SECRET": CLIENT_SECRET, "API_KEY": API_KEY}.items() if not v]
    if missing:
        raise RuntimeError(f"Server misconfigured: missing {missing}")

    # 1) tenta carregar do arquivo local (últimos tokens)
    data = _load_tokens()

    # 2) se não existe, faz seed com REFRESH_TOKEN do ambiente
    if not data:
        if not REFRESH_TOKEN_ENV:
            raise RuntimeError("tokens.json ausente e REFRESH_TOKEN não definido no ambiente.")
        r = _refresh_with(REFRESH_TOKEN_ENV)
        if not r or not r.get("access_token"):
            raise RuntimeError("Falha no refresh inicial com REFRESH_TOKEN (env).")
        data = _save_tokens(r["access_token"], r["refresh_token"])
        return data["access_token"]

    # 3) se passou 4h desde a última atualização, renova
    if _expired_by_4h(data):
        r = _refresh_with(data["refresh_token"])
        if not r or not r.get("access_token"):
            raise RuntimeError("Falha ao renovar token com refresh_token do arquivo.")
        data = _save_tokens(r["access_token"], r["refresh_token"])
        return data["access_token"]

    # 4) ainda dentro da janela de 4h: usa token atual
    return data["access_token"]

# ===== Rotas =====
@app.route("/api/token_bling", methods=["GET"])
def api_token_bling():
    # Autenticação do endpoint por API_KEY em header Authorization: Bearer <API_KEY>
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized: missing bearer"}), 401
    if auth.split(" ", 1)[1] != API_KEY:
        return jsonify({"error": "Unauthorized: bad key"}), 401

    try:
        token = get_bling_token()
        return jsonify({"token": token})
    except Exception as e:
        print("Erro api_token_bling:", e)
        # 502 indica erro ao falar com serviço upstream (Bling) ou falta de configuração
        return jsonify({"error": "Token refresh failed"}), 502

@app.route("/", methods=["GET"])
def home():
    return "API de Token Bling Online!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
