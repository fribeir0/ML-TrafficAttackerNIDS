"""
fake_http.py
------------
Servidor HTTP falso na porta 80 simulando dispositivo IoT/embedded.
Tem rotas reais (login, api, status, config) para que gobuster e nikto
encontrem endpoints e gerem tráfego variado e interessante para o dataset.

Retorna respostas plausíveis — login rejeita credenciais, /api retorna JSON,
/config retorna 403. Isso gera padrões de resposta variados no pcap.
"""

from flask import Flask, request, jsonify, Response
import logging
import os
import time

PORT = 80
LOG  = "/app/logs/http_requests.log"

os.makedirs(os.path.dirname(LOG), exist_ok=True)
logging.basicConfig(level=logging.WARNING)  # silencia Flask verbose

app = Flask(__name__)
app.logger.setLevel(logging.WARNING)

# Suprime logs do Werkzeug para não poluir o terminal
import logging as _log
_log.getLogger("werkzeug").setLevel(_log.ERROR)


def _log_request(extra=""):
    with open(LOG, "a") as f:
        f.write(f"{time.time()} {request.method} {request.path} "
                f"src={request.remote_addr} {extra}\n")


# ── Rotas ────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    _log_request()
    return Response(
        "<html><head><title>IoT Device</title></head>"
        "<body><h1>IoT Sensor Dashboard</h1>"
        "<p><a href='/login'>Login</a></p></body></html>",
        mimetype="text/html"
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw   = request.form.get("password", "")
        _log_request(f"user={user!r} pass={pw!r}")
        time.sleep(0.2)  # delay realista de autenticação
        return Response(
            '{"status":"error","message":"Invalid credentials"}',
            status=401, mimetype="application/json"
        )
    _log_request()
    return Response(
        "<html><body><form method='POST'>"
        "User: <input name='username'><br>"
        "Pass: <input name='password' type='password'><br>"
        "<input type='submit' value='Login'></form></body></html>",
        mimetype="text/html"
    )


@app.route("/api/status")
def api_status():
    _log_request()
    return jsonify({
        "device": "sensor-node",
        "firmware": "1.4.2",
        "uptime": 84723,
        "temp_c": round(23.4 + (time.time() % 5), 1),
        "status": "online"
    })


@app.route("/api/v1/data")
def api_data():
    _log_request()
    return jsonify({"readings": [1.2, 3.4, 5.6], "unit": "celsius"})


@app.route("/config")
def config():
    _log_request()
    # 403 — existe mas não é acessível sem auth
    return Response("Forbidden", status=403)


@app.route("/backup")
def backup():
    _log_request()
    return Response("Not Found", status=404)


@app.route("/admin")
def admin():
    _log_request()
    return Response(
        '{"error":"Authentication required"}',
        status=401, mimetype="application/json"
    )


@app.route("/health")
def health():
    _log_request()
    return jsonify({"status": "ok"})


# Catch-all para rotas que gobuster/nikto tentam e não existem
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(path):
    _log_request()
    return Response("Not Found", status=404)


if __name__ == "__main__":
    print(f"[HTTP] Fake HTTP escutando em 0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
