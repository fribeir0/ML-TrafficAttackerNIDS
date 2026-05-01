import socket
import time
import random
import sys
import json

sensor_id = sys.argv[1] if len(sys.argv) > 1 else "sensor"

SERVER_HOST = "172.30.0.100"
SERVER_PORT = 8080

def generate_payload():
    return {
        "sensor": sensor_id,
        "temperature": round(random.uniform(20, 30), 2),
        "humidity": round(random.uniform(40, 70), 2),
        "timestamp": int(time.time())
    }

def send_data(payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((SERVER_HOST, SERVER_PORT))

        # formato HTTP simples (mais realista que raw socket)
        body = json.dumps(payload)
        request = (
            "POST /data HTTP/1.1\r\n"
            f"Host: {SERVER_HOST}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
            f"{body}"
        )

        s.send(request.encode())
        s.close()
    except Exception:
        pass


while True:
    payload = generate_payload()
    send_data(payload)

    # intervalo típico de sensor (estável, com leve jitter)
    time.sleep(5 + random.uniform(-1, 1))