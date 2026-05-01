import socket
import time
import random
import sys
import json

sensor_id = sys.argv[1] if len(sys.argv) > 1 else "sensor"

C2_HOST = "172.30.0.100"
C2_PORT = 8080

while True:
    payload = {
        "sensor": sensor_id,
        "temperature": round(random.uniform(20, 35), 2),
        "humidity": round(random.uniform(40, 80), 2),
        "timestamp": time.time()
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((C2_HOST, C2_PORT))
        s.send(json.dumps(payload).encode())
        s.close()
    except Exception:
        pass

    time.sleep(random.randint(2, 5))