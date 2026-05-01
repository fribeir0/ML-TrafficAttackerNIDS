"""
extract_features.py
--------------------
Pipeline completo: pcap → features de fluxo → correlação com attack_log → CSV rotulado.

Uso:
    python extract_features.py \
        --pcap   dataset/pcaps/session01.pcap \
        --labels dataset/labels/attack_log.jsonl \
        --out    dataset/csv/session01_labeled.csv

Dependências:
    pip install pandas pyshark tqdm

O script funciona em duas etapas:
  1. Extrai pacotes do pcap via tshark e agrega em fluxos bidirecionais
     (5-tupla: src_ip, dst_ip, src_port, dst_port, proto)
  2. Para cada fluxo, determina o label consultando o attack_log.jsonl:
     - Se o fluxo está dentro do intervalo [start_ts, end_ts] de um ataque → label = nome do ataque
     - Caso contrário → label = "benign"
"""

import argparse
import json
import subprocess
import sys
import os
from collections import defaultdict

import pandas as pd
import numpy as np
from tqdm import tqdm


# ── Constantes ──────────────────────────────────────────────────────────────────

# Campos extraídos via tshark — cada linha do pcap vira um dict com essas chaves
TSHARK_FIELDS = [
    "frame.time_epoch",       # timestamp Unix float
    "ip.src",
    "ip.dst",
    "ip.proto",               # 6=TCP, 17=UDP, 1=ICMP
    "ip.ttl",
    "ip.len",                 # tamanho total do pacote IP
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",              # hex: 0x002=SYN, 0x010=ACK, 0x004=RST, etc.
    "tcp.window_size_value",
    "tcp.len",                # payload TCP
    "udp.length",
    "frame.len",              # tamanho do frame Ethernet
]

TSHARK_SEP = "|"


# ── Extração de pacotes via tshark ───────────────────────────────────────────────

def extract_packets(pcap_path: str) -> list[dict]:
    """
    Chama tshark e retorna lista de dicts, um por pacote IP.
    Ignora pacotes não-IP (ARP, etc).
    """
    fields_args = []
    for f in TSHARK_FIELDS:
        fields_args += ["-e", f]

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", f"separator={TSHARK_SEP}",
        "-E", "occurrence=f",   # pega só o primeiro valor de cada campo
        "-E", "quote=n",
    ] + fields_args

    print(f"[*] Executando tshark em {pcap_path} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[ERRO] tshark não encontrado. Instale com: apt install tshark")
        sys.exit(1)

    packets = []
    for line in result.stdout.splitlines():
        parts = line.split(TSHARK_SEP)
        if len(parts) != len(TSHARK_FIELDS):
            continue
        pkt = dict(zip(TSHARK_FIELDS, parts))

        # Ignora linhas sem IP src/dst (ARP, etc)
        if not pkt["ip.src"] or not pkt["ip.dst"]:
            continue

        # Normaliza tipos
        try:
            pkt["frame.time_epoch"] = float(pkt["frame.time_epoch"])
        except ValueError:
            continue

        for int_field in ["ip.proto", "ip.ttl", "ip.len", "tcp.window_size_value",
                          "tcp.len", "udp.length", "frame.len"]:
            try:
                pkt[int_field] = int(pkt[int_field]) if pkt[int_field] else 0
            except ValueError:
                pkt[int_field] = 0

        # Porta src/dst unificada (TCP ou UDP)
        pkt["src_port"] = int(pkt["tcp.srcport"] or pkt["udp.srcport"] or 0)
        pkt["dst_port"] = int(pkt["tcp.dstport"] or pkt["udp.dstport"] or 0)

        # Flags TCP como inteiro
        try:
            pkt["tcp_flags_int"] = int(pkt["tcp.flags"], 16) if pkt["tcp.flags"] else 0
        except ValueError:
            pkt["tcp_flags_int"] = 0

        packets.append(pkt)

    print(f"[*] {len(packets)} pacotes IP extraídos.")
    return packets


# ── Agregação em fluxos ──────────────────────────────────────────────────────────

def flow_key(pkt: dict) -> tuple:
    """
    Chave bidirecional de fluxo (5-tupla ordenada).
    Pacotes A→B e B→A pertencem ao mesmo fluxo.
    """
    src = (pkt["ip.src"], pkt["src_port"])
    dst = (pkt["ip.dst"], pkt["dst_port"])
    proto = pkt["ip.proto"]
    if src < dst:
        return (src[0], dst[0], src[1], dst[1], proto)
    else:
        return (dst[0], src[0], dst[1], src[1], proto)


def aggregate_flows(packets: list[dict]) -> list[dict]:
    """
    Agrega pacotes em fluxos e computa features estatísticas por fluxo.
    Retorna lista de dicts — um por fluxo.
    """
    flows = defaultdict(list)
    for pkt in packets:
        flows[flow_key(pkt)].append(pkt)

    print(f"[*] {len(flows)} fluxos únicos encontrados.")
    rows = []

    for key, pkts in tqdm(flows.items(), desc="Computando features"):
        pkts_sorted = sorted(pkts, key=lambda p: p["frame.time_epoch"])

        ts      = [p["frame.time_epoch"] for p in pkts_sorted]
        lengths = [p["frame.len"] for p in pkts_sorted]
        iats    = [ts[i+1] - ts[i] for i in range(len(ts)-1)]  # inter-arrival times
        flags   = [p["tcp_flags_int"] for p in pkts_sorted]
        ttls    = [p["ip.ttl"] for p in pkts_sorted if p["ip.ttl"] > 0]

        # Contagem de flags TCP individuais
        syn_count  = sum(1 for f in flags if f & 0x002)
        ack_count  = sum(1 for f in flags if f & 0x010)
        rst_count  = sum(1 for f in flags if f & 0x004)
        fin_count  = sum(1 for f in flags if f & 0x001)
        psh_count  = sum(1 for f in flags if f & 0x008)
        urg_count  = sum(1 for f in flags if f & 0x020)

        n = len(pkts_sorted)
        duration = ts[-1] - ts[0] if n > 1 else 0.0

        row = {
            # Identificação do fluxo
            "src_ip":           key[0],
            "dst_ip":           key[1],
            "src_port":         key[2],
            "dst_port":         key[3],
            "protocol":         key[4],   # 6=TCP, 17=UDP, 1=ICMP

            # Temporais
            "flow_start_ts":    ts[0],
            "flow_end_ts":      ts[-1],
            "duration_s":       round(duration, 6),

            # Volume
            "pkt_count":        n,
            "byte_count":       sum(lengths),
            "pkt_per_sec":      round(n / duration, 4) if duration > 0 else 0,
            "byte_per_sec":     round(sum(lengths) / duration, 4) if duration > 0 else 0,

            # Tamanho de pacote
            "pkt_len_mean":     round(np.mean(lengths), 4),
            "pkt_len_std":      round(np.std(lengths), 4),
            "pkt_len_min":      min(lengths),
            "pkt_len_max":      max(lengths),

            # Inter-arrival time
            "iat_mean":         round(np.mean(iats), 6) if iats else 0,
            "iat_std":          round(np.std(iats), 6) if iats else 0,
            "iat_min":          round(min(iats), 6) if iats else 0,
            "iat_max":          round(max(iats), 6) if iats else 0,

            # Flags TCP
            "syn_count":        syn_count,
            "ack_count":        ack_count,
            "rst_count":        rst_count,
            "fin_count":        fin_count,
            "psh_count":        psh_count,
            "urg_count":        urg_count,
            "syn_ratio":        round(syn_count / n, 4),
            "rst_ratio":        round(rst_count / n, 4),

            # TTL
            "ttl_mean":         round(np.mean(ttls), 2) if ttls else 0,
            "ttl_std":          round(np.std(ttls), 2) if ttls else 0,

            # TCP window
            "win_mean":         round(np.mean([p["tcp.window_size_value"] for p in pkts_sorted]), 2),

            # Flags de padrão de ataque
            "only_syn":         int(syn_count == n),          # SYN flood / scan
            "syn_no_ack":       int(syn_count > 0 and ack_count == 0),
            "has_rst":          int(rst_count > 0),
        }
        rows.append(row)

    return rows


# ── Correlação com attack_log ────────────────────────────────────────────────────

def load_attack_log(label_path: str) -> list[dict]:
    """Carrega o JSONL gerado pelo label_logger."""
    attacks = []
    if not os.path.exists(label_path):
        print(f"[AVISO] attack_log não encontrado em {label_path}. Todos os fluxos serão 'benign'.")
        return attacks
    with open(label_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attacks.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"[*] {len(attacks)} entradas no attack_log carregadas.")
    return attacks


def label_flow(flow_start: float, flow_end: float, attacks: list[dict]) -> str:
    """
    Retorna o label do ataque se o fluxo se sobrepõe com algum intervalo de ataque.
    Usa sobreposição temporal: fluxo e ataque se sobrepõem se não são completamente separados.
    Se múltiplos ataques se sobrepõem, retorna o de maior sobreposição.
    """
    best_label    = "benign"
    best_overlap  = 0.0

    for atk in attacks:
        atk_start = atk.get("start_ts", 0)
        atk_end   = atk.get("end_ts", 0)
        if not atk_end:
            continue

        # Calcula sobreposição
        overlap_start = max(flow_start, atk_start)
        overlap_end   = min(flow_end,   atk_end)
        overlap       = max(0.0, overlap_end - overlap_start)

        if overlap > best_overlap:
            best_overlap = overlap
            best_label   = atk["attack"]

    return best_label


def label_flows(flows: list[dict], attacks: list[dict]) -> list[dict]:
    """Adiciona coluna 'label' a cada fluxo."""
    print("[*] Correlacionando fluxos com attack_log ...")
    for flow in flows:
        flow["label"] = label_flow(
            flow["flow_start_ts"],
            flow["flow_end_ts"],
            attacks
        )

    # Resumo de distribuição de labels
    from collections import Counter
    dist = Counter(f["label"] for f in flows)
    print("\n[*] Distribuição de labels:")
    for label, count in sorted(dist.items(), key=lambda x: -x[1]):
        pct = 100 * count / len(flows)
        print(f"    {label:<30} {count:>6} fluxos  ({pct:.1f}%)")

    return flows


# ── Main ─────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="pcap + attack_log → CSV de features rotulado"
    )
    parser.add_argument("--pcap",   required=True,  help="Caminho do arquivo .pcap")
    parser.add_argument("--labels", required=True,  help="Caminho do attack_log.jsonl")
    parser.add_argument("--out",    required=True,  help="Caminho do CSV de saída")
    parser.add_argument("--min-pkts", type=int, default=2,
                        help="Descarta fluxos com menos de N pacotes (default: 2)")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    # 1. Extrai pacotes
    packets = extract_packets(args.pcap)
    if not packets:
        print("[ERRO] Nenhum pacote extraído. Verifique o pcap.")
        sys.exit(1)

    # 2. Agrega em fluxos
    flows = aggregate_flows(packets)

    # 3. Filtra fluxos muito pequenos (ruído)
    flows = [f for f in flows if f["pkt_count"] >= args.min_pkts]
    print(f"[*] {len(flows)} fluxos após filtro de mínimo {args.min_pkts} pacotes.")

    # 4. Carrega attack_log e rotula
    attacks = load_attack_log(args.labels)
    flows   = label_flows(flows, attacks)

    # 5. Salva CSV
    df = pd.DataFrame(flows)

    # Remove colunas de timestamp do flow (não são features, só foram usadas pra labeling)
    df = df.drop(columns=["flow_start_ts", "flow_end_ts"], errors="ignore")

    df.to_csv(args.out, index=False)
    print(f"\n[✓] CSV salvo em: {args.out}")
    print(f"    Shape: {df.shape[0]} linhas × {df.shape[1]} colunas")
    print(f"\n    Colunas:\n    {list(df.columns)}")


if __name__ == "__main__":
    main()
