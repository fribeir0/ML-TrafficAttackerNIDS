"""
extract_features.py — Extrator de features expandido
Suporta todas as 20+ classes do simulador
"""
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
import pandas as pd
import numpy as np
import sys
import os
import math
from collections import Counter

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def extract_flow_features(packets):
    """Agrupa pacotes em fluxos e extrai features por fluxo"""
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        proto = pkt[IP].proto
        src = pkt[IP].src
        dst = pkt[IP].dst

        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

        # Chave de fluxo bidirecional
        key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)

        if key not in flows:
            flows[key] = {
                "src_ip": src, "dst_ip": dst,
                "src_port": sport, "dst_port": dport,
                "protocol": proto,
                "timestamps": [], "lengths": [],
                "tcp_flags": [], "payloads": [],
                "directions": []
            }

        f = flows[key]
        f["timestamps"].append(float(pkt.time))
        f["lengths"].append(len(pkt))
        f["directions"].append(0 if (src, sport) <= (dst, dport) else 1)

        if TCP in pkt:
            f["tcp_flags"].append(int(pkt[TCP].flags))
        if Raw in pkt:
            f["payloads"].append(bytes(pkt[Raw].load))

    return flows

def flow_to_features(flow_id, flow, label):
    ts = sorted(flow["timestamps"])
    lens = flow["lengths"]
    iats = [ts[i+1] - ts[i] for i in range(len(ts)-1)] if len(ts) > 1 else [0]
    payloads = flow["payloads"]
    payload_bytes = b"".join(payloads)

    fwd = [l for l, d in zip(lens, flow["directions"]) if d == 0]
    bwd = [l for l, d in zip(lens, flow["directions"]) if d == 1]

    flags = flow["tcp_flags"]
    syn_count  = sum(1 for f in flags if f & 0x02)
    ack_count  = sum(1 for f in flags if f & 0x10)
    fin_count  = sum(1 for f in flags if f & 0x01)
    rst_count  = sum(1 for f in flags if f & 0x04)
    psh_count  = sum(1 for f in flags if f & 0x08)

    duration = ts[-1] - ts[0] if len(ts) > 1 else 0

    return {
        # Identificação
        "src_ip":     flow["src_ip"],
        "dst_ip":     flow["dst_ip"],
        "src_port":   flow["src_port"],
        "dst_port":   flow["dst_port"],
        "protocol":   flow["protocol"],

        # Volume
        "pkt_count":       len(lens),
        "total_bytes":     sum(lens),
        "duration_sec":    round(duration, 6),

        # Tamanho de pacotes
        "pkt_len_mean":    round(np.mean(lens), 2),
        "pkt_len_std":     round(np.std(lens), 2),
        "pkt_len_min":     min(lens),
        "pkt_len_max":     max(lens),

        # Inter-arrival time (IAT)
        "iat_mean":    round(np.mean(iats), 6),
        "iat_std":     round(np.std(iats), 6),
        "iat_min":     round(min(iats), 6),
        "iat_max":     round(max(iats), 6),
        "iat_cv":      round(np.std(iats) / (np.mean(iats) + 1e-9), 4),  # beaconing detector

        # Direcionalidade
        "fwd_pkt_count":   len(fwd),
        "bwd_pkt_count":   len(bwd),
        "fwd_bytes_mean":  round(np.mean(fwd), 2) if fwd else 0,
        "bwd_bytes_mean":  round(np.mean(bwd), 2) if bwd else 0,
        "bytes_ratio":     round(sum(fwd) / (sum(bwd) + 1e-9), 4),

        # Taxa
        "pkts_per_sec":    round(len(lens) / (duration + 1e-9), 2),
        "bytes_per_sec":   round(sum(lens) / (duration + 1e-9), 2),

        # TCP flags
        "syn_count":   syn_count,
        "ack_count":   ack_count,
        "fin_count":   fin_count,
        "rst_count":   rst_count,
        "psh_count":   psh_count,
        "syn_ack_ratio":   round(syn_count / (ack_count + 1e-9), 4),

        # Payload
        "payload_pkt_count":  len(payloads),
        "payload_total_bytes": len(payload_bytes),
        "payload_entropy":    round(entropy(payload_bytes), 4),
        "payload_mean_len":   round(np.mean([len(p) for p in payloads]), 2) if payloads else 0,

        # Unique
        "unique_dst_ports":   1,  # por fluxo sempre 1; útil ao agregar por IP
        "has_payload":        int(len(payloads) > 0),

        "label": label
    }

def extract_packet_features(packets, label):
    """Feature por pacote individual (original + expandido)"""
    rows = []
    for pkt in packets:
        if IP not in pkt:
            continue

        payload = bytes(pkt[Raw].load) if Raw in pkt else b""

        row = {
            "src_ip":       pkt[IP].src,
            "dst_ip":       pkt[IP].dst,
            "protocol":     pkt[IP].proto,
            "packet_len":   len(pkt),
            "ttl":          pkt[IP].ttl,
            "ip_flags":     int(pkt[IP].flags),
            "frag_offset":  pkt[IP].frag,
            "src_port":     None,
            "dst_port":     None,
            "tcp_flags":    None,
            "tcp_window":   None,
            "payload_len":  len(payload),
            "payload_entropy": round(entropy(payload), 4),
            "has_payload":  int(len(payload) > 0),
            "is_icmp":      int(ICMP in pkt),
            "is_dns":       int(DNS in pkt),
            "label":        label
        }

        if TCP in pkt:
            row["src_port"]   = pkt[TCP].sport
            row["dst_port"]   = pkt[TCP].dport
            row["tcp_flags"]  = int(pkt[TCP].flags)
            row["tcp_window"] = pkt[TCP].window
        elif UDP in pkt:
            row["src_port"] = pkt[UDP].sport
            row["dst_port"] = pkt[UDP].dport

        rows.append(row)
    return rows

def process_pcap(pcap_file, label, output_file, mode="flow"):
    print(f"[*] Processando: {pcap_file} → label={label} modo={mode}")
    packets = rdpcap(pcap_file)
    print(f"    {len(packets)} pacotes lidos")

    if mode == "flow":
        flows = extract_flow_features(packets)
        rows = [flow_to_features(k, v, label) for k, v in flows.items()]
        print(f"    {len(rows)} fluxos extraídos")
    else:
        rows = extract_packet_features(packets, label)
        print(f"    {len(rows)} pacotes extraídos")

    df = pd.DataFrame(rows)
    df.to_csv(output_file, index=False)
    print(f"    [OK] Salvo em {output_file}")
    return df

def process_all(pcap_dir, csv_dir, mode="flow"):
    """Processa todos os PCAPs e gera dataset unificado"""
    os.makedirs(csv_dir, exist_ok=True)
    dfs = []

    # Mapeia arquivo → label
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith(".pcap")]

    for pcap_file in sorted(pcap_files):
        label = pcap_file.replace(".pcap", "")
        input_path  = os.path.join(pcap_dir, pcap_file)
        output_path = os.path.join(csv_dir, f"{label}.csv")

        try:
            df = process_pcap(input_path, label, output_path, mode)
            dfs.append(df)
        except Exception as e:
            print(f"    [ERRO] {pcap_file}: {e}")

    if dfs:
        full = pd.concat(dfs, ignore_index=True)
        full_path = os.path.join(csv_dir, "dataset_full.csv")
        full.to_csv(full_path, index=False)
        print(f"\n[DONE] Dataset completo: {full_path}")
        print(f"       {len(full)} amostras | {full['label'].nunique()} classes")
        print(f"\nDistribuição:")
        print(full['label'].value_counts().to_string())
        return full

if __name__ == "__main__":
    if len(sys.argv) == 4:
        # Modo individual: python extract_features.py arquivo.pcap label saida.csv
        process_pcap(sys.argv[1], sys.argv[2], sys.argv[3], mode="flow")

    elif len(sys.argv) == 3:
        # Modo batch: python extract_features.py pcaps/ csv/
        process_all(sys.argv[1], sys.argv[2], mode="flow")

    else:
        print("Uso:")
        print("  Individual: python extract_features.py arquivo.pcap label saida.csv")
        print("  Batch:      python extract_features.py pcaps/ csv/")
