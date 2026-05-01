#!/bin/bash
# capture_all.sh — captura e rotula cada classe de ataque automaticamente

PCAP_DIR="/pcaps"
SIMULATOR="docker exec botnet-simulator python botnet_simulator.py"
MONITOR="docker exec traffic-monitor"
DURATION_BENIGN=120
DURATION_ATTACK=30

mkdir -p $PCAP_DIR

run_capture() {
    local label=$1
    local attack=$2
    local duration=$3

    echo ""
    echo "============================================"
    echo "[*] Capturando: $label (${duration}s)"
    echo "============================================"

    # Inicia captura em background
    $MONITOR tcpdump -i eth0 -w "$PCAP_DIR/${label}.pcap" &
    TCPDUMP_PID=$!

    sleep 1

    if [ "$attack" = "benign" ]; then
        echo "[*] Tráfego benigno — aguardando ${duration}s..."
        sleep $duration
    else
        $SIMULATOR $attack
        # Aguarda terminar + buffer
        sleep 5
    fi

    # Para captura
    $MONITOR kill -SIGINT $TCPDUMP_PID 2>/dev/null || true
    sleep 2
    echo "[OK] PCAP salvo: ${label}.pcap"
}

echo "=============================="
echo " LAB IoT Botnet — Captura"
echo " Classes: 20+ ataques"
echo "=============================="

# Tráfego normal
run_capture "benign"            "benign"            $DURATION_BENIGN

# Reconhecimento
run_capture "port_scan"         "port_scan"         $DURATION_ATTACK
run_capture "os_fingerprint"    "os_fingerprint"    $DURATION_ATTACK
run_capture "service_enum"      "service_enum"      $DURATION_ATTACK
run_capture "vuln_scan"         "vuln_scan"         $DURATION_ATTACK

# Brute Force
run_capture "ssh_bruteforce"        "ssh_bruteforce"        $DURATION_ATTACK
run_capture "telnet_bruteforce"     "telnet_bruteforce"     $DURATION_ATTACK
run_capture "http_bruteforce"       "http_bruteforce"       $DURATION_ATTACK
run_capture "credential_stuffing"   "credential_stuffing"   $DURATION_ATTACK

# C2
run_capture "c2_beaconing"    "c2_beaconing"    40
run_capture "c2_dga"          "c2_dga"          $DURATION_ATTACK
run_capture "c2_dns_tunnel"   "c2_dns_tunnel"   $DURATION_ATTACK
run_capture "c2_icmp_tunnel"  "c2_icmp_tunnel"  $DURATION_ATTACK

# DDoS
run_capture "syn_flood"   "syn_flood"   $DURATION_ATTACK
run_capture "udp_flood"   "udp_flood"   $DURATION_ATTACK
run_capture "icmp_flood"  "icmp_flood"  $DURATION_ATTACK
run_capture "http_flood"  "http_flood"  $DURATION_ATTACK
run_capture "slowloris"   "slowloris"   40

# Lateral Movement
run_capture "smb_enum"      "smb_enum"      $DURATION_ATTACK
run_capture "arp_spoofing"  "arp_spoofing"  $DURATION_ATTACK
run_capture "port_forward"  "port_forward"  $DURATION_ATTACK

# Exfiltração
run_capture "data_exfil_http"  "data_exfil_http"  $DURATION_ATTACK
run_capture "data_exfil_dns"   "data_exfil_dns"   $DURATION_ATTACK
run_capture "data_exfil_icmp"  "data_exfil_icmp"  $DURATION_ATTACK

# Malware
run_capture "ransomware_scan"  "ransomware_scan"  $DURATION_ATTACK
run_capture "worm_spread"      "worm_spread"      $DURATION_ATTACK
run_capture "cryptominer"      "cryptominer"      40

# Web Attacks
run_capture "lfi_sim"   "lfi_sim"   $DURATION_ATTACK
run_capture "sqli_sim"  "sqli_sim"  $DURATION_ATTACK
run_capture "rce_sim"   "rce_sim"   $DURATION_ATTACK
run_capture "xss_sim"   "xss_sim"   $DURATION_ATTACK

echo ""
echo "=============================="
echo "[DONE] Todos os PCAPs gerados"
echo "=============================="
ls -lh $PCAP_DIR
