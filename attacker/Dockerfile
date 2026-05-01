FROM python:3.11-slim

# Ferramentas de sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    hping3 \
    nikto \
    gobuster \
    dnsutils \
    curl \
    netcat-openbsd \
    iputils-ping \
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# Wordlist básica para gobuster/hydra
# (rockyou fica grande demais; usamos uma compacta para o lab)
RUN mkdir -p /wordlists && \
    echo -e "admin\nroot\npassword\n123456\ntest\nguest\niotdevice\ndevice\nsensor" \
    > /wordlists/passwords.txt && \
    echo -e "admin\nroot\napi\nv1\nv2\nstatus\nhealth\nconfig\nlogin\nbackup\ndashboard" \
    > /wordlists/paths.txt

# Dependências Python do orquestrador
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
