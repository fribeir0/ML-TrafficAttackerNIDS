FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    hping3 \
    nikto \
    dnsutils \
    curl \
    netcat-openbsd \
    iputils-ping \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz

RUN mkdir -p /wordlists && \
    printf 'admin\nroot\npassword\n123456\ntest\nguest\niotdevice\ndevice\nsensor\n' \
    > /wordlists/passwords.txt && \
    printf 'admin\nroot\napi\nv1\nv2\nstatus\nhealth\nconfig\nlogin\nbackup\ndashboard\n' \
    > /wordlists/paths.txt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app