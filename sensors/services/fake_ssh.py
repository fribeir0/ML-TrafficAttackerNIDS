"""
fake_ssh.py
-----------
Servidor SSH falso na porta 22.
Aceita conexões, apresenta banner real do OpenSSH, registra todas as
tentativas de login (usuário + senha) e sempre rejeita.
Ideal para capturar tráfego de brute force SSH com handshake completo.

Usa paramiko no modo servidor — gera tráfego SSH legítimo que NIDS reais detectam.
"""

import socket
import threading
import paramiko
import logging
import os
import time

PORT    = 22
HOST    = "0.0.0.0"
LOG     = "/app/logs/ssh_attempts.log"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SSH] %(message)s")
os.makedirs(os.path.dirname(LOG), exist_ok=True)

# Gera chave do host na inicialização
HOST_KEY = paramiko.RSAKey.generate(2048)


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        msg = f"LOGIN_ATTEMPT user={username!r} pass={password!r} src={self.client_addr}"
        logging.info(msg)
        with open(LOG, "a") as f:
            f.write(f"{time.time()} {msg}\n")
        # Sempre rejeita — mas depois de um delay pequeno para parecer real
        time.sleep(0.3)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


def handle_client(client_sock, addr):
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        # Banner idêntico ao OpenSSH para não levantar suspeita em scanners
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        server = FakeSSHServer(addr)
        transport.start_server(server=server)
        # Aguarda até o cliente desistir
        chan = transport.accept(timeout=10)
        if chan:
            chan.close()
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(50)
    logging.info(f"Fake SSH escutando em {HOST}:{PORT}")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.error(f"Erro ao aceitar conexão: {e}")


if __name__ == "__main__":
    main()
