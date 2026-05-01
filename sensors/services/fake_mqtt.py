"""
fake_mqtt.py
------------
Broker MQTT 3.1.1 falso na porta 1883.
Implementação manual do protocolo — sem dependência de biblioteca broker.

Comportamento:
  - Aceita CONNECT de qualquer cliente (sem autenticação)
  - Responde CONNACK com código 0 (aceito)
  - Aceita SUBSCRIBE em qualquer tópico, responde SUBACK
  - Aceita PUBLISH e faz echo para todos os clientes conectados (QoS 0 e 1)
  - Registra todos os tópicos e payloads para análise

Isso gera tráfego MQTT real que o NIDS pode detectar como
"acesso não autorizado a broker aberto" — vulnerabilidade IoT comum.
"""

import socket
import threading
import struct
import logging
import os
import time

PORT = 1883
HOST = "0.0.0.0"
LOG  = "/app/logs/mqtt_events.log"

os.makedirs(os.path.dirname(LOG), exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [MQTT] %(message)s")

# Registro de clientes conectados {addr: socket}
clients = {}
clients_lock = threading.Lock()


def _log(msg):
    logging.info(msg)
    with open(LOG, "a") as f:
        f.write(f"{time.time()} {msg}\n")


def read_remaining_length(sock):
    """Decodifica o campo de tamanho variável do MQTT."""
    mult = 1
    val  = 0
    for _ in range(4):
        b = sock.recv(1)
        if not b:
            return None
        byte = b[0]
        val += (byte & 0x7F) * mult
        mult *= 128
        if not (byte & 0x80):
            break
    return val


def encode_remaining_length(length):
    result = b""
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        result += bytes([byte])
        if length == 0:
            break
    return result


def read_utf8(data, offset):
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    return data[offset:offset+length].decode(errors="replace"), offset + length


def handle_client(sock, addr):
    addr_str = f"{addr[0]}:{addr[1]}"
    _log(f"CONNECT_ATTEMPT src={addr_str}")

    with clients_lock:
        clients[addr_str] = sock

    try:
        while True:
            header = sock.recv(1)
            if not header:
                break

            pkt_type = (header[0] >> 4) & 0x0F
            remaining = read_remaining_length(sock)
            if remaining is None:
                break

            payload = b""
            if remaining > 0:
                payload = sock.recv(remaining)

            # CONNECT (1)
            if pkt_type == 1:
                # Extrai client_id
                try:
                    proto_len = struct.unpack_from(">H", payload, 0)[0]
                    offset = 2 + proto_len + 4  # pula protocolo + flags + keepalive
                    client_id, _ = read_utf8(payload, offset)
                except:
                    client_id = "unknown"
                _log(f"CONNECT client_id={client_id!r} src={addr_str}")
                # CONNACK: aceita sem autenticação
                sock.send(b"\x20\x02\x00\x00")

            # PUBLISH (3)
            elif pkt_type == 3:
                flags     = header[0] & 0x0F
                qos       = (flags >> 1) & 0x03
                try:
                    topic, offset = read_utf8(payload, 0)
                    if qos > 0:
                        pkt_id = struct.unpack_from(">H", payload, offset)[0]
                        offset += 2
                        # PUBACK para QoS 1
                        sock.send(b"\x40\x02" + struct.pack(">H", pkt_id))
                    else:
                        offset = offset
                    msg = payload[offset:].decode(errors="replace")
                    _log(f"PUBLISH topic={topic!r} msg={msg[:80]!r} src={addr_str}")
                except:
                    pass

            # SUBSCRIBE (8)
            elif pkt_type == 8:
                try:
                    pkt_id = struct.unpack_from(">H", payload, 0)[0]
                    topic, _ = read_utf8(payload, 2)
                    _log(f"SUBSCRIBE topic={topic!r} src={addr_str}")
                    # SUBACK com QoS 0
                    sock.send(b"\x90\x03" + struct.pack(">H", pkt_id) + b"\x00")
                except:
                    pass

            # PINGREQ (12)
            elif pkt_type == 12:
                sock.send(b"\xd0\x00")  # PINGRESP

            # DISCONNECT (14)
            elif pkt_type == 14:
                _log(f"DISCONNECT src={addr_str}")
                break

    except Exception as e:
        pass
    finally:
        with clients_lock:
            clients.pop(addr_str, None)
        try:
            sock.close()
        except:
            pass
        _log(f"DISCONNECTED src={addr_str}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    logging.info(f"Fake MQTT broker escutando em {HOST}:{PORT}")

    while True:
        try:
            client, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.error(f"Erro: {e}")


if __name__ == "__main__":
    main()
