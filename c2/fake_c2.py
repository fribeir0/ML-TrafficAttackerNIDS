import socket

HOST = "0.0.0.0"
PORT = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(20)

print("[C2 FAKE] Servidor iniciado na porta 8080")

while True:
    conn, addr = server.accept()
    
    try:
        data = conn.recv(4096)

        if data:
            print(f"[C2 FAKE] Dados recebidos de {addr}: {data.decode(errors='ignore')}")
    
    except Exception as e:
        print(f"[ERRO] {e}")
    
    finally:
        conn.close()