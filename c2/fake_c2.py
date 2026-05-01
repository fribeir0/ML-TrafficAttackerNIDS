importsocket

HOST="0.0.0.0"
PORT=8080

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(20)

print("[C2 FAKE] Servidor iniciado na porta 8080")

whileTrue:
conn,addr=server.accept()
data=conn.recv(4096)

ifdata:
print(f"[C2 FAKE] Dados recebidos de{addr}:{data.decode(errors='ignore')}")

conn.close()