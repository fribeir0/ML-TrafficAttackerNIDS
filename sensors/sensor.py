importsocket
importtime
importrandom
importsys
importjson

sensor_id=sys.argv[1]iflen(sys.argv)>1else"sensor"

C2_HOST="172.30.0.100"
C2_PORT=8080

whileTrue:
payload= {
"sensor":sensor_id,
"temperature":round(random.uniform(20,35),2),
"humidity":round(random.uniform(40,80),2),
"timestamp":time.time()
    }

try:
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((C2_HOST,C2_PORT))
s.send(json.dumps(payload).encode())
s.close()
exceptException:
pass

time.sleep(random.randint(2,5))