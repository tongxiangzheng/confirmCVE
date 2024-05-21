import socket
import json
def solve(packageList):
    print(packageList)
def server():
    s = socket.socket()
    port = 8342
    s.bind(('0.0.0.0', port))
    s.listen(5)
    while True:
        c,addr = s.accept()
        lenInfo=c.recv(4)
        length=int.from_bytes(lenInfo, byteorder='big')
        data=b""
        while length!=0:
            recvInfo=c.recv(min(1024,length))
            data=data+recvInfo
            length-=len(recvInfo)
        data=data.decode()
        solve(json.loads(data))
        c.close()
server()