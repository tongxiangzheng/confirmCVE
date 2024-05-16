import socket

def server():
    s = socket.socket()
    port = 8342
    s.bind(('0.0.0.0', port))
    s.listen(5)
    while True:
        c,addr = s.accept()
        print(c.recv(1024))
        c.close()
server()