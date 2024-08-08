import json
def sendObject(s,info):
	info=json.dumps(info).encode()
	length=len(info).to_bytes(4, byteorder='big')
	s.send(length)
	s.send(info)
def receiveObject(s):
	lenInfo=s.recv(4)
	length=int.from_bytes(lenInfo, byteorder='big')
	data=b""
	while length!=0:
		recvInfo=s.recv(min(1024,length))
		data=data+recvInfo
		length-=len(recvInfo)
	data=data.decode()
	return json.loads(data)