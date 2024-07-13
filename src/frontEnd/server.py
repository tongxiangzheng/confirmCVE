import cveSolver
import json
import socket
import os
import sys
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
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
def server():
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	port = 8342
	s.bind(('0.0.0.0', port))
	s.listen(5)
	while True:
		c,addr = s.accept()
		data=receiveObject(c)
		packageList=[]
		for packageInfo in data:
			packageList.append(PackageInfo.loadPackageInfo(packageInfo))
		res=cveSolver.solve(packageList)
		#print(res)
		sendObject(c,res)
		c.close()

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='TRACE')
server()