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
import nwkTools
import spdxReader

def server():
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	port = 8342
	s.bind(('0.0.0.0', port))
	s.listen(5)
	while True:
		c,addr = s.accept()
		data=nwkTools.receiveObject(c)
		packageList=spdxReader.parseSpdxObj(data)
		res=cveSolver.solve(packageList)
		#print(res)
		nwkTools.sendObject(c,res)
		c.close()

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='TRACE')
server()