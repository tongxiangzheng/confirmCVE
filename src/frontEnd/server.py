import socket
import json
import os
import sys
import traceback
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
import queryNVD
from GitChecker import GitChecker
from queryCVEInfo import queryCVEInfo
from loguru import logger as log
def queryPackageCVE(packageInfo:PackageInfo,cves:list)->list[str]:
	try:
		if len(cves)==0:
			return []
		checker=GitChecker(packageInfo)
		ans=checker.check(cves)
	except Exception as e:
		log.warning("failed to query packageCVE")
		return []
	return ans.getDismathedCVE()
def solve(packageInfoList):
    packageList=[]
    for packageInfo in packageInfoList:
        packageList.append(PackageInfo.loadPackageInfo(packageInfo))
    package_cveList=queryNVD.query(packageList)
    res=dict()
    for package,cves in package_cveList.items():
        confirmed_cves=queryPackageCVE(package,cves)
        res[package.name]=confirmed_cves
    return res
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
    port = 8342
    s.bind(('0.0.0.0', port))
    s.listen(5)
    while True:
        c,addr = s.accept()
        data=receiveObject(c)
        res=solve(data)
        print(res)
        sendObject(c,res)
        c.close()

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
log.add(sink=logFile,level='INFO')
#log.add(sink=logFile,level='TRACE')
server()