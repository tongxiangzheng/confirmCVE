import cveSolver
import json
import os
import sys
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
import normalize
def loadSpdxFile(fileName):
	res=[]
	with open(fileName,"r") as f:
		spdxObj=json.load(f)
		packages=spdxObj['packages']
		for package in packages:
			packageType=package['description']
			if packageType=='Deb' or packageType=='Rpm':
				purlStr=package['externalRefs'][0]['referenceLocator']
				res.append(PackageInfo.loadPurl(purlStr))
	return res
def parseSpdxObj(spdxObj):
	res=[]
	packages=spdxObj['packages']
	for package in packages:
		packageType=package['description']
		if packageType.lower()=='deb' or packageType.lower()=='rpm':
			purlStr=package['externalRefs'][0]['referenceLocator']
			purlStr=normalize.reNormalReplace(purlStr)
			packageinfo=PackageInfo.loadPurl(purlStr)
			if 'comment' in package:
				packageinfo.gitLink=package['comment']
			res.append(packageinfo)
	return res


#pl=loadSpdxFile("my_spdx_document.spdx.json")
#print(cveSolver.solve(pl))