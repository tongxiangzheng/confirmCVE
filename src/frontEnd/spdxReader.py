import cveSolver
import json
import os
import sys
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo

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

pl=loadSpdxFile("my_spdx_document.spdx.json")
print(cveSolver.solve(pl))