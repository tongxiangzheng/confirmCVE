import cveSolver
import json
import os
import sys
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
import PackageInfo
import normalize
#def loadSpdxFile(fileName):
#	res=[]
#	with open(fileName,"r") as f:
#		spdxObj=json.load(f)
#		packages=spdxObj['packages']
#		for package in packages:
#			packageType=package['description']
#			if packageType=='Deb' or packageType=='Rpm':
#				purlStr=package['externalRefs'][0]['referenceLocator']
#				res.append(PackageInfo.loadPurl(purlStr))
#	return res
def parseSpdxObj(spdxObj):
	
	names_packages=dict()
	packages=spdxObj['packages']
	for package in packages:
		packageType=package['description']
		if packageType.lower()=='deb' or packageType.lower()=='rpm':
			packageinfo=None
			for externalRefs in package['externalRefs']:
				if externalRefs['referenceCategory']!='PACKAGE_MANAGER':
					continue
				purlStr=externalRefs['referenceLocator']
				purlStr=normalize.reNormalReplace(purlStr)
				packageinfo=PackageInfo.loadPurl(purlStr)
			if packageinfo is not None:
				name=packageinfo.name
				names_packages[name]=packageinfo
			else:
				log.warning('ERROR:spdxReader:cannot find PACKAGE_MANAGER infomation in externalRefs')
		else:
			spdxid=package['SPDXID']
			if spdxid.startswith("SPDXRef-DocumentRoot-Directory"):
				continue
			name=package['name']
			version=package['versionInfo']
			packageinfo=PackageInfo.PackageInfo("maven","","",name,version,None,None)
			name=packageinfo.name
			if name not in names_packages:
				names_packages[name]=packageinfo
					
			#res.append(packageinfo)
	res=list(names_packages.values())
	return res


#pl=loadSpdxFile("my_spdx_document.spdx.json")
#print(cveSolver.solve(pl))