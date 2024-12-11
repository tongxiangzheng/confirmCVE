import os
import sys
from loguru import logger as log
import traceback
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
import queryNVD
import OSInformation
from GitChecker import GitChecker
from GitCheckerDEB import GitCheckerDEB
from queryCVEInfo import queryCVEInfo
from SrcCheckerDeb import SrcCheckerDeb
import dataLoger
def queryPackageCVE(packageInfo:PackageInfo,cves:list)->list:
	dataLoger.logdata("")
	if len(cves)==0:
		dataLoger.logdata("package name:"+packageInfo.name)
		dataLoger.logdata("package type:"+packageInfo.osKind)
		dataLoger.logdata("cves: 0")
		return []
	if packageInfo.osKind!='deb' and packageInfo.osKind!='rpm':
		#for cve in cves:
		#	dataLoger.logdata(" "+cve['name'])
		dataLoger.logdata("package name:"+packageInfo.name)
		dataLoger.logdata("package type:"+packageInfo.osKind)
		dataLoger.logdata("cves: "+str(len(cves)))

		return cves
		#only check os system repo
	try:
		if packageInfo.osKind=='rpm':
			parser=OSInformation.OSInformation()
			osInfo=parser.getOsInfo(packageInfo)
			checker=GitChecker(packageInfo,osInfo)
		elif packageInfo.osKind=='deb':
			#checker=GitCheckerDEB(packageInfo)
			checker=SrcCheckerDeb(packageInfo)
		else:
			log.warning('unknown ostype')
		ans=checker.check(cves)
	except Exception as e:
		traceback.print_exc()
		log.warning("failed to check packageCVE")
		return cves
	
	dataLoger.logdata("package name:"+packageInfo.name)
	dataLoger.logdata("package type:"+packageInfo.osKind)
	#dataLoger.logdata("matched cve: "+str(len(ans.getMatchedCVE())))
	dataLoger.logdata("matched cve:")
	for cve in ans.getMatchedCVE():
		dataLoger.logdata(" "+cve['name']+' reason: '+' '+cve['type']+" info:"+cve['info'])
	#dataLoger.logdata("confirmed cve: "+str(len(ans.getDismatchedCVE())))
	dataLoger.logdata("confirmed cve:")
	for cve in ans.getDismatchedCVE():
		dataLoger.logdata(" "+cve['name'])
	return ans.getDismatchedCVE()
def solve(packageList):
	package_cveList=queryNVD.query(packageList)
	res=dict()
	for package,cves in package_cveList.items():
		#print(cves)
		confirmed_cves=queryPackageCVE(package,cves)
		res[package.name]=confirmed_cves
	return res