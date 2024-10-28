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
def queryPackageCVE(packageInfo:PackageInfo,cves:list)->list:
	if len(cves)==0:
		return []
	if packageInfo.osKind!='deb' and packageInfo.osKind!='rpm':
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
	return ans.getDismathedCVE()
def solve(packageList):
	package_cveList=queryNVD.query(packageList)
	res=dict()
	for package,cves_set in package_cveList.items():
		cves=list(cves_set)
		#print(cves)
		confirmed_cves=queryPackageCVE(package,cves)
		res[package.name]=confirmed_cves
	return res