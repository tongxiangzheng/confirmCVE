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
def queryPackageCVE(packageInfo:PackageInfo,cves:list)->list[str]:
	if len(cves)==0:
		return []
	try:
		parser=OSInformation.OSInformation()
		osInfo=parser.getOsInfo(packageInfo)
		if osInfo.type=='rpm':
			checker=GitChecker(packageInfo,osInfo)
		else:
			checker=GitCheckerDEB(packageInfo)
		ans=checker.check(cves)
	except Exception as e:
		traceback.print_exc()
		log.warning("failed to check packageCVE")
		return cves
	return ans.getDismathedCVE()
def solve(packageList):
	package_cveList=queryNVD.query(packageList)
	res=dict()
	for package,cves in package_cveList.items():
		#print(cves)
		confirmed_cves=queryPackageCVE(package,cves)
		res[package.name]=confirmed_cves
	return res