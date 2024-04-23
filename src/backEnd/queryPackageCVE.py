from loguru import logger as log
import traceback
from PackageInfo import PackageInfo
from GitChecker import GitChecker
from queryCVEInfo import queryCVEInfo
def queryPackageCVE(packageInfo:PackageInfo)->list[str]:
	try:
		cves=queryCVEInfo(packageInfo)
		if len(cves)==0:
			return []
		checker=GitChecker(packageInfo)
		ans=checker.check(cves)
	except Exception as e:
		log.warning("failed to query packageCVE")
		traceback.print_exc()
		return []
	return ans.getDismathedCVE()