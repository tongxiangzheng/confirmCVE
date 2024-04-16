from PackageInfo import PackageInfo
from GitChecker import GitChecker
def driver():
	virtualPackage=PackageInfo("centos","el8","bzip2","1.0.6","26")
	#cves=queryCVEInfo(virtualPackage)
	cves={'CVE-2019-12900', 'CVE-2016-3189'}
	checker=GitChecker(virtualPackage)
	checker.check(cves)

driver()
