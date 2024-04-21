from PackageInfo import PackageInfo
from GitChecker import GitChecker
from queryCVEInfo import queryCVEInfo
def driver():
	virtualPackage=PackageInfo("centos","el8","bzip2","1.0.6","26")
	cves=queryCVEInfo(virtualPackage)
	#cves={'CVE-2019-12900', 'CVE-2016-3189'}
	print(cves)
	checker=GitChecker(virtualPackage)
	checker.check(cves)

driver()
