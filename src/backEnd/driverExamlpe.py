from PackageInfo import PackageInfo
from GitChecker import GitChecker
from queryCVEInfo import queryCVEInfo
def driver():
	virtualPackage=PackageInfo("openEuler","oe2309","openssh","9.3p1","2")
	cves=queryCVEInfo(virtualPackage)
	#cves={'CVE-2019-12900', 'CVE-2016-3189'}
	print(cves)
	checker=GitChecker(virtualPackage)
	checker.check(cves)

driver()
