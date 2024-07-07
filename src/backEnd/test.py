import GitCheckerDEB
import PackageInfo
import os
from loguru import logger as log
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='TRACE')
pi=PackageInfo.loadPackageInfo({"osType":"deb","dist":"boinc","name":"grep","version":"3.8","release":"5","gitLink":"https://salsa.debian.org/debian/grep.git"})
checker=GitCheckerDEB.GitCheckerDEB(pi)
checker.check([])