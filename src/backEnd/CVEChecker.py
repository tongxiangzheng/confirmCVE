import re
from loguru import logger as log
class CVEChecker:
	def __init__(self,cves):
		self.dismatched_cves=dict()
		for cve in cves:
			cve=cve.strip().lower()
			cve_=cve.split("#")[0]
			self.dismatched_cves[cve]=(re.compile("fix.*"+cve_+r"\b"),re.compile(cve_+r".patch\b"))
			#\b匹配单词结尾，表示CVE字符串应为独立的单词
		self.matched_cves=[]
		self.warnings=[]
	def parse(self,info,commit,type):
		info=info.lower()
		log.debug(info)
		matchCVE=[]
		for cveString,cveRe in self.dismatched_cves.items():
			for r in cveRe:
				if r.search(info) is not None:
					matchCVE.append({"name":cveString,"type":type,"commit":commit.hexsha,"info":info})
					break
		for cve in matchCVE:
			self.dismatched_cves.pop(cve["name"])
			self.matched_cves.append(cve)
	def dfsTree(self,tree,commit):
		for blobFile in tree.blobs:
			self.parse(blobFile.name,commit,"patch_file")
		for treeDir in tree.trees:
			self.dfsTree(treeDir,commit)
	def checkCommit(self,commit):
		log.debug("check commit"+commit.hexsha)
		self.parse(commit.message,commit,"commit_message")
		self.dfsTree(commit.tree,commit)
	def getMatchedCVE(self)->list[str]:
		return self.matched_cves
	def getDismathedCVE(self)->list[str]:
		cves=[]
		for cveString in self.dismatched_cves:
			cves.append(cveString)
		return cves
	def addWarning(self,warnInfo):
		if len(self.warnings)<10:
			self.warnings.append(warnInfo)
	def getReport(self)->dict:
		report=dict()
		report['safeCVE']=self.getMatchedCVE()
		report['unsafeCVE']=self.getDismathedCVE()
		report['success']=True
		report['warning']=self.warnings
		#report['safeNumber']=len(self.getMatchedCVE())
		#report['unsafeNumber']=len(self.getDismathedCVE())
		return report
		