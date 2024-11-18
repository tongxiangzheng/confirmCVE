import re
from loguru import logger as log
import os
class CVEChecker:
	def __init__(self,cves:list):
		self.dismatched_cves=dict()
		self.cvedict=dict()
		for cve in cves:
			cveName=cve['name'].strip().lower()
			cve_=cveName.split("#")[0]
			self.cvedict[cveName]=cve
			#self.dismatched_cves[cveName]=(re.compile("Resolves.*"+cve_+r"\b"),re.compile("fix.*"+cve_+r"\b"),re.compile(cve_+r".patch\b"))
			self.dismatched_cves[cveName]=(re.compile(cve_+r"\b"),)#策略为发现提到此cve，则认为进行了修复
			#\b匹配单词结尾，表示CVE字符串应为独立的单词
		self.matched_cves=[]
		self.warnings=[]
	def parse(self,info,commit=None,type="none"):
		info=info.lower()
		#log.trace(info)
		matchCVE=[]
		for cveName,cveRe in self.dismatched_cves.items():
			for r in cveRe:
				p=r.search(info)
				if p is not None:
					if commit is None:
						hexsha="none"
					else:
						hexsha=commit.hexsha
					matchCVE.append({"name":cveName,"type":type,"commit":hexsha,"info":info[max(0,p.span()[0]-100):min(len(info),p.span()[0]+20)],"pointer":self.cvedict[cveName]})
					#log.info(cveName+" : have fix in "+hexsha+" with info: "+info)
					break
		for cve in matchCVE:
			self.dismatched_cves.pop(cve["name"])
			self.matched_cves.append(cve)
	def dfsTree(self,tree,commit):
		for blobFile in tree.blobs:
			self.parse(blobFile.name,commit,type="patch_file")
		for treeDir in tree.trees:
			self.dfsTree(treeDir,commit)
	def dfsDir(self,Dir):
		for file in os.listdir(Dir):
			path=os.path.join(Dir,file)
			if os.path.isfile(path):
				self.parse(file,None,type="patch_file")
	def checkChangeLog(self,message):
		self.parse(message,type="changelog")
	def checkCommit(self,commit):
		log.debug("check commit: "+commit.hexsha)
		self.parse(commit.message,commit,type="commit_message")
		self.dfsTree(commit.tree,commit)
	def getMatchedCVE(self)->list:
		return self.matched_cves
	def getDismatchedCVE(self)->list:
		cves=[]
		for cveName in self.dismatched_cves:
			cves.append(self.cvedict[cveName])
		return cves
	def addWarning(self,warnInfo):
		if len(self.warnings)<10:
			self.warnings.append(warnInfo)
	def getReport(self)->dict:
		report=dict()
		report['safeCVE']=self.getMatchedCVE()
		report['unsafeCVE']=self.getDismatchedCVE()
		report['success']=True
		report['warning']=self.warnings
		#report['safeNumber']=len(self.getMatchedCVE())
		#report['unsafeNumber']=len(self.getDismatchedCVE())
		return report
		