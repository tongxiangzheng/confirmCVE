import os
import git
import re
from loguru import logger as log
class GitChecker:
	def __init__(self,packageName):
		self.packageName=packageName
		self.osInfo='centos'
		self.autoReleaseDict=dict()
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'repos',self.osInfo,packageName)
		repoLink="https://git.centos.org/rpms/"+packageName+'.git'
		log.info("git link is "+repoLink)
		if os.path.exists(downloadPath):
			self.repo = git.Repo(downloadPath)
			#repo.remotes.origin.pull()
			#check if git repo have to update
			#disable only for debug
		else:
			self.repo = git.Repo.clone_from(repoLink,to_path=downloadPath)
	
	def check(self):
		regix=re.compile(r"fix.*cve\b")
		visted_commits=set()
		branchName="el8"
		if branchName in self.repo.remote().refs:
			branch=self.repo.remote().refs[branchName]
			log.debug("branch: "+branch.name)
			nowCommit=self.repo.commit(branch.name)
			while True:
				hexsha=nowCommit.hexsha
				if hexsha in visted_commits:
					break
				visted_commits.add(hexsha)
				log.debug("commit: "+hexsha+" , "+nowCommit.message)
				if regix.search(nowCommit.message) is not None:
					return True
				if len(nowCommit.parents)==0:
					break
				nowCommit=nowCommit.parents[0]
		return False

with open("packageList.txt","r") as f:
	packages=f.readlines()
	for packageName in packages:
		packageName=packageName.strip()
		checker=GitChecker(packageName)
		with open("result.txt","a") as f2:
			if checker.check() is True:
				f2.write(packageName+": "+" have CVE\n")
			else:
				f2.write(packageName+": "+" no CVE\n")
				

