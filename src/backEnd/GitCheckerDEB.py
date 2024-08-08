import os
import git
import io
import wget
import libarchive
import hashlib
import shutil
from loguru import logger as log
from CVEChecker import CVEChecker
from PackageInfo import PackageInfo
from OSInformation import OSInformation
class GitCheckerDEB:
	def __init__(self,packageInfo:PackageInfo):
		self.packageInfo=packageInfo
		gitLink=packageInfo.gitLink
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'..','..','repos',self.packageInfo.osType,packageInfo.name)
		repoLink=gitLink
		if gitLink=='':
			self.repo=None
			return
		log.info("git link is "+repoLink)
		if os.path.exists(downloadPath):
			self.repo = git.Repo(downloadPath)
			#self.repo.remotes.origin.pull()
			#check if git repo have to update
			#disable only for debug
		else:
			self.repo = git.Repo.clone_from(repoLink,to_path=downloadPath)
			
	def checkCommit(self,commit,changelogFileName):
		try:
			changelogFile = commit.tree[changelogFileName]
		except Exception:
			log.warning("error at "+commit.hexsha+" :no spec file at "+changelogFileName)
			#print(commit.tree)
			return False
		with io.BytesIO(changelogFile.data_stream.read()) as f:
			data=f.read()
			try:
				changelogInfo = data.decode('utf-8')
			except Exception as e:
				changelogInfo = data.decode('utf-8', errors='ignore')
				log.warning("error at "+commit.hexsha+" :parse changelog file:"+changelogFileName+" as UTF-8 failed")
			firstLine=changelogInfo.split('\n',1)[0].split(' ')
			
			name=firstLine[0]
			version_release=firstLine[1][1:-1]
			version=version_release.split('-')[0]
			release=version_release.split('-')[1]
			
			log.trace("name:"+name)
			log.trace("version:"+version)
			log.trace("release:"+release)
			log.trace("message:"+commit.message)
			
			if self.packageInfo.name==name and self.packageInfo.version==version and self.packageInfo.release==release:
				return True
		return False
	def specCheck(self):
		if self.repo is None:
			return None
		#使用软件包的version和release信息，与commit中的.spec文件进行匹配
		log.info("start check by spec file")
		log.info(" name is "+self.packageInfo.name)
		log.info(" version is "+self.packageInfo.version)
		if self.packageInfo.release is not None:
			log.info(" release is "+self.packageInfo.release)
		visted_commits=set()
		matched_commits=[]
		#specFilePath=self.osInfo.specfile
		changelogFileName='debian/changelog'
		nowCommit=self.repo.head.commit
		while True:
			hexsha=nowCommit.hexsha
			if hexsha in visted_commits:
				break
			visted_commits.add(hexsha)
			log.debug("commit: "+hexsha+" , "+nowCommit.message)
			if self.checkCommit(nowCommit,changelogFileName):
				matched_commits.append((nowCommit.committed_date,nowCommit.hexsha))
				log.info("match the commit: "+nowCommit.hexsha)
			if len(nowCommit.parents)==0:
				break
			nowCommit=nowCommit.parents[0]
		matched_commits.sort()
		if len(matched_commits)>0:
			return matched_commits[0][1]
		return None
	def getCommitId(self):
		return self.specCheck()
	
	def checkMessage(self,commitId,cveChecker):
		commit=self.repo.commit(commitId)
		while len(commit.parents)>0:
			cveChecker.checkCommit(commit)
			commit=commit.parents[0]
	def check(self,cves:list):
		cveChecker=CVEChecker(cves)
		commitId=self.getCommitId()
		if commitId is None:
			log.warning("Cannot match any commit for "+self.packageInfo.name)
			raise Exception("Cannot match any commit")
		log.info("match commit id: "+commitId)
		self.checkMessage(commitId,cveChecker)
		return cveChecker