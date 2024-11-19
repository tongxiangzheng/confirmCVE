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
# def firstNumber(rawstr)->str:
# 	res=""
# 	for c in rawstr:
# 		if c.isdigit() is True:
# 			res+=c
# 		else:
# 			break
# 	return res
class GitCheckerDEB:
	def __init__(self,packageInfo:PackageInfo):
		#if packageInfo.release is not None:
		#	packageInfo.release=firstNumber(packageInfo.release)
		self.packageInfo=packageInfo
		
		gitLink=packageInfo.gitLink
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'..','..','data','repos',self.packageInfo.osType,packageInfo.name)
		repoLink=gitLink
		self.repoLink=repoLink
		if repoLink=='':
			self.repo=None
			return
		#log.info("git link is "+repoLink)
		tmp=repoLink.split(' ')
		if len(tmp)>1:
			if tmp[1]=='-b':
				self.branch=tmp[2]
				repoLink=tmp[0]
		else:
			self.branch=None
		
		if os.path.exists(downloadPath):
			self.repo = git.Repo(downloadPath)
			#self.repo.remotes.origin.pull()
			#check if git repo have to update
			#disable only for debug
		else:
			if not os.path.exists(downloadPath):
				os.makedirs(downloadPath)
			self.repo = git.Repo.clone_from(repoLink,to_path=downloadPath)
			
	def checkCommit(self,commit,changelogFileName):
		try:
			changelogFile = commit.tree[changelogFileName]
		except Exception:
			#log.warning("error at "+commit.hexsha+" :no spec file at "+changelogFileName)
			#print(commit.tree)
			return False
		with io.BytesIO(changelogFile.data_stream.read()) as f:
			data=f.read()
			try:
				changelogInfo = data.decode('utf-8')
			except Exception as e:
				changelogInfo = data.decode('utf-8', errors='ignore')
				#log.warning("error at "+commit.hexsha+" :parse changelog file:"+changelogFileName+" as UTF-8 failed")
			changelogInfo_line=changelogInfo.split('\n',1)
			for info in changelogInfo_line:
				if len(info)>0:
					firstLine=info.split(' ')
					break
			
			name=firstLine[0]
			version_release=firstLine[1][1:-1].rsplit('-')
			version=version_release[0]
			release=None
			if len(version_release)>1:
				release=firstNumber(version_release[1])
			
			#log.trace("name:"+name)
			#log.trace("version:"+version)
			#if release is not None:
			#	log.trace("release:"+release)
			#log.trace("message:"+commit.message)
			
			if self.packageInfo.name==name and self.packageInfo.version==version:
				if self.packageInfo.release is None or release is None or self.packageInfo.release==release:
					return True
		return False
	def specCheck(self):
		if self.repo is None:
			return None
		#使用软件包的version和release信息，与commit中的.spec文件进行匹配
		# log.info("start check by spec file")
		# log.info(" name is "+self.packageInfo.name)
		# log.info(" version is "+self.packageInfo.version)
		# if self.packageInfo.release is not None:
		# 	log.info(" release is "+self.packageInfo.release)
		visted_commits=set()
		matched_commits=[]
		#specFilePath=self.osInfo.specfile
		changelogFileName='debian/changelog'
		if self.branch is not None:
			branch=self.repo.remote().refs[self.branch]
			#log.debug("branch: "+branch.name)
			nowCommit=self.repo.commit(branch.name)
		elif 'debian' in self.repo.remote().refs:
			#log.info("use debian branch instead master branch")
			branch=self.repo.remote().refs['debian']
			#log.debug("branch: "+branch.name)
			nowCommit=self.repo.commit(branch.name)
		else:
			nowCommit=self.repo.head.commit
		while True:
			hexsha=nowCommit.hexsha
			if hexsha in visted_commits:
				break
			visted_commits.add(hexsha)
			#log.debug("commit: "+hexsha+" , "+nowCommit.message)
			if self.checkCommit(nowCommit,changelogFileName):
				matched_commits.append((nowCommit.committed_date,nowCommit.hexsha))
				#log.info("match the commit: "+nowCommit.hexsha)
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
			log.warning("Cannot match any commit for "+self.packageInfo.name+" at :"+self.repoLink)
			raise Exception("Cannot match any commit")
		log.warning("match commit id: "+commitId)
		log.warning("at :"+self.repoLink+"/commit/"+commitId)
		self.checkMessage(commitId,cveChecker)
		return cveChecker