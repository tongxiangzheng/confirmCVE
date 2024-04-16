import os
import git
import io
import wget
import libarchive
import hashlib
import shutil
from loguru import logger as log
from pyrpm.spec import Spec, replace_macros
from CVEChecker import CVEChecker
from PackageInfo import PackageInfo
from OSInformation import OSInformation
class GitChecker:
	def __init__(self,packageInfo:PackageInfo):
		self.packageInfo=packageInfo
		parser=OSInformation()
		self.osInfo=parser.getOsInfo(packageInfo)
		self.autoReleaseDict=dict()
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'..','..','repos',self.osInfo.name,packageInfo.name)
		repoLink=self.osInfo.gitLink+packageInfo.name+'.git'
		log.info("git link is "+repoLink)
		if os.path.exists(downloadPath):
			self.repo = git.Repo(downloadPath)
			#repo.remotes.origin.pull()
			#check if git repo have to update
			#disable only for debug
		else:
			self.repo = git.Repo.clone_from(repoLink,to_path=downloadPath)
	def getSrcFiles(self):
		filename=self.packageInfo.name+"-"+self.packageInfo.version+"-"+self.packageInfo.release+"."+self.packageInfo.dist+".src.rpm"
		srcFiles=[]
		print(self.osInfo.srcPackageLink)
		for link in self.osInfo.srcPackageLink:
			link=link.replace("{%name_first_alpha}",self.packageInfo.name[0])
			##将宏替换为名称首字母
			URL=link+filename
			DIR = os.path.split(os.path.abspath(__file__))[0]
			downloadPath=os.path.join(DIR,'..','..','packages',self.osInfo.name)
			filePath=os.path.join(downloadPath,filename)
			if not os.path.exists(downloadPath):
				os.makedirs(downloadPath)
			if not os.path.exists(filePath):
				log.info("download "+URL+" to "+filePath)
				try:
					wget.download(URL,out=filePath)
				except Exception as e:
					log.info("can't download src package from "+URL+" ,which is not an error")
					log.info("download error info: "+str(e.args))
					continue
			
			DIR = os.path.split(os.path.abspath(__file__))[0]
			extractFilePath=os.path.join(DIR,'..','..','packages_extract',self.osInfo.name,filename)
			if os.path.isdir(extractFilePath):
				shutil.rmtree(extractFilePath)
			os.makedirs(extractFilePath)
			with libarchive.Archive(filePath) as a:
				for entry in a:
					entryFileName=os.path.join(extractFilePath,entry.pathname)
					a.readpath(entryFileName)
					with open(entryFileName,"rb") as f:
						git_sha1=hashlib.sha1()
						sha1=hashlib.sha1()
						sha256=hashlib.sha256()
						sha512=hashlib.sha512()
						stats = os.stat(entryFileName)
						git_sha1.update(("blob " + str(stats.st_size) + "\0").encode())
						while True:
							data = f.read(1024)
							if not data:
								break
							git_sha1.update(data)
							sha1.update(data)
							sha256.update(data)
							sha512.update(data)
						srcFiles.append({'pathname':entry.pathname,'git_sha1':git_sha1.hexdigest(),'sha1':sha1.hexdigest(),'sha256':sha256.hexdigest(),'sha512':sha512.hexdigest()})
						log.debug("file in src:"+entry.pathname+" git_sha1:"+git_sha1.hexdigest()+" sha1:"+sha1.hexdigest()+" sha256:"+sha256.hexdigest()+" sha512:"+sha512.hexdigest())
			#shutil.rmtree(extractFilePath)
			break
		return srcFiles
	def dfsTree(self,tree,ans):
		for blobFile in tree.blobs:
			ans.add(blobFile.hexsha)
			log.trace(blobFile.name+" : "+blobFile.hexsha)
		for treeDir in tree.trees:
			self.dfsTree(treeDir,ans)
	def parseMetadata(self,metadataName,commit,map):
		#git.centos.org中的仓库会将源码压缩包的文件名和哈希值保存至.$(name).metadata中，需要进行解析
		#fedora中的仓库会将源码压缩包的文件名和哈希值保存至sources文件中，需要进行解析
		try:
			metadataReference=commit.tree[metadataName]
		except Exception:
			return
		with io.BytesIO(metadataReference.data_stream.read()) as f:
			data=f.readlines()
			for info in data:
				info=info.decode()
				log.trace("parse:"+info)
				if info.startswith('SHA256'):
					parseInfo=info.split('=')
					filehex=parseInfo[1].strip()
					map['sha256'].add(filehex)
				elif info.startswith('SHA512'):
					parseInfo=info.split('=')
					filehex=parseInfo[1].strip()
					map['sha512'].add(filehex)
				else:
					filehex=info.split()[0]
					map['sha1'].add(filehex)
				log.trace("sources file: "+filehex)
		return
	def srcCheck(self):
		#尝试获取软件包源码，并使用源码文件与commit进行匹配
		files=self.getSrcFiles()
		if len(files)==0:
			return None
		log.info("start check by src files")
		visted_commits=set()
		matched_commits=[]
		branchName=self.osInfo.branch
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
				blobFiles=set()
				self.dfsTree(nowCommit.tree,blobFiles)
				metadataFiles={'sha1':set(),'sha256':set(),'sha512':set()}
				self.parseMetadata('.'+self.packageInfo.name+'.metadata',nowCommit,metadataFiles)
				self.parseMetadata("sources",nowCommit,metadataFiles)
				commitIsMatch=True
				disMatchNumber=0	#for debug
				disMatchs=[]		#for debug
				for f in files:
					#specFile = nowCommit.tree / f[0]
					if f['git_sha1'] not in blobFiles and f['sha1'] not in metadataFiles['sha1'] and f['sha256'] not in metadataFiles['sha256'] and f['sha512'] not in metadataFiles['sha512']:
						commitIsMatch=False
						disMatchNumber=disMatchNumber+1
						if(disMatchNumber<3):
							disMatchs.append(f['pathname'])
						#break
				if commitIsMatch:
					matched_commits.append((nowCommit.committed_date,nowCommit.hexsha))
					log.info("match the commit: "+nowCommit.hexsha)
				elif disMatchNumber<3:
					log.warning("similar dismatch commit : "+hexsha+" , dismatch file as below")
					for m in disMatchs:
						log.warning("  "+m)
				if len(nowCommit.parents)==0:
					break
				nowCommit=nowCommit.parents[0]
				break
		matched_commits.sort()
		if len(matched_commits)>0:
			return matched_commits[0][1]
		return None
	def getAutorelease(self,commit,version,specFileName):
		#Fedora定义spec文件中宏%autorelease，代表“自上次version字段更改后的commit数
		#若在进行版本匹配时发现这个宏，则需要通过git树中的信息计算出对应的值
		if commit.hexsha in self.autoReleaseDict:
			return self.autoReleaseDict[commit.hexsha]
		try:
			specFile = commit.tree[specFileName]
		except Exception:
			return 0
		with io.BytesIO(specFile.data_stream.read()) as f:
			spec = Spec.from_string(f.read().decode('utf-8', errors='ignore'))
			if version==replace_macros(spec.version, spec):
				if(len(commit.parents)>0):
					fatherCommit=commit.parents[0]
					self.autoReleaseDict[commit.hexsha]=self.getAutorelease(fatherCommit,version,specFileName)+1
				else:
					self.autoReleaseDict[commit.hexsha]=1
			else:
				return 0
		return self.autoReleaseDict[commit.hexsha]

	def checkCommit(self,commit,specFileName):
		try:
			specFile = commit.tree[specFileName]
		except Exception:
			log.warning("error at "+commit.hexsha+" :no spec file at "+specFileName)
			#print(commit.tree)
			return False
		with io.BytesIO(specFile.data_stream.read()) as f:
			data=f.read()
			try:

				spec = Spec.from_string(data.decode('utf-8'))
			except Exception as e:
				spec = Spec.from_string(data.decode('utf-8', errors='ignore'))
				log.warning("error at "+commit.hexsha+" :parse spec file:"+specFileName+" as UTF-8 failed")
			try:
				name=replace_macros(spec.name, spec)
				version=replace_macros(spec.version, spec)
				release=replace_macros(spec.release, spec).split('.')[0]
			except Exception as e:
				log.warning("error at "+commit.hexsha+" :can't parse spec file:"+specFileName+":"+data.decode('utf-8', errors='ignore'))

			if release.find(r"%autorelease")!=-1:
				spec.macros['autorelease']=str(self.getAutorelease(commit,version,specFileName))
				release=replace_macros(spec.release, spec).split('.')[0]
			log.trace("name:"+name)
			log.trace("version:"+version)
			log.trace("release:"+release)
			log.trace("message:"+commit.message)
			
			if self.packageInfo.name==name and self.packageInfo.version==version and self.packageInfo.release==release:
				return True
		return False
	
	def specCheck(self):
		#使用软件包的version和release信息，与commit中的.spec文件进行匹配
		log.info("start check by spec file")
		log.info(" name is "+self.packageInfo.name)
		log.info(" version is "+self.packageInfo.version)
		log.info(" release is "+self.packageInfo.release)
		visted_commits=set()
		matched_commits=[]
		specFilePath=self.osInfo.specfile
		specFileName=specFilePath+self.packageInfo.name+'.spec'
		branchName=self.osInfo.branch
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
				if self.checkCommit(nowCommit,specFileName):
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
		srcResult=self.srcCheck()
		specResult=self.specCheck()
		if srcResult is None:
			if specResult is None:
				raise Exception("Cannot match any commit")
			return specResult
		if srcResult!=specResult:
			log.warning("src and spec matched different commit,srcResult="+str(srcResult)+" specResult="+str(specResult))
			raise Exception("src and spec matched different commit,srcResult="+str(srcResult)+" specResult="+str(specResult))
		return srcResult
	def checkMessage(self,commitId,cveChecker):
		commit=self.repo.commit(commitId)
		while len(commit.parents)>0:
			cveChecker.checkCommit(commit)
			commit=commit.parents[0]
	def check(self,cves):
		cveChecker=CVEChecker(cves)
		commitId=self.getCommitId()
		if commitId is None:
			raise Exception("Cannot match any commit")
		log.info("match commit id: "+commitId)
		self.checkMessage(commitId,cveChecker)
		return cveChecker
