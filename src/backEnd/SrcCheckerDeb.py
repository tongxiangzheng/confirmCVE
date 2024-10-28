import os
import shutil
import tarfile
import subprocess
from loguru import logger as log
from CVEChecker import CVEChecker
from PackageInfo import PackageInfo
from OSInformation import OSInformation

def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
def extractSrc(srcFile,srcFile2,distPath):
	if os.path.exists(distPath):
		shutil.rmtree(distPath)
	os.makedirs(distPath)
	unzip(srcFile,distPath)
	projectPath=None
	for item in os.listdir(distPath):
		if os.path.isdir(os.path.join(distPath,item)):
			projectPath=os.path.join(distPath,item)
	if projectPath is None:
		print("error:unzip unknown error")
		return None
	if srcFile2:
		unzip(srcFile2,projectPath)
	return projectPath
class SrcCheckerDeb:
	def __init__(self,packageInfo:PackageInfo):
		self.packageInfo=packageInfo
		dscLink=packageInfo.dscLink
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'..','..','data',"srcFiles",self.packageInfo.osType,packageInfo.name)
		self.srcBasePath=downloadPath
		self.dscLink=dscLink
		if dscLink=='' or dscLink is None:
			self.srcFile1Path=None
			self.srcFile2Path=None
			return
		log.info("dsc link is "+dscLink)
		
		
		if not os.path.exists(downloadPath):
			os.makedirs(downloadPath)
		
		p = subprocess.Popen("dget "+dscLink, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=downloadPath)
		stdout, stderr = p.communicate()
		zipType=["bz2","gz","lzma","xz"]
		srcFile=None
		srcFile2=None
		for t in zipType:
			fileName=os.path.join(downloadPath,f"{self.packageInfo.name}_{self.packageInfo.version}.orig.tar.{t}")
			if os.path.isfile(fileName):
				srcFile=fileName
				break
		for t in zipType:
			if self.packageInfo.release is None:
				fileName=os.path.join(downloadPath,f"{self.packageInfo.name}_{self.packageInfo.version}.debian.tar.{t}")
			else:
				fileName=os.path.join(downloadPath,f"{self.packageInfo.name}_{self.packageInfo.version}-{self.packageInfo.release}.debian.tar.{t}")
			if os.path.isfile(fileName):
				srcFile2=fileName
				break
		if srcFile is None and srcFile2 is None:
			for t in zipType:
				if self.packageInfo.release is None:
					fileName=os.path.join(downloadPath,f"{self.packageInfo.name}_{self.packageInfo.version}.tar.{t}")
				else:
					fileName=os.path.join(downloadPath,f"{self.packageInfo.name}_{self.packageInfo.version}-{self.packageInfo.release}.tar.{t}")
				if os.path.isfile(fileName):
					srcFile=fileName
					break
		if srcFile is None and srcFile2 is None:
			log.warning("error: no src file in "+downloadPath+" while check package: "+self.packageInfo.dumpAsPurl())
			self.srcFile1Path=None
			self.srcFile2Path=None
			return
		else:
			self.srcFile1Path=srcFile
			self.srcFile2Path=srcFile2

	def getChangeLogFile(self,projectPath):
		
		changeLogFilePath=os.path.join(projectPath,'debian','changelog')
		if not os.path.isfile(changeLogFilePath):
			log.warning("cannot find changelog file in "+changeLogFilePath)
			return ""
		with open(changeLogFilePath) as f:
			data=f.read()
		return data
	def check(self,cves):
		if len(cves)==0:
			return []
		print(cves)
		projectPath=extractSrc(self.srcFile1Path,self.srcFile2Path,os.path.join(self.srcBasePath,'extract'))
		
		cveChecker=CVEChecker(cves)
		cveChecker.checkChangeLog(self.getChangeLogFile(projectPath))
		cveChecker.dfsDir(projectPath)
		return cveChecker