import os
import shutil
import tarfile
import gzip
import subprocess
from loguru import logger as log
from CVEChecker import CVEChecker
from PackageInfo import PackageInfo
from OSInformation import OSInformation
import nwkTools

def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
def unzip_gz(zipfile,toPath):
	distPath=os.path.join(toPath,os.path.basename(zipfile).rsplit(".",1)[0])
	with gzip.open(zipfile, 'rb') as f_in:
		with open(distPath, 'wb') as f_out:
			shutil.copyfileobj(f_in, f_out)
	return distPath
def extractSrc(srcFile,srcFile2,srcFormat,distPath):
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
		if srcFormat=='3.0':
			unzip(srcFile2,projectPath)
		elif srcFormat=='1.0':
			diffFile=unzip_gz(srcFile2,distPath)
			p = subprocess.Popen(f"patch -p1 -i {diffFile}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=projectPath)
			stdout, stderr = p.communicate()
			
	return projectPath

def parseDscFile(dscFilePath):
	with open(dscFilePath,"r") as f:
		data=f.readlines()
	in_files=False
	files=[]
	for info in data:
		if info.startswith("Files:"):
			in_files=True
			continue
		if in_files is False:
			continue
		if info.startswith(" "):
			info=info.strip().split(' ')
			files.append(info[2])
		else:
			break
	return files

class SrcCheckerDeb:
	def __init__(self,packageInfo:PackageInfo):
		self.packageInfo=packageInfo
		dscLink=packageInfo.dscLink
		DIR = os.path.split(os.path.abspath(__file__))[0]
		downloadPath = os.path.join(DIR,'..','..','data',"srcFiles",self.packageInfo.osType,packageInfo.name)
		self.srcBasePath=downloadPath
		self.dscLink=dscLink
		self.srcFile1Path=None
		self.srcFile2Path=None
		self.srcFormat=""
		if dscLink=='' or dscLink is None:
			return
		#log.info("dsc link is "+dscLink)
		
		
		# if not os.path.exists(downloadPath):
		# 	os.makedirs(downloadPath)
		# p = subprocess.Popen("dget "+dscLink, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,cwd=downloadPath)
		# stdout, stderr = p.communicate()
		# 为避免依赖dget，使用以下方式手动实现dget功能

		dscFilePath=nwkTools.downloadFile(dscLink,downloadPath,dscLink.rsplit("/",1)[-1])
		if dscFilePath is None:
			log.warning("failed to download dsc file: "+dscLink)
			return
		srcFiles=parseDscFile(dscFilePath)
		for fi in srcFiles:
			nwkTools.downloadFile(dscLink.rsplit("/",1)[0]+'/'+fi,downloadPath,fi)
		zipType=["bz2","gz","lzma","xz"]
		srcFile=None
		srcFile2=None
		name=self.packageInfo.name
		version=self.packageInfo.version.split(":")[-1]
		for t in zipType:
			fileName=os.path.join(downloadPath,f"{name}_{version}.orig.tar.{t}")
			if os.path.isfile(fileName):
				srcFile=fileName
				break
		for t in zipType:
			if self.packageInfo.release is None:
				fileName=os.path.join(downloadPath,f"{name}_{version}.debian.tar.{t}")
			else:
				fileName=os.path.join(downloadPath,f"{name}_{version}-{self.packageInfo.release}.debian.tar.{t}")
			if os.path.isfile(fileName):
				srcFile2=fileName
				self.srcFormat="3.0"
				break
		if srcFile2 is None:
			for t in zipType:
				if self.packageInfo.release is None:
					fileName=os.path.join(downloadPath,f"{name}_{version}.diff.{t}")
				else:
					fileName=os.path.join(downloadPath,f"{name}_{version}-{self.packageInfo.release}.diff.{t}")
				if os.path.isfile(fileName):
					srcFile2=fileName
					self.srcFormat="1.0"
					break
		if srcFile is None and srcFile2 is None:
			for t in zipType:
				if self.packageInfo.release is None:
					fileName=os.path.join(downloadPath,f"{name}_{version}.tar.{t}")
				else:
					fileName=os.path.join(downloadPath,f"{name}_{version}-{self.packageInfo.release}.tar.{t}")
				if os.path.isfile(fileName):
					srcFile=fileName
					break
		if srcFile is None and srcFile2 is None:
			log.warning("error: no src file in "+downloadPath+" while check package: "+self.packageInfo.dumpAsPurl())
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
		cveChecker=CVEChecker(cves)
		if len(cves)==0:
			return cveChecker
		if self.srcFile1Path is None:
			return cveChecker
		projectPath=extractSrc(self.srcFile1Path,self.srcFile2Path,self.srcFormat,os.path.join(self.srcBasePath,'extract'))
		
		cveChecker.checkChangeLog(self.getChangeLogFile(projectPath))
		cveChecker.dfsDir(projectPath)
		return cveChecker