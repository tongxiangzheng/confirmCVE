import os
import tarfile
import shutil
import pyzstd
from subprocess import PIPE, Popen
DIR=os.path.split(os.path.abspath(__file__))[0]

def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
def loadFile(filePath):
	if os.path.isfile(filePath):
		with open(filePath,"r") as f:
			data=f.read()
			return data
	return None
def builddebPackage(srcFileName,osType,osDist,arch):
	cmd=f'docker build --output={DIR}/buildinfos --target=buildinfo --build-arg ORIGNAME="{srcFileName}" --build-arg SYSTEM_NAME="{osType}" --build-arg SYSTEM_VERSION="{osDist}" --build-arg BUILD_ARCH="{arch}" {DIR}'
	print(cmd)
	os.system(cmd)
	# p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
	# stdout, stderr = p.communicate()


#将操作系统名称更改为可以docker pull的docker仓库的名称
dockerOsTypeMap={"openeuler":"openeuler/openeuler"}

def getBuildInfo(srcFile,osType,osDist,arch)->str:
	filesPath=os.path.join(DIR,'files')
	if os.path.isdir(filesPath):
		shutil.rmtree(filesPath)
	os.makedirs(filesPath)
	buildInfosPath=os.path.join(DIR,'buildinfos')
	if os.path.isdir(buildInfosPath):
		shutil.rmtree(buildInfosPath)
	os.makedirs(buildInfosPath)
	srcFileName=os.path.basename(srcFile)
	shutil.copyfile(srcFile,os.path.join(filesPath,srcFileName))
	osType=osType.lower()
	if osType in dockerOsTypeMap:
		osType=dockerOsTypeMap[osType]
	builddebPackage(srcFileName,osType,osDist,arch)
	for file in os.listdir(buildInfosPath):
		if not file.endswith('-primary.xml.zst'):
			continue
		buildInfoFile=os.path.join(buildInfosPath,file)
		with open(buildInfoFile, "rb") as f:
			data = f.read()
			data = pyzstd.decompress(data).decode()
			return data
	return None
	
