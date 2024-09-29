import os
import tarfile
import shutil
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
def builddebPackage(origName,projectName,osType,osDist,arch):
	cmd='docker build --output={}/buildinfos --target=buildinfo --build-arg ORIGNAME="{}" --build-arg PROJECTNAME="{}" --build-arg SYSTEM_NAME="{}" --build-arg SYSTEM_VERSION="{}" --build-arg BUILD_ARCH="{}" {}'.format(DIR,origName,projectName,osType,osDist,arch,DIR)
	print(cmd)
	os.system(cmd)
	

def getBuildInfo(srcFile,srcFile2,osType,osDist,arch)->str:
	filesPath=os.path.join(DIR,'files')
	if os.isdir(filesPath):
		shutil.rmtree(filesPath)
	os.makedirs(filesPath)
	buildInfosPath=os.path.join(DIR,'buildinfos')
	if os.isdir(buildInfosPath):
		shutil.rmtree(buildInfosPath)
	os.makedirs(buildInfosPath)
	os.system("cp {} {}".format(srcFile,filesPath))
	unzip(srcFile,filesPath)
	projectPath=None
	for item in os.listdir(filesPath):
		if os.path.isdir(os.path.join(filesPath,item)):
			projectPath=os.path.join(filesPath,item)
	if projectPath is None:
		print("error:unzip unknown error")
		return None
	projectName=os.path.basename(projectPath)
	if srcFile2:
		if os.path.isdir(os.path.join(projectPath,"debian")):
			shutil.rmtree(os.path.join(projectPath,"debian"))
		unzip(srcFile2,projectPath)
	srcFileName=os.path.basename(srcFile)
	builddebPackage(srcFileName,projectName,osType,osDist,arch)

	buildInfoFile=os.path.join(buildInfosPath,"res.info")
	data=loadFile(buildInfoFile)
	if data is None:
		return None
	return data
	
