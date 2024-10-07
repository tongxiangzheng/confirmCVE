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
	
def getNameAndVersion(changelogFile):
	print(changelogFile)
	with open(changelogFile) as f:
		changelogInfo = f.read()
		changelogInfo_line=changelogInfo.split('\n',1)
		for info in changelogInfo_line:
			if len(info.strip())>0:
				firstLine=info.split(' ')
				break
		
		name=firstLine[0]
		version_release=firstLine[1][1:-1].split('-')
		version=version_release[0]
		return name,version
def getBuildInfo(srcFile,srcFile2,osType,osDist,arch)->str:
	filesPath=os.path.join(DIR,'files')
	if os.path.isdir(filesPath):
		shutil.rmtree(filesPath)
	os.makedirs(filesPath)
	buildInfosPath=os.path.join(DIR,'buildinfos')
	if os.path.isdir(buildInfosPath):
		shutil.rmtree(buildInfosPath)
	os.makedirs(buildInfosPath)
	#os.system("cp {} {}".format(srcFile,filesPath))
	unzip(srcFile,filesPath)
	projectPath=None
	for item in os.listdir(filesPath):
		if os.path.isdir(os.path.join(filesPath,item)):
			projectPath=os.path.join(filesPath,item)
	if projectPath is None:
		print("error:unzip unknown error")
		return None
	if srcFile2:
		if os.path.isdir(os.path.join(projectPath,"debian")):
			shutil.rmtree(os.path.join(projectPath,"debian"))
		unzip(srcFile2,projectPath)
	name,version=getNameAndVersion(os.path.join(projectPath,"debian","changelog"))
	upstreamTarballFileName=name+"_"+version+".orig.tar."+srcFile.rsplit(".tar.")[1]
	shutil.copyfile(srcFile,os.path.join(filesPath,upstreamTarballFileName))
	projectName=os.path.basename(projectPath)
	builddebPackage(upstreamTarballFileName,projectName,osType,osDist,arch)

	buildInfoFile=os.path.join(buildInfosPath,"res.info")
	data=loadFile(buildInfoFile)
	if data is None:
		return None
	return data
	
