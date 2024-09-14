import os
import tarfile


def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
		return f.getmembers()[0].name
def loadFile(filePath):
	with open(filePath,"r") as f:
		data=f.read()
		return data
	
def builddebPackage(origName,projectName,osType,osDist,arch):
	cmd='docker build --output=./buildinfos --target=buildinfo --build-arg ORIGNAME="{}" --build-arg PROJECTNAME="{}" --build-arg SYSTEM_NAME="{}" --build-arg SYSTEM_VERSION="{}" --build-arg BUILD_ARCH="{}" .'.format(origName,projectName,osType,osDist,arch)
	os.system(cmd)
	

def getBuildInfo(srcFile,srcFile2,osType,osDist,arch):
	os.system("rm files -rf")
	os.system("mkdir files")
	os.system("rm buildinfos -rf")
	os.system("mkdir buildinfos")
	os.system("cp {} files".format(srcFile))
	projectName=unzip(srcFile,"files/")
	projectPath=os.path.join("files",projectName)
	if srcFile2:
		unzip(srcFile2,projectPath)
	srcFileName=os.path.basename(srcFile)
	builddebPackage(srcFileName,projectName,osType,osDist,arch)
	buildInfosPath='buildinfos'
	res=[]
	for file in os.listdir(buildInfosPath):
		if os.path.isfile(os.path.join(buildInfosPath, file)):
			buildInfoFile=os.path.join(buildInfosPath,file)
			res.append(loadFile(buildInfoFile))
	return res

	
