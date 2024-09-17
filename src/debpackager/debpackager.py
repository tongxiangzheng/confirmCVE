import os
import tarfile
DIR=os.path.split(os.path.abspath(__file__))[0]

def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
		return f.getmembers()[0].name
def loadFile(filePath):
	with open(filePath,"r") as f:
		data=f.read()
		return data
	
def builddebPackage(origName,projectName,osType,osDist,arch):
	cmd='docker build --output={}/buildinfos --target=buildinfo --build-arg ORIGNAME="{}" --build-arg PROJECTNAME="{}" --build-arg SYSTEM_NAME="{}" --build-arg SYSTEM_VERSION="{}" --build-arg BUILD_ARCH="{}" {}'.format(DIR,origName,projectName,osType,osDist,arch,DIR)
	print(cmd)
	os.system(cmd)
	
def remove_folder(path):
    if os.path.exists(path):
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
        else:
            for filename in os.listdir(path):
                remove_folder(os.path.join(path, filename))
            os.rmdir(path)

def getBuildInfo(srcFile,srcFile2,osType,osDist,arch)->str:
	filesPath=os.path.join(DIR,'files')
	remove_folder(filesPath)
	os.makedirs(filesPath)
	buildInfosPath=os.path.join(DIR,'buildinfos')
	remove_folder(buildInfosPath)
	os.makedirs(buildInfosPath)
	os.system("cp {} {}".format(srcFile,filesPath))
	projectName=unzip(srcFile,filesPath)
	projectPath=os.path.join(filesPath,projectName)
	if srcFile2:
		unzip(srcFile2,projectPath)
	srcFileName=os.path.basename(srcFile)
	builddebPackage(srcFileName,projectName,osType,osDist,arch)

	buildInfoFile=os.path.join(buildInfosPath,"res.info")
	return loadFile(buildInfoFile)

	
