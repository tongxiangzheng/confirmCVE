import os
import tarfile


def unzip(zipfile,toPath):
	with tarfile.open(zipfile) as f:
		f.extractall(toPath)
		return f.getmembers()[0].name



def getBuildInfo(srcFile,srcFile2,osType,osDist,arch):
	os.system("cp {} files".format(srcFile))
	projectName=unzip(srcFile,"files")
	projectPath=os.path.join("files",projectName)
	if srcFile2:
		unzip(srcFile2,projectPath)
	
