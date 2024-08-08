import os
import json
import re
from loguru import logger as log
from PackageInfo import PackageInfo
class OSInfo:
	def __init__(self,type:str,gitLink:str,specfile:str,srcPackageLink:list[str],name:str,branch:str):
		self.type=type
		self.gitLink=gitLink
		self.specfile=specfile
		self.srcPackageLink=srcPackageLink
		self.name=name
		self.branch=branch
class OSInformation:
	def __init__(self):
		DIR = os.path.split(os.path.abspath(__file__))[0]
		indexPath=os.path.join(DIR,"data")
		with open(os.path.join(indexPath,"repositories.json"),"r") as f:
			data=json.load(f)
			self.repositories=data
		with open(os.path.join(indexPath,"branchMap.json"),"r") as f:
			data=json.load(f)
			self.branchmap=data
	def getOsInfo(self,packageInfo:PackageInfo)->OSInfo:
		info=self.repositories[packageInfo.osType]
		if 'srcPackageLink' not in info:
			info['srcPackageLink']=[]
		if 'specfile' not in info:
			info['specfile']=""
		gitLink=None
		if 'gitLink' in info:
			for link, linkMatch in info['gitLink'].items():
				for m in linkMatch:
					if re.search(m,packageInfo.dist) is not None:
						gitLink=link
						break
				if gitLink is not None:
					break
		branch=None
		try:
			branch=self.branchmap[packageInfo.osType][packageInfo.dist]
		except Exception as e:
			pass
		return OSInfo(info['type'],gitLink,info['specfile'],info['srcPackageLink'],packageInfo.osType,branch)
