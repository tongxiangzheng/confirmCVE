import os
import json
from loguru import logger as log
from PackageInfo import PackageInfo
class OSInfo:
	def __init__(self,gitLink:str,specfile:str,srcPackageLink:list[str],name:str):
		self.gitLink=gitLink
		self.specfile=specfile
		self.srcPackageLink=srcPackageLink
		self.name=name
class OSInformation:
	def __init__(self):
		indexPath=os.path.join("..","data")
		with open(os.path.join(indexPath,"repositories.json"),"r") as f:
			data=json.load(f)
			self.repositories=data
	def getOsInfo(self,packageInfo:PackageInfo)->dict:
		info=self.repositories[packageInfo.osType]
		if 'srcPackageLink' not in info:
			info['srcPackageLink']=[]
		if 'specfile' not in info:
			info['specfile']=""
		return OSInfo(info['gitLink'],info['specfile'],info['srcPackageLink'],packageInfo.osType)
