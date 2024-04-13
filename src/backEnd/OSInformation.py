import os
import json
from loguru import logger as log
class OSInfo:
    def __init__(self,gitLink:str,specfile:str,srcPackageLink:list[str],name:str):
        self.gitLink=gitLink
        if specfile is not None:
	        self.specfile=specfile
        else:
            self.specfile=""
        self.srcPackageLink=srcPackageLink
        self.name=name
class OSInformation:
	def __init__(self):
		indexPath=os.path.join("..","data")
		with open(os.path.join(indexPath,"repositories.json"),"r") as f:
			data=json.load(f)
			self.repositories=data
	def getOsInfo(self,osName:str)->dict:
		info=self.repositories[osName]
		return OSInfo(info['gitLink'],info['specfile'],info['srcPackageLink'],osName)
