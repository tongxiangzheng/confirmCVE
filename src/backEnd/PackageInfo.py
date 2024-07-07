import json
class PackageInfo:
	def __init__(self,osType:str,dist:str,name:str,version:str,release:str,gitLink=None):
		self.osType=osType
		self.dist=dist
		self.name=name
		self.gitLink=gitLink
		id=version.find('p')
		if id==-1:
			self.update=None
			self.version=version
		else:
			self.update=version[id:]
			self.version=version[0:id]
			#print(version,self.version,self.update)
		self.release=release
	def dump(self):
		info={'osType':self.osType,'dist':self.dist,'name':self.name,'version':self.version,'release':self.release}
		if self.update is not None:
			info['update']=self.update
		if self.gitLink is not None:
			info['gitLink']=self.gitLink
		return json.dumps(info)
		

def loadPackageInfo(jsonInfo):
	osType=jsonInfo['osType']
	if osType=='deb':
		gitLink=jsonInfo['gitLink']
	else:
		gitLink=None
	dist=jsonInfo['dist']
	name=jsonInfo['name']
	version=jsonInfo['version']
	if 'update' in jsonInfo:
		version=version+'p'+jsonInfo['update']
	release=jsonInfo['release']
	return PackageInfo(osType,dist,name,version,release,gitLink)