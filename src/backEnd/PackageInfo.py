import json
class PackageInfo:
	def __init__(self,osType:str,dist:str,name:str,version:str,release:str):
		self.osType=osType
		self.dist=dist
		self.name=name
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
		return json.dumps(info)
		

def loadPackageInfo(info):
	osType=info['osType']
	dist=info['dist']
	name=info['name']
	version=info['version']
	release=info['release']
	if 'update' in info:
		return PackageInfo(osType,dist,name,version+'p'+info['update'],release)
	else:
		return PackageInfo(osType,dist,name,version,release)