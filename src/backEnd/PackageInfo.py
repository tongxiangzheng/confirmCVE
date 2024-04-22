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
		
