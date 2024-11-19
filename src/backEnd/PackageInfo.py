import json
class PackageInfo:
	def __init__(self,osKind:str,osType:str,dist:str,name:str,version:str,release:str,dscLink=None):
		self.osKind=osKind.lower()
		self.osType=osType
		self.dist=dist
		self.name=name
		self.dscLink=dscLink
		self.version=version
		self.release=release
	def dump(self):
		info={'osType':self.osType,'dist':self.dist,'name':self.name,'version':self.version,'release':self.release}
		if self.dscLink is not None:
			info['dscLink']=self.dscLink
		return json.dumps(info)
	def dumpAsPurl(self):
		release=self.release
		if self.dscLink is not None:
			return 'pkg:'+self.osKind+'/'+self.osType+'/'+self.name+'@'+self.version+'-'+release+'.'+self.dist
		else:
			return 'pkg:'+self.osKind+'/'+self.osType+'/'+self.name+'@'+self.version+'-'+release+'.'+self.dist+"&"+"dscLink="+self.dscLink

def loadPackageInfo(jsonInfo):
	#abandon
	osType=jsonInfo['osType']
	if osType=='deb':
		gitLink=jsonInfo['gitLink']
	else:
		gitLink=None
	dist=jsonInfo['dist']
	name=jsonInfo['name']
	version=jsonInfo['version']
	release=jsonInfo['release']
	return PackageInfo("",osType,dist,name,version,release,gitLink)

def loadPurl(purlStr):
	info=purlStr.split(':',1)[1]
	info_extra=info.split('?')
	info=info_extra[0].split('/')
	osKind=info[0]
	osType=info[1]
	name=info[2].split('@')[0]
	version_dist=info[2].split('@')[1].rsplit('.',1)
	version_release=version_dist[0].rsplit('-',1)
	version=version_release[0]
	release=None
	if len(version_release)>1:
		release=version_release[1]
	dist=""
	print(version_dist)
	if len(version_dist)>1:
		dist=version_dist[1]
	dscLink=""
	if len(info_extra)>1:
		extraInfo=info_extra[1]
		for extra in extraInfo.split('&'):
			ei=extra.split('=')
			if ei[0]=='dscLink':
				dscLink=ei[1]
	return PackageInfo(osKind,osType,dist,name,version,release,dscLink)