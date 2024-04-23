import xml.dom.minidom
import os
import sys
from collections import defaultdict
from loguru import logger as log
from dom_tool import sub2dict,dfs
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
from PackageInfo import PackageInfo
from queryPackageCVE import queryPackageCVE
class PackagePointer:
	def __init__(self,name:str,flags:str,version:str,release:str|None):
		self.name=name
		self.flags=flags
		self.version=version
		self.release=release
def defaultNoneList():
	return []
class EntryMap:
	def __init__(self):
		self.provideEntryPackages=defaultdict(defaultNoneList)
		self.updateEntrys=dict()
	def registerEntry(self,entry:PackagePointer,package):
		self.provideEntryPackages[entry.name].append((package,entry))
	def copy(self):
		newMap=EntryMap()
		newMap.provideEntryPackages=self.provideEntryPackages
		return newMap
	def queryRequires(self,entry:PackagePointer):
		res=self.provideEntryPackages[entry.name]
		if len(res)!=1:
			if len(res)==0:
				""
				#log.warning("no package provide the require file: "+entry.name)
			else:
				#log.warning("require file: "+entry.name+" is provide by more than one package")
				""
			return None
		#TODO:check res[0][1] is match
		return res[0][0]
def defaultCVEList():
	return 0
class SpecificPackage:
	def __init__(self,packageInfo:PackageInfo,fullName:str,provides:list[PackagePointer],requires:list[PackagePointer]):
		self.packageInfo=packageInfo
		self.fullName=fullName
		self.packageCVE=self.packageCVE=defaultdict(defaultCVEList)
		self.providesInfo=provides
		self.requiresInfo=requires
		self.providesPointers=[]
		self.requirePointers=[]
		self.readOnly=False
		self.checking=False
	def addProvidesPointer(self,package,checkReadOnly=True):
		#无需手动调用，addRequirePointer自动处理
		if checkReadOnly==False or self.readOnly==False:
			self.providesPointers.append(package)
			return self
		else:
			pass
	def addRequirePointer(self,package):
		self.requirePointers.append(package)
		package.addProvidesPointer(self)
	def registerProvides(self,entryMap:EntryMap)->None:
		for provide in self.providesInfo:
			entryMap.registerEntry(provide,self)
	def findRequires(self,entryMap:EntryMap)->None:
		requirePackageSet=set()
		for require in self.requiresInfo:
			res=entryMap.queryRequires(require)
			if res is not None and res not in requirePackageSet:
				self.addRequirePointer(res)
				requirePackageSet.add(res)
	def getPackageCVE(self)->None:
		cves=queryPackageCVE(self.packageInfo)
		log.info("parse "+self.packageInfo.name+" , has cve:"+str(cves))
		for cve in cves:
			self.packageCVE[cve]+=1
	def getAllCVE(self,stack=[])->None:
		log.info("parse:"+self.fullName)
		log.debug(" stack"+str(stack))
		for require in self.requirePointers:
			log.trace(" require: "+require.fullName)
		if self.checking is True:
			log.warning("DAG may not promised, multiple visit: "+self.fullName)
		if self.readOnly is True:
			return
		self.checking=True
		stack.append(self.fullName)
		self.readOnly=True
		self.getPackageCVE()
		for require in self.requirePointers:
			require.getAllCVE()
			for cve,num in require.packageCVE.items():
				self.packageCVE[cve]+=num
		self.checking=False
		stack.pop()
		

def parseEntry(node:xml.dom.minidom.Element)->list[PackagePointer]:
	nodelist=node.childNodes
	res=[]
	for subnode in nodelist:
		if subnode.nodeType==xml.dom.Node.TEXT_NODE:
			continue
		name=subnode.getAttribute('name')
		flags="GE"
		if subnode.hasAttribute('flags'):
			flags=subnode.getAttribute('flags')
		version="0"
		if subnode.hasAttribute('ver'):
			version=subnode.getAttribute('ver')
		release=None
		if subnode.hasAttribute('rel'):
			release=subnode.getAttribute('rel').split('.')[0]
		res.append(PackagePointer(name,flags,version,release))
	return res
def parsePackage(node:xml.dom.minidom.Element)->SpecificPackage:
	fullName=node.getElementsByTagName('name')[0].firstChild.nodeValue
	sourcerpm=node.getElementsByTagName('rpm:sourcerpm')[0].firstChild.nodeValue
	versionNode=node.getElementsByTagName('version')[0]
	version=versionNode.getAttribute('ver')
	name=sourcerpm.split('-'+version)[0]
	releaseRaw=versionNode.getAttribute('rel')
	release=releaseRaw.split('.')[0]
	dist=releaseRaw.split('.')[-1]
	provides=[]
	res=node.getElementsByTagName('rpm:provides')
	if len(res)!=0:
		provides=parseEntry(res[0])
	requires=[]
	res=node.getElementsByTagName('rpm:requires')
	if len(res)!=0:
		requires=parseEntry(res[0])
	packageInfo=PackageInfo("openEuler",dist,name,version,release)
	return SpecificPackage(packageInfo,fullName,provides,requires)
	
	
def parseFile(fromPath):
	doc=xml.dom.minidom.parse(fromPath)
	root=doc.documentElement
	nodelist=root.childNodes
	entryMap=EntryMap()
	packageMap=dict()
	for subnode in nodelist:
		if subnode.nodeType==xml.dom.Node.TEXT_NODE:
			continue
		package=parsePackage(subnode)
		package.registerProvides(entryMap)
		packageMap[package.fullName]=package
	for package in packageMap.values():
		package.findRequires(entryMap)
	
	#test
	testname='python3-inotify'
	packageMap[testname].getAllCVE()
	print(packageMap[testname].packageCVE)

DIR=os.path.split(os.path.abspath(__file__))[0]
log.remove(handler_id=None)
logFile=DIR+"log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='TRACE')
parseFile(os.path.join(DIR,"339ea1b58f3246e5a9af782ce0c8f9141d0670b7954b46432ab150b715fc00ad-primary.xml"))
