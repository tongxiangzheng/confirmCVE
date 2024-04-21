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
				log.warning("no package provide the require file: "+entry.name)
			else:
				#log.warning("require file: "+entry.name+" is provide by more than one package")
				""
			return None
		#TODO:check res[0][1] is match
		return res[0][0]
class SpecificPackage:
	def __init__(self,packageInfo:PackageInfo,provides:list[PackagePointer],requires:list[PackagePointer]):
		self.packageInfo=packageInfo
		self.providesInfo=provides
		self.requiresInfo=requires
		self.providesPointers=[]
		self.requirePointers=[]
		self.readOnly=False
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
		for require in self.requiresInfo:
			res=entryMap.queryRequires(require)
			if res is not None:
				self.addRequirePointer(res)
		

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
			version=subnode.getAttribute('rel').split('.')[0]
		res.append(PackagePointer(name,flags,version,release))
	return res
def parsePackage(node:xml.dom.minidom.Element)->SpecificPackage:
	name=node.getElementsByTagName('name')[0].firstChild.nodeValue
	versionNode=node.getElementsByTagName('version')[0]
	version=versionNode.getAttribute('ver')
	releaseRaw=versionNode.getAttribute('rel')
	release=releaseRaw.split('.')[0]
	dist=releaseRaw.split('.')[1]
	provides=[]
	res=node.getElementsByTagName('rpm:provides')
	if len(res)!=0:
		provides=parseEntry(res[0])
	requires=[]
	res=node.getElementsByTagName('rpm:requires')
	if len(res)!=0:
		requires=parseEntry(res[0])
	packageInfo=PackageInfo("openEuler",dist,name,version,release)
	return SpecificPackage(packageInfo,provides,requires)
	
	
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
		packageMap[package.packageInfo.name]=package
	for package in packageMap.values():
		package.findRequires(entryMap)
		
DIR=os.path.split(os.path.abspath(__file__))[0]
#parseFile(os.path.join(DIR,"little.xml"))
parseFile(os.path.join(DIR,"339ea1b58f3246e5a9af782ce0c8f9141d0670b7954b46432ab150b715fc00ad-primary.xml"))
