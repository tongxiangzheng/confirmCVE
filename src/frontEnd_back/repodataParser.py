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
		#print(" "+entry.name)
		#for r in res:
			#print("  "+r[0].fullName)
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
class Counter:
	def __init__(self):
		self.cnt=0
	def getId(self)->int:
		self.cnt+=1
		return self.cnt
class TargetCVE:
	def __init__(self):
		self.packageCVE=self.packageCVE=defaultdict(defaultCVEList)
	def addCVE(self,cve,num):
		self.packageCVE[cve]+=num
class SpecificPackage:
	def __init__(self,packageInfo:PackageInfo,fullName:str,provides:list[PackagePointer],requires:list[PackagePointer]):
		self.packageInfo=packageInfo
		self.fullName=fullName
		self.targetCVE=None
		self.providesInfo=provides
		self.requiresInfo=requires
		self.providesPointers=[]
		self.requirePointers=[]
		self.readOnly=False
		self.checking=False
		self.dfn=0
	def addProvidesPointer(self,package,checkReadOnly=True):
		#无需手动调用，addRequirePointer自动处理
		if checkReadOnly==False or self.readOnly==False:
			self.providesPointers.append(package)
			return self
		else:
			pass
			#TODO
	def addRequirePointer(self,package):
		self.requirePointers.append(package)
		package.addProvidesPointer(self)
	def registerProvides(self,entryMap:EntryMap)->None:
		for provide in self.providesInfo:
			entryMap.registerEntry(provide,self)
	def findRequires(self,entryMap:EntryMap)->None:
		requirePackageSet=set()
		
		print(self.fullName)
		for require in self.requiresInfo:
			res=entryMap.queryRequires(require)
			if res is not None and res not in requirePackageSet:
				self.addRequirePointer(res)
				requirePackageSet.add(res)
	def getPackageCVE(self)->None:
		cves=queryPackageCVE(self.packageInfo)
		log.info("parse "+self.packageInfo.name+" , has cve:"+str(cves))
		for cve in cves:
			self.targetCVE.addCVE(cve,1)
	def getAllCVE(self,stack=[])->None:
		log.info("parse:"+self.fullName)
		log.debug(" stack"+str(stack))
		for require in self.requirePointers:
			log.trace(" require: "+require.fullName)
		#if self.checking is True:
		#	log.warning("DAG may not promised, multiple visit: "+self.fullName)
		if self.readOnly is True:
			return
		#self.checking=True
		stack.append(self.fullName)
		self.readOnly=True
		self.getPackageCVE()
		for require in self.requirePointers:
			require.getAllCVE()
			if require.targetCVE==self.targetCVE:
				continue
			for cve,num in require.targetCVE.packageCVE.items():
				self.targetCVE.addCVE(cve,num)
		#self.checking=False
		stack.pop()
	def tarjan(self,counter:Counter,visStack:list):
		self.dfn=counter.getId()
		self.low=self.dfn
		self.checking=True
		visStack.append(self)
		for v in self.requirePointers:
			if v.dfn==0:
				v.tarjan(counter,visStack)
				self.low=min(self.low,v.low)
			elif v.checking is True:
				self.low=min(self.low,v.low)
		if self.dfn==self.low:
			self.targetCVE=TargetCVE()
			#for debug
			if visStack[-1]!=self:
				log.warning("find a loop")
				for cnt in range(1,len(visStack)+1):
					log.info(" "+visStack[-cnt].fullName)
					if visStack[-cnt]==self:
						break

			while True:
				assert len(visStack)>0
				t=visStack[-1]
				visStack.pop()
				t.checking=False
				if t==self:
					break
				t.targetCVE=self.targetCVE
		
		

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
	packageInfo=PackageInfo("centOS",dist,name,version,release)
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
	
	#通过提供的文件和需要文件，解析包之间的依赖关系
	for package in packageMap.values():
		package.findRequires(entryMap)
	return
	#tarjan
	c=Counter()
	for package in packageMap.values():
		if package.dfn==0:
			tarjanStack=[]
			package.tarjan(c,tarjanStack)
			log.info(package.fullName+" dfn :"+str(package.dfn))
			if len(tarjanStack)!=0:
				log.warning("tarjanStack is not empty at end when parse: "+package.fullName)
				for s in tarjanStack:
					log.info(" "+s.fullName+" dfn: "+str(s.dfn)+" low: "+str(s.low))
	for package in packageMap.values():
		if package.checking==True:
			log.warning("package: "+package.fullName+" is not pop from stack")
	#test
	testname='ca-certificates'
	packageMap[testname].getAllCVE()
	print(packageMap[testname].targetCVE.packageCVE)

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
#log.add(sink=logFile,level='TRACE')
parseFile(os.path.join(DIR,"ca039bbfe8297c592cdc0e7251689f5d597771d39b2ddede01106ad0a7f0ba60-primary.xml"))
