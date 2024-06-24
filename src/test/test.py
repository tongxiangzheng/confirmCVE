

import xml.dom.minidom
import os
import sys
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import SoftManager
machineArch={"x86_64","noarch"}
def parsePackage(node:xml.dom.minidom.Element):
	fullName=node.getElementsByTagName('name')[0].firstChild.nodeValue
	sourcerpm=node.getElementsByTagName('rpm:sourcerpm')[0].firstChild.nodeValue
	versionNode=node.getElementsByTagName('version')[0]
	version=versionNode.getAttribute('ver')
	name=sourcerpm.split('-'+version)[0]
	releaseRaw=versionNode.getAttribute('rel')
	release=releaseRaw.split('.')[0]
	dist=releaseRaw.split('.')[-1]
	arch=node.getElementsByTagName('arch')[0].firstChild.nodeValue
	if arch not in machineArch:
		return None
	return name
	
def parseFile():
	matchNumber=0
	notMatchNumber=0
	matchSet=set()
	nonMatchSet=set()
	files=["ca039bbfe8297c592cdc0e7251689f5d597771d39b2ddede01106ad0a7f0ba60-primary.xml",
		"d8472d61c5e53a3e9cbffb68e0dddbd04a07c2b7d864b07ddd211c6ad1380c6e-primary.xml"]
	
	#files=["3a7ec7ec6f40977fbeb8308388129eb948f04c173338e60e501f598e135efcee-primary.xml",
	#"f0b24cf02e03658f80290c59c5be0a3f0ee2b7b0a8c6b54e81d4fa9aaa0051f1-primary.xml"]
	cnt=0
	for file in files:
		with open(file,"r") as f:
			doc=xml.dom.minidom.parseString(f.read())
		root=doc.documentElement
		nodelist=root.childNodes
		for subnode in nodelist:
			if subnode.nodeType==xml.dom.Node.TEXT_NODE:
				continue
			packageName=parsePackage(subnode)
			if packageName is None:
				continue
			cnt+=1
			if packageName in matchSet or packageName in nonMatchSet:
				continue
			basePath,path=SoftManager.getPath(SoftManager.normalizeName(packageName))
			if os.path.isfile(path):
				print("match: "+packageName)
				matchSet.add(packageName)
			else:
				print("not match: "+packageName)
				nonMatchSet.add(packageName)
				
	print("package total number: "+str(cnt))
	print("match number: "+str(len(matchSet)))
	print("not match number: "+str(len(nonMatchSet)))
	with open("matchSet.txt","w") as f:
		for packageName in matchSet:
			f.write(packageName+"\n")
	with open("nonMatchSet.txt","w") as f:
		for packageName in nonMatchSet:
			f.write(packageName+"\n")
	
	
		

parseFile()