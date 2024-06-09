

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
	with open("ca039bbfe8297c592cdc0e7251689f5d597771d39b2ddede01106ad0a7f0ba60-primary.xml","r") as f:
		doc=xml.dom.minidom.parseString(f.read())
	root=doc.documentElement
	nodelist=root.childNodes
	matchNumber=0
	notMatchNumber=0
	for subnode in nodelist:
		if subnode.nodeType==xml.dom.Node.TEXT_NODE:
			continue
		packageName=parsePackage(subnode)
		if packageName is None:
			continue
		basePath,path=SoftManager.getPath(SoftManager.normalizeName(packageName))
		if not os.path.isfile(path):
			print("not match: "+packageName)
			notMatchNumber+=1
		else:
			print("match: "+packageName)
			matchNumber+=1
	print("match number: "+str(matchNumber))
	print("not match number: "+str(notMatchNumber))
	
		

parseFile()