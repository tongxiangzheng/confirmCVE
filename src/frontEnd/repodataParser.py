import xml.dom.minidom
import os
from dom_tool import sub2dict

def parsePackage(node):
	pass
	

def parseFile(fromPath):
	doc=xml.dom.minidom.parse(fromPath)
	root=doc.documentElement
	nodelist=root.childNodes
	for subnode in nodelist:
		if subnode.nodeType==xml.dom.Node.TEXT_NODE:
			continue
		parsePackage(subnode)
		
DIR=os.path.split(os.path.abspath(__file__))[0]
parseFile(os.path.join(DIR,"339ea1b58f3246e5a9af782ce0c8f9141d0670b7954b46432ab150b715fc00ad-primary.xml"))
