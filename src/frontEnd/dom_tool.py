from collections import defaultdict

def dfs(now,len):
	for i in range(len):
		print(' ',end='')
	print("type=",now.nodeType,"name=",now.nodeName,",value=",now.nodeValue)
	for child in now.childNodes:
		dfs(child,len+1)

class Counter:
	def __init__(self):
		self.id=0
	def getId(self):
		ans=str(self.id)
		self.id+=1
		return ans

def defaultNoneList():
	return []

def sub2dict(node):
	subDict=defaultdict(defaultNoneList)
	nodelist=node.childNodes
	for subnode in nodelist:
		name=subnode.nodeName
		subDict[name].append(subnode)
	return subDict