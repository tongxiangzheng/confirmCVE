import os
import sys
import json
import re
from collections import defaultdict
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
from PackageInfo import PackageInfo
import SoftManager

class CVEInfo:
    def __init__(self,path):
        with open(path,"r") as f:
            data=json.load(f)
        self.cveName=data['id']
        self.path=path
        self.collect=[]
        self.nodes=[]
        if 'configurations' not in data:
            #log.warning("file "+path+" have no configurations info")
            return None
        configurations=data['configurations']
        for configure in configurations:
            node=configure['nodes'][0]
            now=dict()
            now['operator']=node['operator']
            now['expressions']=[]
            for cpeMatch in node['cpeMatch']:
                #if cpeMatch['vulnerable'] is False:
                criteria=cpeMatch['criteria']
                now['expressions'].append(criteria)
            self.nodes.append(now)
    def addRelated(self,package):
        self.collect.append(package)
    def check(self)->bool:
        for node in self.nodes:
            regexs=[]
            for expression in node['expressions']:
                expression=expression.replace('.','\\.')
                regexs.append((expression,re.compile(expression)))
                #print("expression: "+expression)
            if node['operator']=='OR':
                for package in self.collect:
                    for regex in regexs:
                        expression=regex[0]
                        info=expression.split(":")
                        name=package.name.lower()
                        if info[4]!=name:
                            continue
                        cpestr="cpe:2.3:a:"+info[3]+":"+name+':'+package.version+":*:*:*:*:*:*:*"
                        #print("cpestr: "+cpestr)
                        if regex[1].match(cpestr) is not None:
                            return True
            elif node['operator']=='AND':
                result=True
                for package in self.collect:
                    for regex in regexs:
                        expression=regex[0]
                        info=expression.split(":")
                        name=package.name.lower()
                        if info[4]!=name:
                            continue
                        cpestr="cpe:2.3:a:"+info[3]+":"+name+':'+package.version+":*:*:*:*:*:*:*"
                        #print("cpestr: "+cpestr)
                        if regex[1].match(cpestr) is not None:
                            result=False
                if result is True:
                    return True
        return False
def registerPackage(relatedCVE,cvePath,package):
    if cvePath not in relatedCVE:
        relatedCVE[cvePath]=CVEInfo(cvePath)
    cve=relatedCVE[cvePath]
    cve.addRelated(package)

def query(packageList:list[PackageInfo]):
    relatedCVE=dict()
    res=dict()
    for package in packageList:
        res[package]=[]
        name=package.name.lower()
        basePath,path=SoftManager.getPath(SoftManager.normalizeName(name))
        if not os.path.isfile(path):
            log.warning("cannot find package: "+package.name)
            continue
        with open(path,"r") as f:
            data=f.readlines()
            for cvePath in data[1:]:
                cvePath=cvePath.strip()
                log.trace(package.name+" have cve at "+cvePath)
                registerPackage(relatedCVE,cvePath,package)
    for cve in relatedCVE.values():
        if cve.check():
            log.trace(cve.path+" is active")
            for package in cve.collect:
                res[package].append(cve.cveName)
        else:
            log.trace(cve.path+" is not active")
    
    return res

#p=PackageInfo("centos","el8","NetworkManager","1.0.1","6")
#list=[]
#list.append(p)
#print(query(list))