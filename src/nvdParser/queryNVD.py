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
        with open(os.path.join(SoftManager.basePath,path),"r") as f:
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
                #print(cpeMatch)
                versionStartIncluding=None
                if 'versionStartIncluding' in cpeMatch:
                    versionStartIncluding=cpeMatch['versionStartIncluding']
                versionStartExcluding=None
                if 'versionStartExcluding' in cpeMatch:
                    versionStartExcluding=cpeMatch['versionStartExcluding']
                versionEndIncluding=None
                if 'versionEndIncluding' in cpeMatch:
                    versionEndIncluding=cpeMatch['versionEndIncluding']
                versionEndExcluding=None
                if 'versionEndExcluding' in cpeMatch:
                    versionEndExcluding=cpeMatch['versionEndExcluding']
                now['expressions'].append((criteria,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding))
            self.nodes.append(now)
    def addRelated(self,package):
        self.collect.append(package)
    def compare(self,version1,version2):
        # -1: version1<version2 0:version1==version2 1:version1>version2
        v1=version1.split('.')
        v2=version2.split('.')
        if len(v1)!=len(v2):
            log.warning("version cannot compare, v1: "+version1+" v2: "+version2)
            return 0
        for i in range(len(v1)):
            if v1[i]<v2[i]:
                return -1
            if v1[i]>v2[i]:
                return -1
        return 0
    def checkMatch(self,cpestr,regex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding,version):
        if regex.match(cpestr) is None:
            return False
        if versionStartIncluding is not None and self.compare(versionStartIncluding,version)>0:
            return False
        if versionStartExcluding is not None and self.compare(versionStartExcluding,version)>=0:
            return False
        if versionEndIncluding is not None and self.compare(version,versionEndIncluding)>0:
            return False
        if versionEndExcluding is not None and self.compare(version,versionEndExcluding)>=0:
            return False
        return True
    def check(self)->bool:
        for node in self.nodes:
            regexs=[]
            for expression,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding in node['expressions']:
                #print(expression)
                expression=expression.replace('.','\\.')
                regexs.append((expression,re.compile(expression),versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding))
                #print("expression: "+expression)
            if node['operator']=='OR':
                for package in self.collect:
                    for expression,regex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding in regexs:
                        info=expression.split(":")
                        name=package.name.lower()
                        if info[4]!=name:
                            continue
                        cpestr="cpe:2.3:a:"+info[3]+":"+name+':'+package.version+":*:*:*:*:*:*:*"
                        #print("cpestr: "+cpestr)
                        if self.checkMatch(cpestr,regex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding,package.version) is True:
                            return True
            elif node['operator']=='AND':
                result=True
                for package in self.collect:
                    for expression,regex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding in regexs:
                        info=expression.split(":")
                        name=package.name.lower()
                        if info[4]!=name:
                            continue
                        cpestr="cpe:2.3:a:"+info[3]+":"+name+':'+package.version+":*:*:*:*:*:*:*"
                        #print("cpestr: "+cpestr)
                        if self.checkMatch(cpestr,regex,versionStartIncluding,versionStartExcluding,versionEndIncluding,versionEndExcluding,package.version) is True:
                            result=False
                if result is True:
                    return True
        return False
def registerPackage(relatedCVE,cvePath,package):
    if cvePath not in relatedCVE:
        relatedCVE[cvePath]=CVEInfo(cvePath)
    cve=relatedCVE[cvePath]
    cve.addRelated(package)

def query(packageList:list): #list[PackageInfo]
    relatedCVE=dict()
    res=dict()
    for package in packageList:
        res[package]=set()
        name=package.name.lower()
        basePath,path=SoftManager.getPath(SoftManager.normalizeName(name))
        if not os.path.isfile(path):
            log.warning("cannot find package: "+package.name)
            continue
        with open(path,"r") as f:
            data=f.readlines()
            for cvePath in data:
                cvePath=cvePath.strip()
                log.trace(package.name+" have cve at "+cvePath)
                registerPackage(relatedCVE,cvePath,package)
    for cve in relatedCVE.values():
        if cve.check():
            log.trace(cve.path+" is active")
            for package in cve.collect:
                res[package].add(cve.cveName)
        else:
            log.trace(cve.path+" is not active")
    
    return res

#p=PackageInfo("centos","el8","NetworkManager","1.0.1","6")
#list=[]
#list.append(p)
#print(query(list))