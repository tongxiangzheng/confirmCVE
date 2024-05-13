import os
import sys
import json
import re
from loguru import logger as log
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
from PackageInfo import PackageInfo
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
    def check(self):
        for node in self.nodes:
            regexs=[]
            for expression in node['expressions']:
                expression=expression.replace('.','\\.')
                regexs.append((expression,re.compile(expression)))
                print("expression: "+expression)
            if node['operator']=='OR':
                for package in self.collect:
                    for regex in regexs:
                        expression=regex[0]
                        info=expression.split(":")
                        if info[4]!=package.name:
                            continue
                        cpestr="cpe:2.3:a:"+info[3]+":"+package.name+':'+package.version+":*:*:*:*:*:*:*"
                        print("cpestr: "+cpestr)
                        if regex[1].match(cpestr) is not None:
                            return True
            elif node['operator']=='AND':
                result=True
                for package in self.collect:
                    cpestr="cpe:2.3:a:*:"+package.name+':'+package.version+":*:*:*:*:*:*:*"
                    print("cpestr: "+cpestr)
                    for regex in regexs:
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
    for package in packageList:
        path=os.path.join(DIR,'package_cve',package.name[0],package.name)
        if not os.path.isfile(path):
            log.warning("cannot find package: "+package.name)
            continue
        with open(path,"r") as f:
            data=f.readlines()
            for cvePath in data:
                cvePath=cvePath.strip()
                registerPackage(relatedCVE,cvePath,package)
    for cve in relatedCVE.values():
        print(cve.check())
p=PackageInfo("centos","el8","apr-util","1.0.1","6")
list=[]
list.append(p)
query(list)