import os
import json
from loguru import logger as log
ignoredVulnStatus={'Rejected','Awaiting Analysis','Received','Undergoing Analysis'}
class CVEInfo:
    def __init__(self,path):
        with open(path,"r") as f:
            data=json.load(f)
        self.cveName=data['id']
        self.path=path
        self.collect=[]
        self.effective=True
        vulnStatus=data['vulnStatus']
        if vulnStatus in ignoredVulnStatus:
            self.effective=False
            return None
        if 'configurations' not in data:
            #log.warning("file "+path+" have no configurations info")
            self.effective=False
            return None
        configurations=data['configurations']
        for configure in configurations:
            node=configure['nodes'][0]
            for cpeMatch in node['cpeMatch']:
                #if cpeMatch['vulnerable'] is False:
                criteria=cpeMatch['criteria']
                info=criteria.split(':')
                part=info[2]
                #part的值：a（应用程序）、h（硬件平台）、o（操作系统），仅处理应用程序操作系统
                if part != 'a' and part != 'o':
                    continue
                cpename=info[4]
                self.collect.append(cpename)
DIR = os.path.split(os.path.abspath(__file__))[0]
class Soft:
    def normalizeName(self,name:str):
        return name.replace('/','_slash_')
    def __init__(self,name:str):
        name=self.normalizeName(name)
        self.name=name
        pathBase=os.path.join(DIR,'package_cve',name[0])
        if not os.path.exists(pathBase):
            os.makedirs(pathBase)
        self.path=os.path.join(pathBase,name)
        self.items=[]
        #if os.path.isfile(self.path):
        #    with open(self.path,"r") as f:
        #        self.items=f.readlines()
        self.changed=False
    def add(self,item):
        self.items.append(item)
        self.changed=True
    def remove(self,item):
        self.items.remove(item)
        self.changed=True
    def dump(self):
        if self.changed is False:
            return
        with open(self.path,"w") as f:
            for i in self.items:
                f.write(i+"\n")
        self.changed=False
class SoftManager:
    def __init__(self):
        self.softCache=dict()
    def dump(self):
        for soft in self.softCache.values():
            soft.dump()
    def addItem(self,softName,item):
        if softName not in self.softCache:
            self.softCache[softName]=Soft(softName)
        soft=self.softCache[softName]
        soft.add(item)
    def removeItem(self,softName,item):
        if softName not in self.softCache:
            self.softCache[softName]=Soft(softName)
        soft=self.softCache[softName]
        soft.remove(item)
    def registerCVE(self,cveInfo:CVEInfo):
        for softName in cveInfo.collect:
            self.addItem(softName,cveInfo.path)
    def unRegisterCVE(self,cveInfo:CVEInfo):
        for softName in cveInfo.collect:
            self.removeItem(softName,cveInfo.path)
def build():
    basePath=os.path.join(DIR,'nvd-json-data-feeds')
    softManager=SoftManager()
    for year in os.listdir(basePath):
        yearPath=os.path.join(basePath,year)
        if os.path.isfile(yearPath):
            continue
        if year.startswith('.') or year.startswith('_'):
            continue
        #if year!='CVE-1999':
        #    continue    #小规模测试
        for cves in os.listdir(yearPath):
            cvesPath=os.path.join(yearPath,cves)
            for cve in os.listdir(cvesPath):
                cvePath=os.path.join(cvesPath,cve)
                cveInfo=CVEInfo(cvePath)
                if cveInfo.effective is False:
                    continue
                softManager.registerCVE(cveInfo)
    softManager.dump()

#CVEInfo('/home/txz/code/nvd-json-data-feeds/CVE-2020/CVE-2020-94xx/CVE-2020-9488.json')
build()