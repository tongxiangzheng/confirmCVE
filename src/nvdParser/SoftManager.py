import os
import json
from loguru import logger as log
ignoredVulnStatus={'Rejected','Awaiting Analysis','Received','Undergoing Analysis'}

DIR = os.path.split(os.path.abspath(__file__))[0]
basePath=os.path.join(DIR,'nvd-json-data-feeds')
targetPath=os.path.join(DIR,'package_cve')
dataPath=os.path.join(DIR,"data")
class CVEInfo:
    def __init__(self,path,f=None):
        #if f is None, will load file from path
        #if else, will load file from f
        if f is not None:
            data=json.load(f)
        else:
            with open(os.path.join(basePath,path),"r") as f:
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
                self.collect.append((cpename,criteria))
def normalizeName(name:str):
    return name.replace('/','_slash_')
def normalizeName0(name0):
    if name0!='.':
        return name0
    else:
        return 'dot'

def getPath(name):
    pathBase=os.path.join(targetPath,normalizeName0(name[0]))
    path=os.path.join(pathBase,name)
    return pathBase,path
class Soft:
    def __init__(self,name:str,cpe:str,loadFile):
        name=normalizeName(name)
        self.name=name
        self.cpe=cpe
        pathBase,path=getPath(name)
        if not os.path.exists(pathBase):
            os.makedirs(pathBase)
        self.path=path
        self.items=[]
        if loadFile is True:
            if os.path.isfile(self.path):
                with open(self.path,"r") as f:
                    data=f.readlines()
                    for info in data:
                        self.items.append(info.strip())
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
    def __init__(self,loadFile=True):
        self.softCache=dict()
        self.head=None
        self.loadFile=loadFile
        if os.path.isfile(dataPath):
            with open(os.path.join(DIR,"data"),"r") as f:
                data=f.readlines()
                if len(data)!=0:
                    self.head=data[0]
    def dump(self):
        for soft in self.softCache.values():
            soft.dump()
        with open(os.path.join(DIR,"data"),"w") as f:
            f.write(self.head)
    def getsoft(self,softName,softCPE):
        if softName not in self.softCache:
            soft=Soft(softName,softCPE,self.loadFile)
            self.softCache[softName]=soft
            return soft
        else:
            return self.softCache[softName]
    def addItem(self,softInfo,item):
        soft=self.getsoft(softInfo[0],softInfo[1])
        log.trace(soft.name+" add Item: "+item)
        soft.add(item)
    def removeItem(self,softInfo,item):
        soft=self.getsoft(softInfo[0],softInfo[1])
        log.trace(soft.name+" remove Item: "+item)
        soft.remove(item)
    def registerCVE(self,cveInfo:CVEInfo):
        if cveInfo.effective is False:
            return
        for softInfo in cveInfo.collect:
            self.addItem(softInfo,cveInfo.path)
    def unRegisterCVE(self,cveInfo:CVEInfo):
        if cveInfo.effective is False:
            return
        for softInfo in cveInfo.collect:
            self.removeItem(softInfo,cveInfo.path)
    def queryCPE(self,softName):
        if softName not in self.softCache:
            return None
        else:
            return self.softCache[softName].cpe