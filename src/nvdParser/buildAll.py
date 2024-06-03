import os
import git
from loguru import logger as log
import SoftManager
DIR = os.path.split(os.path.abspath(__file__))[0]
def build():
    
    repoLink="git@github.com:fkie-cad/nvd-json-data-feeds.git"
    #log.info("git link is "+repoLink)
    if os.path.exists(SoftManager.basePath):
        repo = git.Repo(SoftManager.basePath)
        repo.remotes.origin.pull()
        #check if git repo have to update
        #disable only for debug
    else:
        repo = git.Repo.clone_from(repoLink,to_path=SoftManager.basePath)
    softManager=SoftManager.SoftManager(loadFile=False)
    for year in os.listdir(SoftManager.basePath):
        yearPath=os.path.join(SoftManager.basePath,year)
        if os.path.isfile(yearPath):
            continue
        if year.startswith('.') or year.startswith('_'):
            continue
        #if year!='CVE-2024':
        #    continue    #小规模测试
        for cves in os.listdir(yearPath):
            cvesPath=os.path.join(yearPath,cves)
            for cve in os.listdir(cvesPath):
                cveInfo=SoftManager.CVEInfo(os.path.join(year,cves,cve))
                softManager.registerCVE(cveInfo)
    softManager.head=repo.head.commit.hexsha
    softManager.dump()

#CVEInfo('/home/txz/code/nvd-json-data-feeds/CVE-2020/CVE-2020-94xx/CVE-2020-9488.json')
#build()