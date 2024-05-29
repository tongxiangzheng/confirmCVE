import os
import git
from loguru import logger as log
import SoftManager
DIR = os.path.split(os.path.abspath(__file__))[0]
def build():
    basePath=os.path.join(DIR,'nvd-json-data-feeds')
    repoLink="git@github.com:fkie-cad/nvd-json-data-feeds.git"
    log.info("git link is "+repoLink)
    if os.path.exists(basePath):
        repo = git.Repo(basePath)
        repo.remotes.origin.pull()
        #check if git repo have to update
        #disable only for debug
    else:
        repo = git.Repo.clone_from(repoLink,to_path=basePath)
    softManager=SoftManager.SoftManager()
    for year in os.listdir(basePath):
        yearPath=os.path.join(basePath,year)
        if os.path.isfile(yearPath):
            continue
        if year.startswith('.') or year.startswith('_'):
            continue
        #if year!='CVE-2024':
        #    continue    #小规模测试
        for cves in os.listdir(yearPath):
            cvesPath=os.path.join(yearPath,cves)
            for cve in os.listdir(cvesPath):
                cvePath=os.path.join(cvesPath,cve)
                cveInfo=SoftManager.CVEInfo(cvePath)
                softManager.registerCVE(cveInfo)
    softManager.head=repo.head.commit.tree.hexsha
    softManager.dump()

#CVEInfo('/home/txz/code/nvd-json-data-feeds/CVE-2020/CVE-2020-94xx/CVE-2020-9488.json')
build()