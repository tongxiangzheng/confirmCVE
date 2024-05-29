import os
import git
from loguru import logger as log
import CVEInfo
import buildAll
import io
DIR = os.path.split(os.path.abspath(__file__))[0]
def dfs(newCommit,oldCommit,softManager):
    #abandon
    for blobFile in newCommit.blobs:
        oldFile=oldCommit[blobFile.path]
        if oldFile.hexsha!=blobFile.hexsha:
            print(blobFile.path,oldFile.hexsha,blobFile.hexsha)
        #log.trace(blobFile.name+" : "+blobFile.hexsha)
    for treeDir in newCommit.trees:
        dfs(treeDir,oldCommit,softManager)

def update():
    basePath=os.path.join(DIR,'nvd-json-data-feeds')
    repoLink="git@github.com:fkie-cad/nvd-json-data-feeds.git"
    log.info("git link is "+repoLink)
    if os.path.exists(basePath):
        repo = git.Repo(basePath)
        #repo.remotes.origin.pull()
        #check if git repo have to update
        #disable only for debug
    else:
        buildAll.build()
        return
    softManager=CVEInfo.SoftManager()
    print(softManager.head)
    print(repo.head.commit.hexsha)
    headCommit=repo.head.commit
    nowCommit=repo.commit(softManager.head)
    print(headCommit.tree)
    print(nowCommit.tree)
    diffTree=nowCommit.diff(headCommit)
    for a in diffTree:
        print(a.a_path)
        with io.BytesIO(nowCommit.tree[a.a_path].data_stream.read()) as f:
            cveInfo=CVEInfo.CVEInfo("",f)
            softManager.unRegisterCVE(cveInfo)
        with io.BytesIO(headCommit.tree[a.a_path].data_stream.read()) as f:
            cveInfo=CVEInfo.CVEInfo("",f)
            softManager.unRegisterCVE(cveInfo)
        

    return
    newCommits=[]
    while True:
        hexsha=nowCommit.hexsha
        if hexsha==softManager.head:
            break
        print("commit: "+hexsha+" , "+nowCommit.message)
        newCommits.append(nowCommit)
        if len(nowCommit.parents)==0:
            break
        nowCommit=nowCommit.parents[0]
    newCommits.reverse()
    for commit in newCommits:
        print(commit.hexsha)

    return
    for year in os.listdir(basePath):
        yearPath=os.path.join(basePath,year)
        if os.path.isfile(yearPath):
            continue
        if year.startswith('.') or year.startswith('_'):
            continue
        if year!='CVE-2024':
            continue    #小规模测试
        for cves in os.listdir(yearPath):
            cvesPath=os.path.join(yearPath,cves)
            for cve in os.listdir(cvesPath):
                cvePath=os.path.join(cvesPath,cve)
                cveInfo=CVEInfo.CVEInfo(cvePath)
                if cveInfo.effective is False:
                    continue
                softManager.registerCVE(cveInfo)
    softManager.head=repo.head.commit.tree.hexsha
    softManager.dump()

#CVEInfo('/home/txz/code/nvd-json-data-feeds/CVE-2020/CVE-2020-94xx/CVE-2020-9488.json')
update()