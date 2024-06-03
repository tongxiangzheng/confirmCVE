import os
import git
from loguru import logger as log
import SoftManager
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
    repoLink="git@github.com:fkie-cad/nvd-json-data-feeds.git"
    #log.info("git link is "+repoLink)
    if os.path.exists(SoftManager.basePath) and os.path.exists(SoftManager.targetPath):
        repo = git.Repo(SoftManager.basePath)
        repo.remotes.origin.pull()
        #check if git repo have to update
        #disable only for debug
    else:
        buildAll.build()
        return
    softManager=SoftManager.SoftManager()
    log.info("latest git commit:"+repo.head.commit.hexsha)
    log.info("now git commit:"+softManager.head)
    headCommit=repo.head.commit
    nowCommit=repo.commit(softManager.head)
    diffTree=nowCommit.diff(headCommit)
    for a in diffTree:
        print(a.a_path)
        if a.a_path.startswith('CVE-'):
            unregisterUnsuccess=False
            registerUnsuccess=False
            try:
                with io.BytesIO(nowCommit.tree[a.a_path].data_stream.read()) as f:
                    cveInfo=SoftManager.CVEInfo(a.a_path,f)
                    softManager.unRegisterCVE(cveInfo)
            except KeyError:
                log.debug("cannot unregister file: "+a.a_path+" . It's OK because it may be a new file")
                unregisterUnsuccess=True
            try:
                with io.BytesIO(headCommit.tree[a.a_path].data_stream.read()) as f:
                    cveInfo=SoftManager.CVEInfo(a.a_path,f)
                    softManager.registerCVE(cveInfo)
            except KeyError:
                log.debug("cannot register file: "+a.a_path+" , the file may deleted")
<<<<<<< HEAD
                registerUnsuccess=True
            if unregisterUnsuccess is True and registerUnsuccess is True:
                log.warning(a.a_path+" : have unknown error")

    softManager.dump()
=======
                pass
            
    softManager.dump()
    return
>>>>>>> 830e1e6 (merge)

#CVEInfo('/home/txz/code/nvd-json-data-feeds/CVE-2020/CVE-2020-94xx/CVE-2020-9488.json')
update()