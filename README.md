# confirmCVE

后端功能：
给定发行版版本，软件包名称，软件包版本，软件包release号，确认可能存在问题的cve

前端功能：
处理依赖关系，根据依赖关系对cve漏洞进行扩散

docker生成：
docker run --name gitChecker -p 8000:80 -v /home/txz/analyze-rpms:/mnt/analyze-rpms -it ubuntu /bin/bash

apt update
apt install python3 python3-pip rpm yum git -y

pip3 install GitPython
pip3 install python-rpm-spec
pip3 install wget
pip3 install python-libarchive
pip3 install loguru
pip3 install pycurl
pip3 install certifi
pip3 install flask

对于centos,滚动发行的发行版结尾将添加-stream用于区分，例如8-steam的dist为el8-stream


## 以上都不用看
```
cd src/frontEnd
python server.py
```