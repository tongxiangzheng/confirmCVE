import json
import pycurl
import certifi
from io import BytesIO
from urllib.parse import urlencode
from PackageInfo import PackageInfo
from loguru import logger as log
def sendCurl(URL:str,params:dict[str,str],additional:list=[])->dict:
	buffer = BytesIO()
	c = pycurl.Curl()
	URL=URL+'?'+urlencode(params)
	for ad in additional:
		URL=URL+"&"+ad
	c.setopt(c.URL,URL)
	c.setopt(c.HTTPGET,1)
	c.setopt(c.WRITEDATA,buffer)
	c.setopt(c.CAINFO,certifi.where())
	c.perform()
	c.close()
	body = buffer.getvalue()
	body.decode('iso-8859-1')
	result=json.loads(body.decode('iso-8859-1'))
	return result
def getCVE(cpeName:str)->set[str]:
	params = {'cpeName': cpeName}
	result=sendCurl('https://services.nvd.nist.gov/rest/json/cves/2.0',params,["noRejected"])
	vulnerabilities=result['vulnerabilities']
	cves=set()
	for vul in vulnerabilities:
		cve=vul['cve']
		cves.add(cve['id'])
	return cves
def getCPE(packageInfo:PackageInfo)->dict|None:
	matchString="cpe:2.3:a:*:"+packageInfo.name+':'+packageInfo.version
	if packageInfo.update is not None:
		matchString=matchString+':'+packageInfo.update
	params = {'cpeMatchString': matchString}
	result=sendCurl('https://services.nvd.nist.gov/rest/json/cpes/2.0',params)
	if result['totalResults'] !=1:
		if result['totalResults']==0:
			log.warning("have no result in:")
		else:
			log.warning("have multiple result in:")
		log.warning("cpe:2.3:a:*:"+packageInfo.name+':'+packageInfo.version)
		for p in result['products']:
			log.warning(" "+p['cpe']['cpeName'])
		#raise Exception("cannot find CPE")
		return None
	product=result['products'][0]['cpe']
	return product

def queryCVEInfo(packageInfo:PackageInfo)->set[str]:
	product=getCPE(packageInfo)
	if product is None:
		return set()
	return getCVE(product['cpeName'])

