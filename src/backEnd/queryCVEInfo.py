import json
import pycurl
import certifi
from io import BytesIO
from urllib.parse import urlencode
from PackageInfo import PackageInfo
from loguru import logger as log
def sendCurl(URL:str,params:dict,additional:list)->dict:
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
	result=json.loads(body.decode('iso-8859-1'))
	return result
def getCVE(cpeName:str)->set:
	params = {'cpeName': cpeName}
	result=sendCurl('https://services.nvd.nist.gov/rest/json/cves/2.0',params,["noRejected"])
	#with open("query.log","w") as f:
	#	json.dump(result,f,indent=2)
	vulnerabilities=result['vulnerabilities']
	cves=set()
	allowedSeverity={'LOW':False,'MEDIUM':False,'HIGH':True,'CRITICAL':True}
	#允许的安全等级，标记为False表示忽略，为True表示不忽略
	for vul in vulnerabilities:
		cve=vul['cve']
		id=cve['id']
		metrics=cve['metrics']
		if 'cvssMetricV2' in metrics:
			cvssInfo=metrics['cvssMetricV2']
			if len(cvssInfo)>0:
				severity=cvssInfo[0]['baseSeverity']
				if allowedSeverity[severity] is False:
					continue
		elif 'cvssMetricV31' in metrics:
			cvssInfo=metrics['cvssMetricV31']
			if len(cvssInfo)>0:
				severity=cvssInfo[0]['cvssData']['baseSeverity']
				if allowedSeverity[severity] is False:
					continue
		else:
			log.warning("cannot get cvss info for cve:"+id)     
		cves.add(id)
	return cves
def getCPE(packageInfo:PackageInfo)->dict:
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

def queryCVEInfo(packageInfo:PackageInfo)->set:
	product=getCPE(packageInfo)
	if product is None:
		return set()
	return getCVE(product['cpeName'])

