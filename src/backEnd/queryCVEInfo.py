import json
import pycurl
import certifi
from io import BytesIO
from urllib.parse import urlencode
from PackageInfo import PackageInfo
def sendCurl(URL:str,params:dict[str,str],additional:list=[])->dict[str,str]:
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
def getCPE(packageInfo:PackageInfo)->dict:
	params = {'cpeMatchString': "cpe:2.3:a:*:"+packageInfo.name+':'+packageInfo.version}
	result=sendCurl('https://services.nvd.nist.gov/rest/json/cpes/2.0',params)
	if result['totalResults'] !=1:
		print("have multiple result or no result in:")
		print("cpe:2.3:a:*:"+packageInfo.name+':'+packageInfo.version)
		for p in result['products']:
			print(" "+p['cpe']['cpeName'])
		return None
	product=result['products'][0]['cpe']
	return product

def queryCVEInfo(packageInfo:PackageInfo)->set[str]:
	product=getCPE(packageInfo)
	if product is None:
		return None
	return getCVE(product['cpeName'])

