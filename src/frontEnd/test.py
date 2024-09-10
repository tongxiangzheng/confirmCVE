import requests
import json

def queryCVE(spdxObj,url):
	try:
		response = requests.post(url, json=spdxObj)
	except requests.exceptions.ConnectionError as e:
		print("failed to query CVE: Unable to connect: "+url)
		return {}
	except Exception as e:
		print(f'failed to query CVE: {e}')
	if response.status_code == 200:
		return response.json()
	else:
		print(f'failed to query CVE: Request failed with status code {response.status_code}')
		return {}

spdxPath="my_spdx_document.spdx.json"
with open(spdxPath,"r") as f:
	spdxObj=json.load(f)
	cves=queryCVE(spdxObj,"http://127.0.0.1:8342/querycve/")
	print(cves)