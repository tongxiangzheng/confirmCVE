import cveSolver
import json
import socket
import os
import sys
from loguru import logger as log
from flask import Flask,request
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
import nwkTools
import spdxReader
import json
 
 
app = Flask(__name__)
 
 
@app.route('/querycve/', methods=["POST","GET"])
def queryCVE():
	data = json.loads(request.get_data(as_text=True))
	packageList=spdxReader.parseSpdxObj(data)
	res=cveSolver.solve(packageList)
	return res

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='DEBUG')

port = 8342
app.run(host="0.0.0.0",port=port)