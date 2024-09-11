import cveSolver
import json
import socket
import os
import sys
from loguru import logger as log
from flask import Flask,flash, request, redirect, url_for
from werkzeug.utils import secure_filename
DIR=os.path.split(os.path.abspath(__file__))[0]
sys.path.insert(0,os.path.join(DIR,'..','backEnd'))
sys.path.insert(0,os.path.join(DIR,'..','nvdParser'))
import PackageInfo
import nwkTools
import debpackager
import spdxReader
import json
 
 
app = Flask(__name__)

DEBPACKAGER_UPLOAD_FOLDER=os.path.join(DIR,"..","debpackager","files")
 
@app.route('/querycve/', methods=["POST"])
def queryCVE():
	data = json.loads(request.get_data(as_text=True))
	packageList=spdxReader.parseSpdxObj(data)
	res=cveSolver.solve(packageList)
	return res

@app.route('/deb/getbuildinfo', methods=["POST"])
def getbuildinfo():
	# check if the post request has the file part
	if 'file' not in request.files:
		print('No file part')
		return {"error":1}
	file = request.files['file']
	# If the user does not select a file, the browser submits an
	# empty file without a filename.
	if file.filename == '':
		print('No selected file')
		return {"error":2}
	filename = secure_filename(file.filename)
	filePath=os.path.join(DEBPACKAGER_UPLOAD_FOLDER, filename)
	file.save(filePath)
	res=debpackager.getBuildInfo(filePath)
	return {}

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='DEBUG')

port = 8342
app.run(host="0.0.0.0",port=port)