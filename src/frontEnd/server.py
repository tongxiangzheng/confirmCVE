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
sys.path.insert(0,os.path.join(DIR,'..','debpackager'))
import PackageInfo
import nwkTools
import debpackager
import spdxReader
import json
import uuid
import traceback
 
app = Flask(__name__)

DEBPACKAGER_UPLOAD_FOLDER=os.path.join(DIR,"..","debpackager","uploadfiles")
 
@app.route('/querycve/', methods=["POST"])
def queryCVE():
	data = json.loads(request.get_data(as_text=True))
	packageList=spdxReader.parseSpdxObj(data)
	res=cveSolver.solve(packageList)
	return res

fileMap=dict()
@app.route('/deb/postfile/', methods=["POST"])
def postfile():
	# check if the post request has the file part
	if 'file' not in request.files:
		print('No file part')
		return {"error":1,"errorMessage":"No file part"}
	file = request.files['file']
	# If the user does not select a file, the browser submits an
	# empty file without a filename.
	if file.filename == '':
		print('No selected file')
		return {"error":2,"errorMessage":"No selected file"}
	filename = secure_filename(file.filename)
	filePath=os.path.join(DEBPACKAGER_UPLOAD_FOLDER, filename)
	if not os.path.isdir(DEBPACKAGER_UPLOAD_FOLDER):
		os.makedirs(DEBPACKAGER_UPLOAD_FOLDER)
	file.save(filePath)
	random_id = uuid.uuid4()
	fileMap[random_id.hex]=filePath
	return {"error":0,"token":random_id.hex}

@app.route('/deb/querybuildinfo/', methods=["POST"])
def querybuildinfo():
	data = json.loads(request.get_data(as_text=True))
	if data['srcFile'] not in fileMap:
		return {"error":1,"errorMessage":"invalid file token"}
	srcfile=fileMap[data['srcFile']]
	srcFile2=None
	if 'srcFile2' in data:
		if data['srcFile2'] not in fileMap:
			return {"error":1,"errorMessage":"invalid file token"}
		srcFile2=fileMap[data['srcFile2']]
	try:
		res=debpackager.getBuildInfo(srcfile,srcFile2,data['osType'],data['osDist'],data['arch'])
	except Exception:
		traceback.print_exc()
		return {"error":2,"errorMessage":"failed to build"}
	if res is None:
		return {"error":2,"errorMessage":"failed to build"}

	return {"error":0,"buildinfo":res}

log.remove(handler_id=None)
logFile="log.log"
if os.path.exists(logFile):
	os.remove(logFile)
#log.add(sink=logFile,level='INFO')
log.add(sink=logFile,level='DEBUG')

port = 8342
app.run(host="0.0.0.0",port=port)