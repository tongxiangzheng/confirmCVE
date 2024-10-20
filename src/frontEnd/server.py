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
sys.path.insert(0,os.path.join(DIR,'..','rpmpackager'))
import hashlib
import debpackager
import rpmpackager
import spdxReader
import json
import uuid
import traceback
 
app = Flask(__name__)

DEBPACKAGER_UPLOAD_FOLDER=os.path.join(DIR,"..","..","data","uploadfiles")
 
@app.route('/querycve/', methods=["POST"])
def queryCVE():
	data = json.loads(request.get_data(as_text=True))
	packageList=spdxReader.parseSpdxObj(data)
	res=cveSolver.solve(packageList)
	return res

file_tokenMap=dict()
token_fileMap=dict()
def setToken_file_relationship(file):
	random_id = uuid.uuid4()
	token=random_id.hex
	file_tokenMap[file]=token
	token_fileMap[token]=file
	return token
def init():
	if not os.path.isdir(DEBPACKAGER_UPLOAD_FOLDER):
		os.makedirs(DEBPACKAGER_UPLOAD_FOLDER)
	for file in os.listdir(DEBPACKAGER_UPLOAD_FOLDER):
		filePath=os.path.join(DEBPACKAGER_UPLOAD_FOLDER,file)
		setToken_file_relationship(filePath)

@app.route('/postfile/', methods=["POST"])
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
	#filename = secure_filename(file.filename)
	img_key = hashlib.md5(file.read()).hexdigest() 
	file.seek(0)
	filename=img_key
	allowed_type=['.src.rpm','.tar.bz2','.tar.bz2','.tar.gz','.tar.lzma','.tar.xz']
	for t in allowed_type:
		if file.filename.endswith(t):
			filename+=t
	
	filePath=os.path.join(DEBPACKAGER_UPLOAD_FOLDER, filename)
	if filePath in file_tokenMap:
		token=file_tokenMap[filePath]
	else:
		file.save(filePath)
		token=setToken_file_relationship(filePath)
	return {"error":0,"token":token}

@app.route('/deb/querybuildinfo/', methods=["POST"])
def debQuerybuildinfo():
	data = json.loads(request.get_data(as_text=True))
	if data['srcFile'] not in token_fileMap or data['srcFile'] is None:
		return {"error":1,"errorMessage":"invalid file token"}
	srcfile=token_fileMap[data['srcFile']]
	srcFile2=None
	if data['srcFile2'] is not None:
		if data['srcFile2'] not in token_fileMap:
			return {"error":1,"errorMessage":"invalid file token"}
		srcFile2=token_fileMap[data['srcFile2']]
	try:
		res=debpackager.getBuildInfo(srcfile,srcFile2,data['osType'],data['osDist'],data['arch'])
	except Exception:
		traceback.print_exc()
		return {"error":2,"errorMessage":"failed to build"}
	if res is None:
		return {"error":2,"errorMessage":"failed to build"}

	return {"error":0,"buildinfo":res}
@app.route('/rpm/querybuildinfo/', methods=["POST"])
def rpmQuerybuildinfo():
	data = json.loads(request.get_data(as_text=True))
	if data['srcFile'] not in token_fileMap or data['srcFile'] is None:
		return {"error":1,"errorMessage":"invalid file token"}
	srcfile=token_fileMap[data['srcFile']]
	try:
		res=rpmpackager.getBuildInfo(srcfile,data['osType'],data['osDist'],data['arch'])
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
log.add(sink=logFile,level='WARNING')
#log.add(sink=logFile,level='TRACE')

port = 8342
init()
app.run(host="0.0.0.0",port=port)