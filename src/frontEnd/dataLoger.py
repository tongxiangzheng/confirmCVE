
def logdata(info):
	print(info)
	return
	with open("log.info",'a') as f:
		f.write(info+"\n")