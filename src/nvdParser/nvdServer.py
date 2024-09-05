import threading
import time
import updateNVD

def updateLoop():
	while True:
		updateNVD.update()
		time.sleep(60*60)
		# update per hour

def nvdServer():
	t=threading.Thread(target=updateLoop,daemon=True)
	t.start()