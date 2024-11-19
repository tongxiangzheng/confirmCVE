


with open("log.info") as f:
	data=f.readlines()


name_type_set=set()
name=""
type=""
matchNum=0
confirmNum=0

res={
	"deb":{
		"cnt":0,
		"match":0,
		"confirm":0
	},
	"rpm":{
		"cnt":0,
		"match":0,
		"confirm":0
	},
	"maven":{
		"cnt":0,
		"match":0,
		"confirm":0
	}
}

for info in data[1:]:
	info=info.strip()
	if len(info)==0:
		name_type=name+type
		if name_type in name_type_set:
			continue
		name_type_set.add(name_type)
		res[type]['cnt']+=1
		res[type]['match']+=matchNum
		if type=="maven" and matchNum!=0:
			print(name)
		res[type]['confirm']+=confirmNum
	elif info.startswith("package name:"):
		name=info.split(":")[1]
		confirmNum=0
		matchNum=0
	elif info.startswith("package type:"):
		type=info.split(":")[1]
	elif info.startswith("cves:"):
		confirmNum=int(info.split(": ")[1])
	elif info.startswith("matched cve:"):
		matchNum=int(info.split(": ")[1])
	elif info.startswith("confirmed cve:"):
		confirmNum=int(info.split(": ")[1])

print(res)