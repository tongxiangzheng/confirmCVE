import pandas as pd

df = pd.DataFrame(columns=['软件名','类型', '最终确认的cve数量','经检查被排除的cve数量(如果为发行版软件包)'])

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
		if type=="maven":
			df.loc[len(df)] = [name,type,matchNum,None]
		else:
			df.loc[len(df)] = [name,type,matchNum,confirmNum]
		res[type]['cnt']+=1
		res[type]['match']+=matchNum
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
df.to_csv("res.csv", index=False,encoding='utf_8_sig')
print(res)