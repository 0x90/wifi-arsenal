import csv,json,couchdbkit

def n(l):
    d=csv.DictReader(open(l))
    l=p(d.next())
    r=p(d.next())
    out=[]
    while r:
        if l["p"]==r["p"]:
        	l["n"].append(r["n"][0])
        else:
            out.append({"point":l["p"],"networks":l["n"]})
            l=r
        try:
            r=p(d.next())
        except:
            r=0
            out.append({"point":l["p"],"networks":l["n"]})     
    return out

def p(obj):
	point={"geometry":{"type":"Point","coordinates":[float(obj["CurrentLongitude"]),float(obj["CurrentLatitude"]),float(obj["AltitudeMeters"])]},"acc":float(obj["AccuracyMeters"])}
	net={"SSID":obj["SSID"],"MAC":obj["MAC"],"firstSeen":obj["FirstSeen"],"Kind":obj["Type"],"ch":int(obj["Channel"]),"modes":obj["AuthMode"],"strength":int(obj["RSSI"])}
	return {"p":point,"n":[net]}

def js(o,l):
    j=open(o,"w")
    ll=n(l)
    json.dump(ll,j,ensure_ascii=False)
    j.close()

def up(u,l):
	server = couchdbkit.Server(u)
	db = server.get_or_create_db("couchfi")
	docs= n(l)
 	db.bulk_save(docs)



