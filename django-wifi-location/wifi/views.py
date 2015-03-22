from django.shortcuts import render_to_response, redirect
from django.http import HttpResponse
from django.utils import simplejson as json
from django.views.decorators.csrf import csrf_exempt
#from datetime import datetime
import time
from wifi.models import *
from wifi.utils import *
import logging


# The client smartphone submits a WiFi RSSI measurment via submit_fingerprint
# to retrieve its estimated location.
@csrf_exempt 
def submit_fingerprint(request):
    if (request.method == 'POST'):
        data = json.loads(request.body)
    else:
        if request.method == "GET": 
            context = {}
            return render_to_response('test.html', context)
    data = json.loads(request.body)
    resp = {"status": "0"}
    if data and data.has_key("fingerprint_data"):
        start_time = time.time()
        result = measure(data["fingerprint_data"])
        print "Measure time:", time.time() - start_time, "seconds"
        if (result != None):
            resp["location"] = str(result[0]) + " " + str(result[1])
            resp["confidence"] = str(result[2])
            resp["bias_offset"] = str(result[3])
    else:
        resp["location"] = None
        resp["confidence"] = None
        resp["bias_offset"] = None
    return HttpResponse(content=json.dumps(resp), 
                        content_type='application/json')




@csrf_exempt 
def add_fingerprint(request):
	if (request.method == 'POST'):
		print "POST request received!"
		data = json.loads(request.body)
	else:
		if request.method == "GET": 
			context = {}
			return render_to_response('test.html', context)
	resp = {"status": 0}
	if (data):
		data = data['fingerprint_data']

		print data
		
		for key in data:
			try:
				sr = SignalReading()
				bss = Bss.objects.filter(mac_addr=key)
				if len(bss) < 1:
					bss = Bss()
					bss.mac_addr = key
					bss.save()
				else:
					bss = bss[0]
				sr.bss = bss
				sr.rssi = int(data[key]/100.0)
				sr.rssi_linear = abs(data[key])-(abs(data[key])//100)*100
				sr.channel = 1
				sr.save()
			except Exception as e1:
				resp = {"status": -1, "errMsg": str(e1)}
	
	print resp
	return HttpResponse(content=json.dumps(resp), 
						content_type='application/json')

	
