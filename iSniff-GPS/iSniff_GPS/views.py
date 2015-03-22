from django.http import HttpResponse, HttpRequest
from django.core.exceptions import *
from django.shortcuts import render
from django.views.generic import *
from django.db.models import Count
from datetime import datetime
from models import *
from string import lower
import wigle
import wloc
import re
from netaddr import EUI

def get_manuf(apdict):
	manufdict = {}
	for m in apdict.keys():
		try:
	                mac = EUI(m)
        	        manufdict[m] = mac.oui.records[0]['org']
			#.split(' ')[0].replace(',','')
        	        #.replace(', Inc','').replace(' Inc.','')
	        except:
                	manufdict[m] = 'unknown'
        return manufdict

class ClientList(ListView):
	model = Client
	template_name = 'client_list.html'
        def get_queryset(self):
          return Client.objects.order_by('manufacturer','mac')
        def get_context_data(self, **kwargs):
	       	context = super(ClientList, self).get_context_data(**kwargs)
		probedict = {}
		for client in Client.objects.all():
			probedict[client] = AP.objects.filter(client=client)
		context['probedict'] = probedict
		context['apcount'] = len(AP.objects.all())
		context['devicecount'] = len(Client.objects.all())
	        return context

class ClientDetail(DetailView):
	model = Client
	slug_field = 'mac'
	template_name = 'client_detail.html'
        def get_context_data(self, **kwargs):
	       	context = super(ClientDetail, self).get_context_data(**kwargs)
		context['APs'] = AP.objects.filter(client=self.object)
	        return context

class APList(ListView):
	model = AP
	template_name = 'ap_list.html'
        def get_queryset(self):
        	return AP.objects.annotate(num_clients=Count('client')).order_by('-num_clients')
        def get_context_data(self, **kwargs):
			context = super(APList, self).get_context_data(**kwargs)
			context['apcount'] = len(AP.objects.all())
			context['devicecount'] = len(Client.objects.all())
			#context['Clients'] = self.object.client
			return context

class APDetail(DetailView):
	model = AP
	template_name = 'ap_detail.html'
	def get_object(self):
		lookup = self.kwargs['ssid_or_bssid']
		if re.match(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w',lookup):
			a=AP.objects.get(BSSID=lookup)
		else:
			a=AP.objects.get(SSID=lookup)
		return a

	def get_context_data(self, **kwargs):
		print self.kwargs
		context = super(APDetail, self).get_context_data(**kwargs)
		context['Clients'] = self.object.client.all()
		return context

class Home(TemplateView):
    template_name = "home.html"
 
class stats(TemplateView):
    template_name = "stats.html"
    def get_context_data(self, **kwargs):
        from operator import itemgetter
        context = super(stats, self).get_context_data(**kwargs)
        manuf = {}
	for m in Client.objects.values_list('manufacturer',flat=True).distinct():
		m = m[0].upper()+(m[1:].lower())
        	manuf[m] = len(Client.objects.filter(manufacturer__iexact=m))
	l = []
	for m in manuf.items():
        	l.append(m)		
	context['manuf']=sorted(l, key=itemgetter(1), reverse=True)[:10]
	context['devicecount'] = len(Client.objects.all())
        return context


def getCenter(apdict):
	numresults = len(apdict)
	latCenter = 0.0
	lonCenter = 0.0	
	for (lat,lon) in apdict.values():
		latCenter += lat
		lonCenter += lon
	try:
		return( ((latCenter / numresults),(lonCenter / numresults)) )
	except ZeroDivisionError:
		return((0,0))
	
def AppleWloc(request,bssid=None):	
	if not bssid:
		bssid = '00:1e:52:7a:ae:ad'
	print 'Got request for %s' % bssid
	if request.GET.get('ajax'):
		template='apple-wloc-ajax.js'		
	else:
		template='apple-wloc.html'
		request.session['apdict'] = {}
		request.session['apset'] = set() #reset server-side cache of unique bssids if we load page normally
	print '%s in set at start' % len(request.session['apset'])
	bssid=lower(bssid)
	apdict = wloc.QueryBSSID(bssid)	
	print '%s returned from Apple' % len(apdict)
	dupes = 0
	for ap in apdict.keys():
		if ap in request.session['apset']:
			dupes += 1
			del apdict[ap]
		request.session['apset'].add(ap)
	numresults = len(apdict)
	print '%s dupes excluded' % dupes
	print '%s in set post filter' % len(request.session['apset'])
	print '%s returned to browser post filter' % numresults
	#if numresults == 0 or (-180.0, -180.0) in apdict.values():
	#	return HttpResponse('0 results.')
	if bssid in apdict.keys():
		try:
			a = AP.objects.get(BSSID=bssid) #original design - only save ap to db if it's one that has been probed for
			(a.lat,a.lon) = apdict[bssid]
			a.save() #if Apple returns a match for BSSID we save this as location
			print 'Updated %s location to %s' % (a,(a.lat,a.lon))
		except ObjectDoesNotExist:
			pass
	for key in apdict.keys():
		request.session['apdict'][key] = apdict[key]
	print 'Session apdict: %s' % len(request.session['apdict'])
	return render(request,template,{'bssid':bssid,'hits':len(apdict),'center':getCenter(apdict),'bssids':apdict.keys(),'apdict':apdict,'manufdict':get_manuf(apdict)})

def LoadDB(request,name=None):
	c=PointDB.objects.get(name=name)
	request.session['apdict']=c.pointdict
	apdict = request.session['apdict']
	request.session['apset']=set(apdict.keys())
	print 'Loaded saved DB %s from %s' % (name,c.date_saved)
	return render(request,'apple-wloc.html',{'bssid':apdict.keys()[0],'hits':len(apdict),'center':getCenter(apdict),'bssids':apdict.keys(),'apdict':apdict,'manufdict':get_manuf(apdict)})

def SaveDB(request,name=None):
	try:
		c = PointDB.objects.get(name=name)
	except ObjectDoesNotExist:
		c = PointDB(name=name)
	c.pointdict = request.session['apdict']
	c.save()
	return HttpResponse('Saved %s points as %s' % (len(request.session['apdict'].keys()),name)) #xss

def AppleMobile(request,cellid=None,LTE=False):
	if 'cellset' not in request.session:
		request.session['cellset'] = set()
	if request.GET.get('ajax'):
		template='apple-mobile-ajax.js'		
	else:
		template='apple-mobile.html'
		request.session['cellset'] = set()
	if cellid:
		(celldict,celldesc) = wloc.QueryMobile(cellid,LTE)
		numresults = len(celldict)
		if numresults == 0:
			return HttpResponse('0 results.')
		dupes = 0
		for cell in celldict.keys():
			if cell in request.session['cellset']:
				dupes += 1
				del celldict[cell]
			request.session['cellset'].add(cell)
		return render(request,template,{'bssid':cellid,'hits':len(celldict),'center':getCenter(celldict),\
			'bssids':celldict.keys(),'apdict':celldict,'manufdict':celldesc,'LTE':LTE})
	else:
		return render(request,'wigle-wloc.html',{'ssid':'','center':(56.97518158, 24.17274475)})

def locateSSID(request,ssid=None):
	if ssid:
		apdict = wigle.getLocation(SSID=ssid)
		numresults = len(apdict)
		if numresults == 0:
			return HttpResponse('0 results.')
		return render(request,'wigle-wloc.html',{'ssid':ssid,'hits':len(apdict),'center':getCenter(apdict),'bssids':apdict.keys(),'apdict':apdict})
	else:
		return render(request,'wigle-wloc.html',{'ssid':'','center':(56.97518158, 24.17274475)})
		
def updateSSID(request):
	try:
		ssid = request.POST['ssid']
		(lat,lon) = request.POST['position'].replace('(','').replace(')','').split(',')
		lat = float(lat)
		lon = float(lon)
		a = AP.objects.get(SSID=ssid)
		(a.lat,a.lon) = (lat,lon)
		a.save()
		return HttpResponse('Updated %s location to %s' % (a,(a.lat,a.lon)))
	except ObjectDoesNotExist:
		return HttpResponse('Not found in db.')



