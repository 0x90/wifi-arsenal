from django.conf.urls import patterns, include, url
from views import *
# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
	url(r'^wifi/submit_fingerprint$', submit_fingerprint),
	url(r'^wifi/add_fingerprint$', add_fingerprint)
    # Examples:
    # url(r'^$', 'wifi.views.home', name='home'),
    # url(r'^wifi/', include('wifi.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
