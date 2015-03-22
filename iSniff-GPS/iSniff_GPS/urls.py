from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls import patterns, include, url
from django.contrib import admin
from views import *

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', ClientList.as_view(), name="clientlist"),
    url(r'^client/(?P<slug>[:\w]+)$', ClientDetail.as_view(), name="client"),
    url(r'^clients/?$', ClientList.as_view()),
    url(r'^network/(?P<ssid_or_bssid>.+)$', APDetail.as_view(), name="network"),
    url(r'^networks/?$', APList.as_view(), name="networks"),
    url(r'^apple-wloc/?$', AppleWloc, name="applewloc-base"),
    url(r'^savedb/(?P<name>[:\w]*)$', SaveDB, name="savedb"),
    url(r'^loaddb/(?P<name>[:\w]*)$', LoadDB, name="loaddb"),
    url(r'^apple-wloc/(?P<bssid>[:\w]+)$', AppleWloc, name="applewloc"),
    url(r'^apple-mobile/(?P<cellid>[:\w-]*)$', AppleMobile, name="apple-mobile"),
    url(r'^apple-mobile-lte/(?P<cellid>[:\w-]*)$', AppleMobile, {'LTE':True}, name="apple-mobile-lte"),
    url(r'^updateSSID$', updateSSID, name="updatessid"),
    url(r'^locateSSID/?$', locateSSID, name="locatessid-base"),
    url(r'^locateSSID/(?P<ssid>[\w\W]+)$', locateSSID, name="locatessid"),
    url(r'^stats/?$', stats.as_view(), name="stats"),

    url(r'^admin/', include(admin.site.urls)),)
