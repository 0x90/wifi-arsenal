import datetime
from django.utils.timezone import utc
from django.db import models
import logging

class Fingerprint(models.Model):
    x_coord = models.FloatField(default=0)
    y_coord = models.FloatField(default=0)
    bias_offset = models.IntegerField(default=0,blank=True,null=True)
    clusters = models.ManyToManyField('Cluster', through='ClusterToFingerprint')

class Bss(models.Model):
	mac_addr = models.CharField(max_length=64, db_index=True)
	ssid = models.CharField(max_length=32)
	channel = models.IntegerField(default=0, blank=True, null=True, db_index=True)
	clusters = models.ManyToManyField('Cluster', through='BssToCluster')
	
class SignalReading(models.Model):
	bss = models.ForeignKey(Bss)
	rssi = models.IntegerField(default=0, db_index=True)
	rssi_linear = models.FloatField(default=0)
	fingerprint = models.ForeignKey(Fingerprint, blank=True, null=True)


class Cluster(models.Model):
	cluster_name = models.CharField(max_length=32)
	fingerprints = models.ManyToManyField('Fingerprint', through='ClusterToFingerprint')
	bsss = models.ManyToManyField('Bss', through='BssToCluster')

class ClusterToFingerprint(models.Model):
	cluster = models.ForeignKey(Cluster)
	fingerprint = models.ForeignKey(Fingerprint)
	

class BssToCluster(models.Model):
	bss = models.ForeignKey(Bss)
	cluster = models.ForeignKey(Cluster)

	
