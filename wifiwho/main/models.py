from django.db import models
class Device(models.Model):
    src_mac = models.CharField(max_length=30, db_index=True)
    dst_mac = models.CharField(max_length=30, null=True)
    signal = models.CharField(max_length=30, null=True)
    label = models.CharField(max_length=30, null=True)
    lastseen = models.DateTimeField(null=True)

class Probe(models.Model):
    device = models.ForeignKey(Device, related_name='probe_set')
    probe = models.CharField(max_length=255, db_index=True)
