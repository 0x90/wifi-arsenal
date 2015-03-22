from django.contrib import admin
from main.models import Device, Probe
#admin.site.register(Device)
admin.site.register(Probe)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('src_mac', 'dst_mac', 'signal', 'label', 'lastseen', 'get_probes')
    def get_probes(self, obj):
        ret = []
        for i in obj.probe_set.all():
            ret.append(i.probe)
        return ", ".join(ret)
admin.site.register(Device, DeviceAdmin)

