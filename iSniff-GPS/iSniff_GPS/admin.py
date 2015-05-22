from models import Client, AP, Location
from django.contrib import admin

class ClientAdmin(admin.ModelAdmin):
	list_display = ['manufacturer', 'mac', 'lastseen_date', 'name']

class APAdmin(admin.ModelAdmin):
	list_display = ['SSID', 'BSSID', 'manufacturer', 'lastprobed_date', 'name']

admin.site.register(Client, ClientAdmin)
admin.site.register(AP, APAdmin)
admin.site.register(Location)

