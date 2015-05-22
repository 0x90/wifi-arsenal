from django.shortcuts import render
from main.models import Device

# Create your views here.
def home(request):
    devices = Device.objects.exclude(dst_mac=None)
    return render(request, 'main/index.html', {'devices':devices})
