#!/usr/bin/env python

from pylab import *
import matplotlib
import matplotlib.image as mpimg
import sys
import ConfigParser

config = ConfigParser.ConfigParser()
config.read("Wifi-Contour.ini")
imageFile = config.get("Wifi-Contour", "image")
fig = figure()
x_pts = []
y_pts = []
img = mpimg.imread(imageFile)
ymax,xmax = img.shape[0:2]
xmin,ymin = 0,0
ax = fig.add_subplot(111)
imshow(img[::-1]) 
ax.axis([xmin, xmax, ymin, ymax])
draw()

#if config.getboolean("Wifi-Contour","plot"):
#    SSID = config.get('Wifi-Contour','Bssid')
#    for i in SSID.split(' '):
#        print i
#    sys.exit()


def TitlePrint(s):
    title(s,fontsize=16)
    draw()

TitlePrint('Select Points on the graph')

def onclick(event):
    makePlot(event.xdata,event.ydata)

def on_key(event):
    done = True

def makePlot(x,y):
    fig.clf()
    TitlePrint('Select Points on the graph')
    x_pts.append(x)
    y_pts.append(y)
    imshow(img[::-1])
    ax = fig.add_subplot(111) 
    ax.scatter(x_pts,y_pts,marker='o',c='b',s=5)
    ax.axis([xmin, xmax, ymin, ymax])
    draw()

done = False

cid = fig.canvas.mpl_connect('button_press_event', onclick)
cid = fig.canvas.mpl_connect('key_press_event', on_key)
show()
print x_pts
