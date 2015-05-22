#!/usr/bin/env python

try:
	from Tkinter import *
	import Pmw, math
except ImportError, e:
	pass
	
class GraphPositions(object):
	def __init__(self, canvas):
		Pmw.initialise()
		self.balloon = Pmw.Balloon(canvas)
		self.canvas = canvas

		self.CANVAS_SIZE = 800
		
		# initiating variables to store images.
		self.scanner_image = PhotoImage(file='gui/images/WAP.gif')
		self.ap_image = PhotoImage(file='gui/images/ap2.gif')
		self.sta_image = PhotoImage(file='gui/images/sta.gif')
		
		# From Table2: Distance, average RSSI [dBm] and standard deviation for CC2420 ZigBee module:
		self.sig2dis = ([52,2],[53,4],[58,6],[63,9], [65,12], [70,15], [76,20], [82,25])
		self.ch2bg = ([1, 'green'], [2, 'blue'], [3, 'tan'], [4, 'gray'], [5, 'black'], [6, 'orange'], [7, 'pink'], [8, 'yellow'], [9, 'white'], [10, 'purple'], [11, 'red'])
		
		# Draw circular disc region around Scanner device
		self.draw_oval_gradient()
		self.aps_count = 0
		self.stas_count = 0
		
		# Put an icon of Scanner device on the center of circular disc.
		scanner = self.canvas.create_image(402,402, image=self.scanner_image, anchor=CENTER, tags='scanner')	
		# binding Pmw Balloon feature to 'scanner' item in canvas
		self.balloon.tagbind(self.canvas, scanner, 'Scanner device\nMAC Address:\nInterface used:\nSignal strength:')
					
	# Draws Circular disc like object on canvas having color gradient from Red to Green. It is made so
	# to represent the signal attenuation of Wireless devices accross distance.	
	def draw_oval_gradient(self):				
		color_table = Frame(self.canvas, highlightbackground="black", highlightthickness=1)
		color_table.pack()
		heading = Frame(color_table)
		ch_heading = Label(heading, text="Channel", highlightbackground="black", highlightthickness=1, font="Verdana 8 bold").pack(side=LEFT)
		bg_heading = Label(heading, text="Color", highlightbackground="black", highlightthickness=1, font="Verdana 8 bold").pack(side=LEFT)
		heading.pack()
		for ch, bg in self.ch2bg:
			row = Frame(color_table)
			tag = "color%d"%ch
			channel = Label(row, text=ch, width=6, highlightbackground="black", highlightthickness=1, font="Verdana 8 bold").pack(side=LEFT)
			background = Label(row, width=4, bg=bg, highlightbackground="black", highlightthickness=1, font="Verdana 8 underline").pack(side=LEFT)
			row.pack()
			#self.balloon.bind(background, "Channel: %d, Background: %s" %(ch, bg))
		self.canvas.create_window(900, 0, window=color_table, anchor=NE)
		
		x = 30
		y = 770
		limit = 409
		(r1,g1,b1) = (65535,41000,2000)		# Red Color
		(r2,g2,b2) = (10000,65535,1000)		# Green Color

		r_ratio = float(r2-r1) / limit
		g_ratio = float(g2-g1) / limit
		b_ratio = float(b2-b1) / limit

		for i in range(limit):
			x += 1
			y -= 1
			nr = int(r1 + (r_ratio * i))
			ng = int(g1 + (g_ratio * i))
			nb = int(b1 + (b_ratio * i))
			color = "#%4.4x%4.4x%4.4x" % (nr,ng,nb)
			self.canvas.create_oval(x,x,y,y, outline=color, fill=color)
        
        def add_device(self, device, x, y, tags, help, ch, ssid):
        	# let's get channel and its corresponding color code.
        	for c, b in self.ch2bg:
        		if c == ch:
        			bg = b
        	# co-ordinates for drawing circles under device' icon
        	x1 = x - 14
        	y1 = y - 16
        	x2 = x + 14
        	y2 = y + 12
        	        	
        	if device == "ap":
        		# draws circle background filled with channel's corresponding color.
        		self.canvas.create_oval(x1,y1, x2,y2, outline=bg, fill=bg)
        		self.canvas.create_image(x, y, image=self.ap_image, tags=tags)
        	elif device == "sta":
        		self.canvas.create_image(x, y, image=self.sta_image, tags=tags)
        	
        	# co-ordinates for writing text under icon
        	x3 = x
        	y3 = y + 16
        	
        	# Write text below icon
        	self.canvas.create_text(x3,y3, text=ssid, font="Verdana 6 underline", fill="white")
		self.balloon.tagbind(self.canvas, tags, help)
        
        # Adds Access Points and Stations in the canvas
        def calc_position(self, device, ch, ssid, bssid, signal, enc):
		'''for sig,dis in self.sig2dis:
			if sig == signal:
				distance = dis'''
		d = 300 - (signal * 3)
		margin = self.CANVAS_SIZE / 20
		xcenter = int(self.CANVAS_SIZE / 2)
		ycenter = int(self.CANVAS_SIZE / 2)
		line_length = ((self.CANVAS_SIZE / 2) - margin - d)
		
		if device == "ap":
			self.aps_count += 1
			angle_step1 = 30
			for i in range(self.aps_count):
				theta = (angle_step1 * i)# + (angle_step1 / 2)
				xstart = int(margin * math.cos(theta)) + xcenter
				ystart = int(margin * math.sin(theta)) + ycenter
				xend = int(line_length * math.cos(theta)) + xcenter
				yend = int(line_length * math.sin(theta)) + ycenter
			
			help_msg2 = "%d. Access Point\nESSID: %s\nBSSID: %s\nChannel: %d\nSignal strength: -%d dBm \nEncryption: %s" % (i,ssid,bssid,ch,signal,enc)
			ap_tag = "ap%d" % i
			self.add_device("ap", xend, yend, ap_tag, help_msg2, ch, ssid)
				#self.canvas.create_image(xend, yend, image=self.ap_image, tags=ap_tag)
				#self.canvas1.create_line(xstart, ystart, xend, yend, fill="blue")
				#self.balloon.tagbind(self.canvas, ap_tag, help_msg2)
		else:
			self.stas_count += 1
			angle_step2 = 20
			#line_length = line_length - 60
			for j in range(self.stas_count):
				theta = angle_step2 * j
				xstart = int(margin * math.cos(theta)) + xcenter
				ystart = int(margin * math.sin(theta)) + ycenter
				xend = int(line_length * math.cos(theta)) + xcenter
				yend = int(line_length * math.sin(theta)) + ycenter
			
			help_msg = "%d. Client device\nMAC Address: %s\nProbe requests: %s" % (j, bssid, ssid)
			tag = "client%d" % j
			self.add_device("sta", xend, yend, tag, help_msg, ch, "Client%d"%j)
				#self.canvas.create_image(xend, yend, image=self.sta_image, tags=tag)
				#self.canvas1.create_line(xstart, ystart, xend, yend, fill="blue")
				#self.balloon.tagbind(self.canvas, tag, help_msg)
