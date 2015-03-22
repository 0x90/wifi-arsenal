# Copyright (c) 2009 Emiliano Pastorino <emilianopastorino@gmail.com>
#
# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#



import matplotlib
matplotlib.use('GTKAgg')
matplotlib.interactive(True)
import matplotlib.pyplot as pyplot
import matplotlib.pylab as pylab

class Plotter():

	def __init__(self,xval,yval,tags,title):
		self.colors = ('#ff0000','#00ff00','#0000ff','#ffff00','#ff00ff','#00ffff','#800000','#008000','#000080','#808000','#800080','#008080','#ff8000','#ff0080','#00ff80','#ff00c0','#ffc000','#c0ff00','#00ffc0','#00c0ff')
		self.xval = xval
		self.yval = yval
		self.tags = tags
		self.title = title
	
	def simpleplot(self):
		fig = pyplot.figure()
		j=0
		lineas=[]
		for i in self.yval:
			linea = pyplot.plot(self.xval,i,self.colors[j])
			lineas.append(linea[0])
			j=j+1
			if j>19:
				j = 0
		pyplot.legend(lineas,self.tags,'best')
		pyplot.xlabel('Time (s)')
		pyplot.ylabel('Airtime consumption (%)')
		pyplot.title(self.title)
		pyplot.grid(True)
		pyplot.show()

	def stackareaplot(self):
		fig = pyplot.figure()
		lineas=[]
		stack = []
		k=0
		for i in self.yval:
			stack.append(i)
			m=0
			for j in i:
				if k > 0:
					stack[k][m]=stack[k][m]+stack[k-1][m]
					m = m+1
			k=k+1
	
		j=0
		xss=[]
		yss=[]
		used_colors=[]
		for i in stack:
			linea = pyplot.plot(self.xval,i,self.colors[j])
			used_colors.append(self.colors[j])
			lineas.append(linea[0])
			xs,ys = pylab.poly_between(self.xval,0,i)
			xss.append(xs)
			yss.append(ys)
			j=j+1
			if j>19:
				j = 0
		j=0
		k=-1
		used_colors_inv = used_colors[::-1]
		for i in yss:
			pylab.fill(xss[0], yss[k], used_colors_inv[j])
			j=j+1
			k=k-1
		pyplot.legend(lineas,self.tags,'best')
		pyplot.title(self.title)
		pyplot.xlabel('Time (s)')
		pyplot.ylabel('Airtime consumption (%)')
		pyplot.grid(True)
		pyplot.show()

class Test():

	def simpleplot(self):
		plt = Plotter([0,20],[[0,1],[0,2],[0,3],[0,4],[0,5],[0,6],[0,7],[0,8],[0,9],[0,10],[0,11],[0,12],[0,13],[0,14],[0,15],[0,16],[0,17],[0,18],[0,19],[0,20]],['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t'],'hola')
		plt.simpleplot()

#	def stackareaplot(self):
#		plt = Plotter([0,20],[[0,1],[0,2],[0,3],[0,4],[0,5],[0,6],[0,7],[0,8],[0,9],[0,10],[0,11],[0,12],[0,13],[0,14],[0,15],[0,16],[0,17],[0,18],[0,19],[0,20]],['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t'],'hola')
#		plt.stackareaplot()

	def stackareaplot(self):
		
		plt = Plotter([0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000, 2100, 2200, 2300],[[0.010666335555555581, 0.0088586274074074108, 0.0059840918518518455, 0.00031296111111111114, 0.0086995377777777903, 0.010214910185185212, 0.0044641161111111079, 0.038744648888889052, 0.021350007407407605, 0.002331960185185185, 0.0013770194444444447, 0.00067598759259259258, 8.3303703703703709e-06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0.010666335555555581, 0.0088586274074074108, 0.0059840918518518455, 0.00031296111111111114, 0.0086995377777777903, 0.010214910185185212, 0.0044641161111111079, 0.038744648888889052, 0.021350007407407605, 0.002331960185185185, 0.0013770194444444447, 0.00067598759259259258, 8.3303703703703709e-06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],['a','b'],'hola')
		plt.stackareaplot()
