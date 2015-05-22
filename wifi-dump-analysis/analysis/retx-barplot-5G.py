#Author : Abhinav Narain
#Date : 7-feb-2013
#Purpose : To plot the devices inside homes 
import sys, os, numpy, math, time
import matplotlib.font_manager
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.ticker import ScalarFormatter
import datetime as dt
# Figure dimensions                                                                                                   
fig_width = 30
fig_length = 30.25

MARKERS = ['b-+', 'g-x', 'c-s', 'm-^', 'y->', 'r-p']
MARKER_SUM = 'k-*'
MARKEVERY = 5
LEGEND_PROP = matplotlib.font_manager.FontProperties(size=6)

# Can be used to adjust the border and spacing of the figure    
fig_left = 0.12
fig_right = 0.94
fig_bottom = 0.25
fig_top = 0.94
fig_hspace = 0.5
row=1
column=1
ic=-1

color= ['black','blue','green','brown','red','purple','cyan','magenta','orange','yellow','pink', 'lime', 'olive', 'chocolate','navy',  'teal', 'gray', 'crimson',  'darkred' , 'darkslategray', 'violet', 'mediumvioletred' ,'orchid','tomato' , 'coral', 'goldenrod','tan', 'peru',  'sienna','rosybrown','darkgoldenrod','navajowhite','darkkhaki','darkseagreen' ,'firebrick','lightsteelblue']

try:
    import cPickle as pickle
except ImportError:
    import pickle

if __name__=='__main__':    
    print len(sys.argv)
    if len(sys.argv) !=2:
        print "usage : python unpickeler.py filename.png  "
        sys.exit(0)
    outfile_name = sys.argv[1]
    #path=sys.argv[2] #of pickle files 
    if '.eps' not in outfile_name and '.png' not in outfile_name:
        print "Do you really want to write graph to %s?" % (outfile_name)
        sys.exit(0)        
#setup for graph
    legend = []
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    aray=[]

    homes = [ 'OWC43DC7A3EDEC' , 'OWC43DC79DE112','OWC43DC7A37C01','OW2CB05DA0C23E','OW4C60DEE6B28F','OWA021B7A9BEF0','OWC43DC7B0AE1B' ]
    percentile = [5532.49333382, 4243377.15384,263994.393162,16820.12,8587.95 ,922.153,2662424.2]
    mean=        [17909.8448489,1231217.11,211149.186,19758.39,15647.46,154316.173,718685.267]
    retx =       [5.0741,0.5145,0.7665,2.1455,1.194,0.583,1.6653]


    _subplot = fig.add_subplot(1,1,1)

    #_subplot.scatter(mean,retx,s=1,color=color[ic],label=legend_elem)
    #done with creation
    width=0.35
    import numpy as np
    ind = np.arange(len(homes))        
    rects=_subplot.bar(ind,retx,width,color='red')
    _subplot.set_ylabel('Avg retransmission(retx/frame_count)')        
    g=[]
    for i in homes : 
        g.append(str(i))
    _subplot.set_xticks(ind+width)
    _subplot.set_xticklabels(g)
    #_subplot.legend(loc=0, prop=LEGEND_PROP, bbox_to_anchor=(0.1,- 0.05), scatterpoints=1)
    aray.append(rects[0])
    #legend_elem=file.strip('pickle.')
    #legend_elem=legend_elem.strip('^rate_')
    #legend.append(legend_elem)
    #print legend
    #print "========"
    #print aray
    #if len(aray) > 0:
     #   _subplot.legend(aray,legend)#,bbox_to_anchor=(0.1,- 0.05))
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

