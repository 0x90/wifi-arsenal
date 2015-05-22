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
fig_width = 10
fig_length = 10.25

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
ic=0

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
    homes_percentile= {'OWC43DC7B0AE78':255808.333328,
            'OWC43DC7A3EDEC':5324897.62963,
            'OWC43DC7B0AE54':206037021.385,
            'OWC43DC7B0AE69':222976.907692,
            'OWC43DC7A37C01':4702.10769272,
            'OWC43DC79DE112':3994.10769224,
            'OWC43DC79B5D25':154413737.708,                 
            'OW2CB05DA0C23E':19108.8461538,
            'OW4C60DEE6B28F':90729796.2308,
            'OWA021B7A9BEF0':6751.21538472,    
            'OWC43DC7B0CAB6':92979085.9658,
            'OWC43DC7B0AE1B':802717.811966,
            }

    homes_mean= {'OWC43DC7B0AE78':179183.614151,
            'OWC43DC7A3EDEC':6186679.21124,
            'OWC43DC7B0AE54':52126422.1296,
            'OWC43DC7B0AE69':197027.26674,
            'OWC43DC7A37C01':204787.461194,
            'OWC43DC79DE112':37137.1772026,
            'OWC43DC79B5D25':86377849.7867,
            'OW2CB05DA0C23E':84594.6515146,
            'OW4C60DEE6B28F': 59912674.08, 
            'OWA021B7A9BEF0':20533.77,  
            'OWC43DC7B0CAB6': 72061887.8806,
                 'OWC43DC7B0AE1B':974623.77534
                 }
    homes_retx= {'OWC43DC7B0AE78':0.45445,
            'OWC43DC7A3EDEC':0.00352,
            'OWC43DC7B0AE54':0.0795,
            'OWC43DC7B0AE69':0.550,
            'OWC43DC7A37C01':5.0174,
            'OWC43DC79DE112':0.09238,
            'OWC43DC79B5D25':0.0,
            'OW2CB05DA0C23E':0.13295,
            'OW4C60DEE6B28F': 0.0,
            'OWA021B7A9BEF0':3.2324,    
            'OWC43DC7B0CAB6':0.0,
            'OWC43DC7B0AE1B':2.0348}

    sorted(homes_retx.items(), key=lambda x: x[1])
    sorted(homes_percentile.items(), key=lambda x: x[1])
    sorted(homes_mean.items(), key=lambda x: x[1])
    print homes_retx
    x=[]
    y=[]
    z=[]
    for i,j in homes_retx.iteritems():
        x.append(homes_mean[i])
        y.append(j)
        z.append(i)
    _subplot = fig.add_subplot(1,1,1)
    _subplot.set_xlabel('Delay between frames (microseconds)')
    _subplot.set_ylabel('retransmission(retx/frame tx)')
    for i in range(0,len(z)):
        _subplot.scatter(x[i],y[i],s=50,color=color[i],label=z[i])
    #done with creation
    #width=0.35
    #import numpy as np
    #ind = np.arange(len(homes))        
    #rects=_subplot.bar(ind,percentile,width,color='blue')
    #_subplot.set_ylabel('Delay(90th percentile)')        
    g=[]
    for i in z : 
        g.append(str(i))
    #_subplot.set_xticks(ind+width)
    #_subplot.set_xticklabels(g)
    #_subplot.legend(loc=0, prop=LEGEND_PROP, bbox_to_anchor=(0.1,- 0.05), scatterpoints=1)
    #aray.append(rects[0])
    #legend_elem=file.strip('pickle.')
    #legend_elem=legend_elem.strip('^rate_')
    #legend.append(legend_elem)
    #print legend
    #print "========"
    #print aray
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)

    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

