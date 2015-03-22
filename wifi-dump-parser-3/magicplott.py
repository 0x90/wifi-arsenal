#Data : Sept 10, 2013
#Purpose : Plotting functions for Wireless Data Capture Analysis
# File belongs to part of Data Parsing Library
import sys, os, numpy, math, time
import matplotlib.font_manager
import numpy as np
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg
import datetime as dt
from utils import *
try:
    import cPickle as pickle
except ImportError:
    import pickle
LEGEND_PROP = matplotlib.font_manager.FontProperties(size=7)
# Figure dimensions                                                                                                   

if 1 :
    fig_width = 10
    fig_length = 10.25
else :
    fig_width = 14
    fig_length = 14.25
# Can be used to adjust the border and spacing of the figure    
fig_left = 0.12
fig_right = 0.94
fig_bottom = 0.25
fig_top = 0.94
fig_hspace = 0.5
row=1
column=1
RATE_MARKERS = {
        1.0 :'+',2.0: 'x',5.5:'s',6.5:'o',11.0:'^',
        13.0:'H',18.0:'>',19.5:'h',26.0:'v',36.0:'p',
        39.0:'<',48.0:'*',54.0:'D',52.0:'1',58.5:'2',
        65.0:'3',78.0:'4',117.0 :'8',130.0:'_',
        104.0:'|',
        6.0: '$6$',#CARETDOWN,
        60.0: '$60$',#'CARETRIGHT',
        40.5: '$40.5$',#'CARETLEFT',
        45.0:  '$45$', #CARETUP,
        135.0 : '$135$', #'TICKDOWN',
        270.0: '$270$',#'TICKUP',
        108.0: '$108$',#'TICKRIGHT',
        120.0: '$120$',#'TICKLEFT'
        }

color= [ 'blue', 'green', 'brown', 'red', 'purple', 'cyan', 'magenta', 'orange', 'yellow', 'pink',
        'lime', 'olive', 'chocolate','navy', 'teal', 'gray', 'black',  'darkred' , 'darkslategray',
        'violet', 'mediumvioletred' ,'orchid','tomato' , 'coral', 'goldenrod', 'tan', 'peru',  'sienna',
        'rosybrown','darkgoldenrod','navajowhite','darkkhaki','darkseagreen' ,'firebrick','lightst','crimson',
        ]

def plotter_scatter_rssi_rate(x_axis,y_axis,x_axis_label,y_axis_label,title,outfile_name):
    '''
    device id array
    dictionary of array of (rate,rssi)
    x label
    y label
    title
    output file name
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    index=0
    for k,v in y_axis.iteritems():
        print 'k is', k
        #rssi, rates
        print len(v[1]), len(v[0])
        if len(v[1])>0 and len(v[0])>0 :                
            _subplot.scatter(v[1],v[0],color=color[index],label=k)
            index=index+1
            
    _subplot.minorticks_on()
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:        
        canvas.print_figure(outfile_name, dpi = 110)

def scatter_retx_contention(x_axis,y_axis,x_axis_label,y_axis_label,x_logscale,y_logscale,title,outfile_name):
    '''
    Input:
    x_axis: a dictionary of list of lists {a:[[rate,retx],[]]}
    y_axis: a dictionary of contention delay
    x label
    y label
    bool for x logscale
    bool for y logscale
    title
    Output:
    file name
    '''
    legend = []
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    #sorted(homes_percentile.items(), key=lambda x: x[1])
    index=0
    rates_encountered=[]
    li=[]
    lh=[]
    _subplot = fig.add_subplot(1,1,1)
    for key,rates_array in x_axis.iteritems():
        for val in range(0,len(rates_array)) :
            lp=None
#            print len(y_axis[key])
#            print "key is " , key
#            print "rates are ", rates_array
#            print "median is " , median(y_axis[key])
            if len(rates_array[val])==0 :
                break
            if val==0 :
                legend.append(key)
                lp=key
                lh.append(key)
            else:
                lp='_nolegend_'
            print rates_array[val][0]
            a = _subplot.scatter(rates_array[val][1], percentile(y_axis[key],90),s=50,color=color[index],marker=RATE_MARKERS[rates_array[val][0]],label=lp)
            #_subplot.boxplot(contention_table[key]),positions=rates_array[val][1])
            if rates_array[val][0] in rates_encountered:
                pass
            else:
                rates_encountered.append(rates_array[val][0])
                li.append(a)
        index = index+1
    legend2=_subplot.legend(li,RATE_MARKERS,bbox_to_anchor=(0.9,-0.05), prop=LEGEND_PROP,loc=2)
    _subplot.add_artist(legend2)
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)
    if x_logscale :
        _subplot.set_xscale('log')
    if y_logscale :
        _subplot.set_yscale('log')
#    _subplot.set_xlim([0,1])
#    _subplot.set_ylim([0,20])
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:        
        canvas.print_figure(outfile_name, dpi = 110)



def plotter_boxplot(x_axis,y_axis, x_axis_label, y_axis_label,title,outfile_name):
    '''
    x-Home Router Id labels 
    y-The percentage of RTS frames out of  RTS+CTS fraems expressed as percentage ; noise floor
    Gives the box plot of the percentage as the input
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    _subplot.boxplot(y_axis,notch=0, sym='+', vert=1, whis=1.5)
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot.set_ylabel(y_axis_label,fontsize=20)
    _subplot.set_xlabel(x_axis_label,fontsize=20)
    a= [i for i in range(0,len(x_axis))]
    _subplot.set_xticklabels(x_axis)
    _subplot.set_xticks(a)
    #_subplot.set_ylim([0,100])
    _subplot.set_title(title,fontsize=20)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)    
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)


def plotter_utilization_boxplot(x_axis,y_axis, x_axis_label, y_axis_label,title,outfile_name):
    '''
    plots utilization of channel
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    _subplot.boxplot(y_axis,notch=0, sym='+', vert=1, whis=1.5)
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    a= [i for i in range(0,len(x_axis))]
    _subplot.set_xticklabels(x_axis)
    _subplot.set_xticks(a)
    _subplot.set_ylim([0,100])
    _subplot.set_title(title)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)    
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)


def bar_graph_plotter(x_axis,y_axis ,x_axis_label, y_axis_label,title,outfile_name):
    '''
    x-axis is the label for all bitrates observed in home    
    y-axis is the frequency of bitrate normalized by that of the highest frame bitrate observed 
    '''
    ind = np.arange(len(x_axis))  # the x locations for the groups
    width = 0.35       # the width of the bars
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    rect1=_subplot.bar(ind,y_axis,width,color='b')
    _subplot.set_xlim([0,len(x_axis)])
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot.set_ylabel(y_axis_label,fontsize=17)
    _subplot.set_xlabel(x_axis_label,fontsize=17)
    _subplot.set_ylim([0,100])
    a= [i for i in range(0,len(x_axis))]
    _subplot.set_xticklabels(x_axis, fontsize=17)
    _subplot.set_xticks(a)
    _subplot.set_title(title)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def bar_graph_stacked_rate_plotter(rates,first_list,sec_list,title,x_axis_label,y_axis_label,outfile_name):
    '''
    Shows the stacked distribution of muticast bitrates
    x-axis is the bitrate label
    y-axis is the frequency of each bitrate normalized by the total number of frames observed
    '''
    ind = np.arange(len(rates))  # the x locations for the groups
    width = 0.35       # the width of the bars
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    rect1=_subplot.bar(ind,first_list,width,color='r')
    rect2=_subplot.bar(ind,sec_list,width,bottom=first_list,color='b')
    _subplot.legend((rect1[0],rect2[0]), ('Unicast frames','multicast frames'))
    _subplot.set_ylabel(y_axis_label,fontsize=17)
    _subplot.set_xlabel(x_axis_label,fontsize=17)
    a= [i for i in range(0,len(rates))]
    _subplot.set_xticklabels(rates)
    _subplot.set_xticks(a)
    _subplot.set_ylim([0,100])
    _subplot.set_title(title,fontsize=17)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)
 
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def bar_graph_plotter_distr(x_axis_1,y_axis_1 ,x_axis_2, y_axis_2,x_axis_label, y_axis_label,title_1,title_2,outfile_name):
    '''
    Depricated as Snoeren mentioned a scatterplot with specs to be plotted

    Shows the distribution of bitrates uplink and downlink as a bar graph
    Separate bar graphs for each path
    x-axis is the bitrate label
    y-axis is the frequency of each bitrate normalized by the total number of frames observed
    '''
    ind = np.arange(len(x_axis_1))  # the x locations for the groups
    width = 0.35       # the width of the bars
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(2,1,1)
    rect1=_subplot.bar(ind,y_axis_1,width,color='r')
    _subplot.set_ylim([0,1])
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    a= [i for i in range(0,len(x_axis_1))]
    _subplot.set_xticklabels(x_axis_1)
    _subplot.set_xticks(a)
    _subplot.set_title(title_1)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)
   
    ind = np.arange(len(x_axis_2))  # the x locations for the groups
    _subplot_2 = fig.add_subplot(2,1,2)
    rect2=_subplot_2.bar(ind,y_axis_2,width,color='b')
    #rect2=_subplot.bar(ind+width,y2_axis,color='g')
    #_subplot_2.legend((rect2[0]),('bitrates'))
    _subplot_2.set_ylim([0,1])
    _subplot_2.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))   
    _subplot_2.set_ylabel(y_axis_label)                                      
    _subplot_2.set_xlabel(x_axis_label)                                      
    a= [i for i in range(0,len(x_axis_2))]                                   
    _subplot_2.set_xticklabels(x_axis_2)                                       
    _subplot_2.set_xticks(a)                                                  
    _subplot_2.set_title(title_2)
    labels = _subplot_2.get_xticklabels()
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)



def bar_graph_subplots(device_ids,x_axes,y_axes,x_axis_label, y_axis_label,title,outfile_name):
    '''
    device ids in home
    x axes is the traffic type
    y axes is the frame count on of that access class type
    Plots one graph for a home with multiple devices in each subplot with the given information
    '''
    width = 1      # the width of the bars
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)

    for i in range(0,len(device_ids)):
        print x_axes[i]
        ind = np.arange(len(x_axes[i]))  # the x locations for the groups
        _subplot = fig.add_subplot(len(device_ids),1,i)
        rect1=_subplot.bar(ind,y_axes[i],width,color=color[i])
        _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
        _subplot.set_ylabel(y_axis_label)
        _subplot.set_xlabel(x_axis_label)
        #_subplot.set_xlim([0,10])
        #_subplot.set_yscale('log')
        d={0:'Video',
           1:'Voice',
           2:'Best Effort',
           3:'Background',
           8:'Multicast/Content After Beacon',
           }
        a=[]
        for j in range(0,len(x_axes[i])):
            a.append(d[x_axes[i][j]])
        _subplot.set_xticklabels(a)               
        #_subplot.set_xticks(a)        
        _subplot.set_title(title+ '('+device_ids[i]+')')
        labels = _subplot.get_xticklabels()
        for label in labels:
            label.set_rotation(30)  

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def scatter_plot_dev_retx(router_list,x_axis,y_axis,x_axis_label, y_axis_label, title, outfile_name,xlim,ylim):
    '''
    Plots the retransmission in network(90th percentile) vs number of devices per interval
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    legend=[]
    for i in range(0,len(router_list)):
        _subplot.scatter(x_axis[i],y_axis[i],s=50,color=color[i],marker='*',label=router_list[i]) 
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label,fontsize=17)
    _subplot.set_xlabel(x_axis_label,fontsize=17)
    _subplot.set_title(title,fontsize=17)
    _subplot.set_xlim(xlim)
    _subplot.set_ylim(ylim)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)  

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def scatter_contention(router_list,x_axis,y_axis,x_axis_label, y_axis_label, title,outfile_name,xlim,ylim):
    '''
    Plots the contention period(90th percentile) of different homes 
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    legend=[]
    for i in range(0,len(router_list)):        
        _subplot.scatter(x_axis[i], percentile(y_axis[i],90),s=100,color=color[i],label=router_list[i]) 
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)
    _subplot.set_xlim(xlim)
    _subplot.set_ylim(ylim)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)  

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)


def plot_timeseries(timeseries_ampdu,ampdu_list, timeseries_mpdu, mpdu_list, x_axis_label,y_axis_label,y2_axis_label,title,outfile_name, router_id):
    '''
    timestamps of every minute
    max mpdu size of observed in the minute (for ampdu and mpdu length)
    '''
    print "in plot timeseries"
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(2,1,1)
    dates=[dt.datetime.fromtimestamp(ts) for ts in timeseries_mpdu]
    _subplot.plot(dates,mpdu_list,'o',color=color[0],label=router_id) 
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)

    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)  
    _subplot_2 = fig.add_subplot(2,1,2)
    legend=[]
    dates_2=[dt.datetime.fromtimestamp(ts) for ts in timeseries_ampdu]
    _subplot_2.plot(dates_2,ampdu_list,'o',color=color[1],label=router_id) 
    _subplot_2.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
    _subplot_2.set_ylabel(y2_axis_label)
    _subplot_2.set_xlabel(x_axis_label)
    _subplot_2.set_title(title)

    labels = _subplot_2.get_xticklabels()
    for label in labels:
        label.set_rotation(30)
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def scatter_contention_per_class(router_list,x_axis,y_axis,x_axis_label, y_axis_label, title,outfile_name,xlim,ylim):
    '''
    Plots the contention period(9th percentile) of different homes 
    Input : router list
    Number of Devices/AP
    Dictionary of contention delay per access class
    title
    file output name
    {x,y}lim
    '''
    ACCESS_CLASS_MARKERS={
        0:'+',
        1:'o',
        2:'*',
        3:'x',
        8:'H'}
    N_ACCESS_CLASS_MARKERS={
        'Voice':'+',
        'Video':'o',
        'Best Effort':'*',
        'Background':'x',
        'CAB':'H'}
        
    ac_encountered=[]
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    legend=[]
    sp=[]
    nsp=[]    
    for i in range(0,len(router_list)): 
        ac_map=y_axis[i]
        at=1
        for ac_class,ac_contention_array in ac_map.iteritems():
        #print  "contention", ac_contention_array[0]
            if ac_class in ac_encountered:
                pass
            else:
                tsp=_subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color='b',marker=ACCESS_CLASS_MARKERS[ac_class]) 
                ac_encountered.append(ac_class)
                sp.append(tsp)
            if at==1:
                _subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color=color[i],marker=ACCESS_CLASS_MARKERS[ac_class],label=router_list[i]) 
                at=0
            else :
                _subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color=color[i],marker=ACCESS_CLASS_MARKERS[ac_class]) 


    legend2=_subplot.legend(sp,N_ACCESS_CLASS_MARKERS,bbox_to_anchor=(0.9,-0.05), prop=LEGEND_PROP,loc=2)
    _subplot.add_artist(legend2)
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)
    _subplot.set_xlim(xlim)
    _subplot.set_ylim(ylim)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)  

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def bitrate_up_down_link(router_id,rate_map,x_axis_label, y_axis_label,title,outfile_name):
    '''
    Plots the distribution of bitrates uplink and downlink
    '''
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    i,j=0,0
    max_x=0
    max_y=0
    more_than_seven_devices=0
    for device_id, rate_dict in rate_map.iteritems():
        print len(rate_map)
        if len(rate_map)>7:
            more_than_seven_devices=1
            break 
        if len(rate_map) >=2: 
            _subplot = fig.add_subplot((len(rate_map)/2) +1 ,2,i)
        else :
            _subplot = fig.add_subplot(1,2,i)
        rate_sum=sum(rate_dict.values()) 
        for rate_tuple,freq in rate_dict.iteritems():
            rate_tuple=list(rate_tuple)
            _subplot.scatter(rate_tuple[0],rate_tuple[1],s=freq*100/rate_sum,color=color[i])
            if rate_tuple[0]>max_x:
                max_x=rate_tuple[0]
            if rate_tuple[1]>max_y:
                max_y=rate_tuple[1] 
        _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
        _subplot.set_ylabel(y_axis_label)
        _subplot.set_xlabel(x_axis_label+'( '+device_id+' )')
        _subplot.set_xticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
        _subplot.set_yticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
        _subplot.set_xlim([0,max_x+2])
        _subplot.set_ylim([0,max_y+2])
        labels = _subplot.get_xticklabels()
        for label in labels:
            label.set_rotation(30)
        i=i+1
    outfile_name=outfile_name+'.png'
    fig.suptitle(title+'('+router_id+')',fontsize=20)
    #fig.tight_layout()
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)
    if not(more_than_seven_devices):
        return 
    fig_2 = Figure(linewidth=0.0)
    fig_2.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    device_count=0
    devices_plotted=[]
    for device_id, rate_dict in rate_map.iteritems():
        if device_count <=6:
            devices_plotted.append(device_id)
            _subplot = fig.add_subplot(6,2,device_count)
            rate_sum=sum(rate_dict.values())
            for rate_tuple,freq in rate_dict.iteritems():
                rate_tuple=list(rate_tuple)
                _subplot.scatter(rate_tuple[0],rate_tuple[1],s=freq*100/rate_sum,color=color[i])
                if rate_tuple[0]>max_x:
                    max_x=rate_tuple[0]
                if rate_tuple[1]>max_y:
                    max_y=rate_tuple[1]
            _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
            _subplot.set_ylabel(y_axis_label)
            _subplot.set_xlabel(x_axis_label+'( '+device_id+' )')
            _subplot.set_xticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
            _subplot.set_yticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
            _subplot.set_xlim([0,max_x+2])
            _subplot.set_ylim([0,max_y+2])
            labels = _subplot.get_xticklabels()
            for label in labels:
                label.set_rotation(30)
            if device_count==6:
                fig.suptitle(title+'('+router_id+' (part1))',fontsize=20)
                outfile_name=outfile_name+'_1.png'
                canvas = FigureCanvasAgg(fig)
                if '.eps' in outfile_name:
                    canvas.print_eps(outfile_name, dpi = 110)
                if '.png' in outfile_name:
                    canvas.print_figure(outfile_name, dpi = 110)
            device_count +=1
            i=i+1
        else :
            _subplot_2 = fig_2.add_subplot(len(rate_map)-6,2,j)
            rate_sum=sum(rate_dict.values())
            for rate_tuple,freq in rate_dict.iteritems():
                rate_tuple=list(rate_tuple)
                _subplot_2.scatter(rate_tuple[0],rate_tuple[1],s=freq*100/rate_sum,color=color[device_count])
                if rate_tuple[0]>max_x:
                    max_x=rate_tuple[0]
                if rate_tuple[1]>max_y:
                    max_y=rate_tuple[1]
            _subplot_2.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05))
            _subplot_2.set_ylabel(y_axis_label)
            _subplot_2.set_xlabel(x_axis_label+'( '+device_id+' )')
            _subplot_2.set_xticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
            _subplot_2.set_yticks([1.0,2.0,5.5,9.0,12.0,18.0,24.0,36.0,48.0,54.0,65.0,117.0,130.0])
            _subplot_2.set_xlim([0,max_x+2])
            _subplot_2.set_ylim([0,max_y+2])
            labels = _subplot_2.get_xticklabels()
            for label in labels:
                label.set_rotation(30)
            if device_count==max_device_count:
                outfile_name=outfile_name+'_2.png'
                fig_2.suptitle(title+'('+router_id+' (part2))',fontsize=20)
                canvas = FigureCanvasAgg(fig_2)
                if '.eps' in outfile_name:
                    canvas.print_eps(outfile_name, dpi = 110)
                if '.png' in outfile_name:
                    canvas.print_figure(outfile_name, dpi = 110)
            device_count +=1
            j=j+1

def scatter_utilization_throughput(x_axis,y_axis, x_axis_label, y_axis_label, title, outfile_name):
    '''
    Plots utilization vs throughput of Bismark AP in home
    '''

    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    legend=[]
    max_xlim=0
    for i in range(0,len(x_axis)):
        _subplot.scatter(x_axis[i], y_axis[i],s=25)
        if x_axis[i]>max_xlim:
            max_xlim=x_axis[i]
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label)
    _subplot.set_xlabel(x_axis_label)
    _subplot.set_title(title)
    _subplot.set_xlim([0,100])
    _subplot.set_ylim([0,max_xlim])
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def scatter_contention_for_quals(router_list,x_axis,y_axis,x_axis_label, y_axis_label, title,outfile_name,xlim,ylim):   
    '''
    Plots the contention period(9th percentile) of different homes
    Input : router list
    Number of Devices/AP
    Dictionary of contention delay per access class
    title
    file output name
    {x,y}lim
    '''
    ylim=[0,8000]
    ACCESS_CLASS_MARKERS={
        0:'+',
        1:'o',
        2:'*',
        3:'x',
        8:'H'}
    N_ACCESS_CLASS_MARKERS={
        'Best Effort':'*'
        }
    ac_encountered=[]
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(1,1,1)
    legend=[]
    sp=[]
    nsp=[] 
    for i in range(0,len(router_list)):
        ac_map=y_axis[i]
        at=1
        for ac_class,ac_contention_array in ac_map.iteritems():
            if  not (ac_class ==2):
                continue
            if ac_class in ac_encountered:
                pass
            else:
                tsp=_subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color='b',marker=ACCESS_CLASS_MARKERS[ac_class])
                ac_encountered.append(ac_class)
                sp.append(tsp)
            if at==1:
                _subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color=color[i],marker=ACCESS_CLASS_MARKERS[ac_class],label=router_list[i])
                at=0
            else :
                _subplot.scatter(x_axis[i], percentile(ac_contention_array[0],90),s=100,color=color[i],marker=ACCESS_CLASS_MARKERS[ac_class]) 


    legend2=_subplot.legend(sp,N_ACCESS_CLASS_MARKERS,bbox_to_anchor=(1.9,-0.05), prop=LEGEND_PROP,loc=2)
    _subplot.add_artist(legend2)
    _subplot.legend(loc=0, prop=LEGEND_PROP,bbox_to_anchor=(0.1,- 0.05),scatterpoints=1)
    _subplot.set_ylabel(y_axis_label,fontsize=20)
    _subplot.set_xlabel(x_axis_label,fontsize=20)
    _subplot.set_title(title,fontsize=20)
    _subplot.set_xlim(xlim)
    _subplot.set_ylim(ylim)
    labels = _subplot.get_xticklabels()
    for label in labels:
        label.set_rotation(30)

    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)
