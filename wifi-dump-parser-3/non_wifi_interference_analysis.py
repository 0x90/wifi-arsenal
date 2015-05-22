# Date : 10 September ,2013
#Purpose : To calculate the entropy of the physical layer error counters 
#          and plot the entropy of the counters
# Also calculates the FFT and Autocorrelation of an input series
# Runs on local machine so that $DISPLAY is accessible
import matplotlib.font_manager
import numpy as np
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg
import datetime as dt
import sys,os
from collections import defaultdict
from pylab import plot, show, title, xlabel, ylabel, subplot,savefig
from scipy import fft, arange
import pickle

fig_width = 12
fig_length = 12.25
# Can be used to adjust the border and spacing of the figure                   
fig_left = 0.12
fig_right = 0.94
fig_bottom = 0.25
fig_top = 0.94
fig_hspace = 0.5

def pickle_reader(input_folder):
    data_fs=os.listdir(input_folder)
    Physical_errors_table=defaultdict(list)
    for f_name in data_fs :
        _f_content= pickle.load(open(input_folder+f_name,'rb'))        
        router_id= _f_content[0]
        Physical_errors_table[router_id]=_f_content[1]
    return Physical_errors_table


def auto_correlation(y):
    import matplotlib.pyplot as plt
    import numpy as np
    fig = plt.figure()
    ax1 = fig.add_subplot(211)
    ax1.plot(y)
    #ax1.xcorr(y, y, usevlines=True, maxlags=50, normed=True, lw=2)
    ax1.grid(True)
    ax1.axhline(0, color='black', lw=2)
    ax2 = fig.add_subplot(212, sharex=ax1)
    ax2.acorr(y, usevlines=True, normed=True, maxlags=30, lw=2)    
    ax2.grid(True)
    ax2.axhline(0, color='black', lw=2)
    ax2.set_title('AutoCorrelation')
    plt.show() 


def mylog(val,base):
    if val:
        a= np.log(val)
        b=np.log(base)
        return (a*1.0 /b)
    else: 
        return 0

def new_entropy(a):
    num_bins=10
    counts, bin_edges = np.histogram(a,bins=num_bins,normed=True)
    cdf=np.cumsum(counts)
    scale = 1.0/cdf[-1]
    cdf=cdf*scale
    subplot(2,1,1)
    sorted=np.sort(counts)
    plot(counts,np.arange(len(sorted)*1.0)/len(sorted) )
    loc='hello'
    plot(bin_edges[1:],cdf,label=loc,color='r', linewidth=5.0)
    show()
    
def _e(labels):
    num_bins=10
    counts, bin_edges = np.histogram(labels,bins=num_bins,normed=True)
    cdf=np.cumsum(counts)
    scale = 1.0/cdf[-1]
    counts=counts*scale
    ent=0.
    for i in counts:        
        if i > 0:
            ent -= i * mylog(i, base=10)
    return ent

def entropy(labels):
    """ Computes entropy of label distribution. """    
    n_labels = len(labels)
    if n_labels <= 1:
        return 0
    counts = np.bincount(labels)    
    probs = counts / (n_labels*1.0)
    n_classes = np.count_nonzero(probs)
    if n_classes <= 1:
        return 0
    ent = 0.0    
    # Compute standard entropy.
    for i in probs:
        ent -= i * mylog(i, base=n_classes)
    return ent

def save_plotSpectrum(y,Fs,image_name):
    """
    Plots a Single-Sided Amplitude Spectrum of y(t)
    """
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    n = len(y) # length of the signal

    _subplot = fig.add_subplot(2,1,1)        
    print "Fi"
    _subplot.plot(arange(0,n),y)
    xlabel('Time')
    ylabel('Amplitude')
    _subploti_2=fig.add_subplot(2,1,2)
    k = arange(n)
    T = n/Fs
    frq = k/T # two sides frequency range
    frq = frq[range(n/2)] # one side frequency range

    Y = fft(y)/n # fft computing and normalization
    Y = Y[range(n/2)]

    _subplot_2.plot(frq,abs(Y),'r') # plotting the spectrum
    xlabel('Freq (Hz)')
    ylabel('|Y(freq)|')
    print "here"
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

def plotSpectrum(y,Fs,image_name):
    """
    Plots a Single-Sided Amplitude Spectrum of y(t)
    """
    n = len(y) # length of the signal
    subplot(2,1,1)
    
    plot(arange(0,n),y)
    xlabel('Time')
    ylabel('Amplitude')
    subplot(2,1,2)
    k = arange(n)
    T = n/Fs
    frq = k/T # two sides frequency range
    frq = frq[range(n/2)] # one side frequency range

    Y = fft(y)/n # fft computing and normalization
    Y = Y[range(n/2)]

    plot(frq,abs(Y),'r') # plotting the spectrum
    xlabel('Freq (Hz)')
    ylabel('|Y(freq)|')
    print "here"
    #show()
    savefig(image_name,dpi=110)

def print_image(x,y,x2,y2,outfile_name):
    fig = Figure(linewidth=0.0)
    fig.set_size_inches(fig_width,fig_length, forward=True)
    Figure.subplots_adjust(fig, left = fig_left, right = fig_right, bottom = fig_bottom, top = fig_top, hspace = fig_hspace)
    _subplot = fig.add_subplot(2,1,1)
    _subplot.set_title('Detection of Source generating non-wifi Interference')
    _subplot.plot(x,y,color='b')
    _subplot.set_xlabel('Time')
    _subplot.set_ylabel('Error Counts')
#    _subplot.set_ylim([0,1])
    _subplot2=fig.add_subplot(2,1,2)
    _subplot2.plot(x2,y2,color='r') # plotting the spectrum                     
    _subplot2.set_ylabel('Entropy')
    _subplot2.set_xlabel('Time')
    _subplot2.set_ylim([0,1])
    canvas = FigureCanvasAgg(fig)
    if '.eps' in outfile_name:
        canvas.print_eps(outfile_name, dpi = 110)
    if '.png' in outfile_name:
        canvas.print_figure(outfile_name, dpi = 110)

if 0:# __name__ =='__main__':
    '''
    Does processing of the physical layer errors
    in the each frame pickled by phy_err_stats.py
    '''
    if len(sys.argv)!=2:
        print "Usage: python file.py <folder with data>"
        sys.exit(1)
    input_f=sys.argv[1]
    Physical_errors_table=pickle_reader(input_f)
    global_data=[]
    for k,v in Physical_errors_table.iteritems() : # key is the router id        
        a=sorted(v,key=v.get)
        for i in a :
            d=v[i]
            phy_=d[0][0]
            phy_cck=d[0][1]
            phy_ofdm=d[0][2]
            global_data.append(phy_ofdm)

    y=[]
    for i in global_data:        
        for t in i : 
            if not(t[0]==0):
                y.append(t)

    time1= global_data[0][0][0]
    err_samples=[]
    temp_accumulator=0
    orig_ofdm_counts=[]
    orig_ofdm_time=[]
    sa=0
    er=0
    for i in range(1,len(y)) :
        sa=sa+1
        if y[i-1][0]>y[i][0] :
            er=er+1
        else: 
            orig_ofdm_counts.append(y[i][1])
            orig_ofdm_time.append(y[i][0])
            if y[i][0]-time1 <8334:
                temp_accumulator=temp_accumulator+y[i][1]
            else :
                err_samples.append(temp_accumulator)
                temp_accumulator=0
                time1=y[i][0]

    print er*100.0/(er+sa)
    e=[]
    t=[]
    print "before spectrum plotting " 
    plotSpectrum(err_samples,1000000/8334.0,'fft.png')
    print "done with printing spectrum "
    for i in range(0,len(err_samples),250):    
        #auto_correlation(err_samples[i:i+250])
        e.append(entropy(err_samples[i:i+250]))
        t.append(i)

    print_image(orig_ofdm_time,orig_ofdm_counts,t,e,'non_scaled_entropy_without_ofdm.png') 

#            print "ofdm",entropy(phy_ofdm[0:2000])
#            print "phy", entropy(phy_[0:2000])
#            print "cck",entropy(phy_cck[0:2000])


if __name__ =='__main__':
    '''
    Does processing of the timestamps of bad fcs frames
    collected by data
    ''' 
    if len(sys.argv)!=2:
        print "Usage: python file.py <folder with data>"
        sys.exit(1)
    input_f=sys.argv[1]
    Physical_errors_table=pickle_reader(input_f)
    global_data=[]
    for k,v in Physical_errors_table.iteritems() : # key is the router id        
        file_timestamps=sorted(v,key=v.get)
        for tstamp in file_timestamps :            
            d=v[tstamp]
            phy_=d[0]
            global_data.append(phy_)

    y=[]
    st=0
    for i in global_data: 
        for t in i : 
            y.append(t)
    err_samples=[]
    temp_accumulator=0
    orig_ofdm_counts=[]
    orig_ofdm_time=[]
    sa=0
    er=0
    time1= y[0][0]
    for i in range(1,len(y)) :
        sa=sa+1
        if y[i-1][0]>y[i][0] :
            er=er+1
        else: 
            orig_ofdm_counts.append(y[i][1])
            orig_ofdm_time.append(y[i][0])
            if y[i][0]-time1 <8334:
                temp_accumulator=temp_accumulator+y[i][1]
            else :
                err_samples.append(temp_accumulator)
                temp_accumulator=0
                time1=y[i][0]

    print "% error=",er*100.0/(er+sa)
    e=[]
    t=[]
    print "before spectrum plotting " 
    save_plotSpectrum(err_samples,1000000/8334.0,'fft.png')
    print "done with printing spectrum "
    for i in range(0,len(err_samples),250):    
        #auto_correlation(err_samples[i:i+250])
        e.append(entropy(err_samples[i:i+250]))
        t.append(i)

    print_image(orig_ofdm_time,orig_ofdm_counts,t,e,'non_scaled_entropy_without_ofdm.png') 
