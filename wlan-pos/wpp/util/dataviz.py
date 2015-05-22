#!/usr/bin/env python
from __future__ import division
import os
import sys
import getopt
import string
import time
import csv

from pprint import pprint,PrettyPrinter
import numpy as np
import matplotlib as mpl
#import matplotlib.pylab as mlab
import matplotlib.pyplot as plt
#import Gnuplot, Gnuplot.funcutils

from offline import dumpCSV
from online import fixPos, getWLAN
from gps import getGPS
from config import WLAN_FAKE, LOCPATH, LOCSUFFIX, RADIUS, icon_types, props_jpg
from geo import dist_unit
from map import GMap, Icon, Map, Point


def usage():
    import time
    print """
online.py - Copyleft 2009-%s Yan Xiaotian, xiaotian.yan@gmail.com.
Location fingerprinting using deterministic/probablistic approaches.

usage:
    offline <option> <infile>
option:
    -e --eval=<loc file(s)> :  Evaluate fingerprinting quality for records in loc file,
                               including sample count, mean/max error, std, CDF/histogram viz.
    -f --fakewlan=<mode id> :  Fake AP scan results in case of bad WLAN coverage.
                               <mode id> same as in WLAN_FAKE of config module.
    -g --gpsfake            :  Fake coords results in case of bad GPS coverage.
    -m --map=<loc file(s)>  :  Pinpoint fix/ref point pairs in <loc file> into GMap.
    -t --test               :  Online fingerprinting test with related info logged in loc file.
    -h --help               :  Show this help.
    -v --verbose            :  Verbose mode.
example:
    #sudo python test.py -t 
    #python test.py -e /path/to/locfile -v
""" % time.strftime('%Y')


def solveCDF(data=None, pickedX=None):
    """ 
    Parameters
    ----------
    data: sequence that contains what to be solved.
    pickedX: selected X=[x1, x2, ...] that play as xtics in CDF graph.

    Returned
    ----------
    ( X(sampled sorted data), Y(probs), [ [x(.67),.67], [x(.95),.95] ] )
    """
    # CDF calculation and visualization.
    cnt_tot = len(data)
    sortData = np.array( sorted(data) )
    probs = [sortData.searchsorted(x,side='right')/cnt_tot for x in pickedX]

    feat_probs = [.67, .95]
    feat_points = [ sortData[int(rat*cnt_tot)] for rat in feat_probs ]
    X = list(pickedX[:])
    X.extend(feat_points)
    probs.extend(feat_probs)

    X=sorted(X); probs=sorted(probs)

    return (X, probs, zip(feat_points,feat_probs))


def getStats(data=None):
    """ 
    Get total count, mean/max val, standard deviation of values.
    data: data sequence.
    Returns
    -------
    (cnt_tot, mean, min, max, stdev)
    """
    dat = np.array(data)
    cnt_tot = len(dat)
    mean = dat.mean()
    max = dat.max()
    min = dat.min()
    stdev = dat.std(ddof=1)
    return (cnt_tot, mean, min, max, stdev)


def pyplotCDF(data=None, figmainname=None, ofmt='png'):
    """
    Plot CDF, histogram and featured points (with prob: 0.67,0.95), using Matplotlib.pyplot
    Input
    -----
    data: data sequence tobe plotted.
    figmainname: main part of savefig file name, the naming format for savefig:
        cdf_<figmainname>_<featstyle>.png
    """
    cntallerr, meanerr, minerr, maxerr, stdeverr = getStats(data)
    print '%8s  %-10s%-10s%-10s\n%s\n%8d  %-10.2f%-15.2f%-10.2f' % \
            ('count', 'mean(m)', 'max(m)', 'stdev(m)', '-'*38, 
            cntallerr, meanerr, maxerr, stdeverr)

    cdf_color = 'b'; hist_color = 'g'
    bins = int(maxerr - minerr)
    log = False
    if bins < 1: 
        bins = 1
    elif bins > 10000 and maxerr > 10000: 
        #log=True
        bins = 10000
        plt.xscale('log')
        mpl.rcParams['font.size'] = 10
        data = np.sort(data)[:-6]
    plt.hist(data, bins=bins, cumulative=True, normed=True, alpha=.6, log=log,
        histtype='step', linewidth=1.5, edgecolor=cdf_color, label='CDF')
    plt.hist(data, bins=bins, cumulative=False, normed=True, log=log,
        histtype='bar', rwidth=1, alpha=0.6, facecolor=hist_color, label='Histogram')

    #ax = plt.subplot(111)

    plt.grid(False)
    plt.axhline(1, color='k', linestyle='dotted')
    plt.ylim([0, 1.05])

    plt.yticks([0, .67, .95, 1, 1.05],['0', '0.67', '0.95', '1', ''])
    leg_err = 'mean: %.2fm, max: %.2fm, stdev: %.2fm' % (meanerr, maxerr, stdeverr)
    plt.xlabel('Error/m\n(%s)' % leg_err)
    plt.ylabel('Probability')
    plt.title('CDF & Histogram (samples: %d, %s)' % (cntallerr,figmainname))

    # Solve error values for feature points with probability 0.67/0.95.
    x, y, feat_pts = solveCDF(data=data, pickedX=data) 

    # Plot CDF points with probability: 0.67 and 0.95.
    feat_lc = 'r'
    for pt in feat_pts:
        x = pt[0]; y = pt[1]
        plt.axhline(y, color=feat_lc, linestyle='dotted', linewidth=1.1)

        # Dot the featured points out, NOT accurate for coords.
        #plt.plot([x], [y], 'o', color='black', label=None, markersize=5)

        # Annotate featured points with arrow and text, e.g. fig/cdf_2010-0409_anno.png.
        # xy:position of arrow end, xytext:(xratio, yratio).
        # featstyle: Style of illustration for featured points, 
        #  including annotated(with arrow), or pure text attached.
        #featstyle = 'anno' 
        #plt.annotate('%d%%: %.2fm'%(int(y*100),x), 
        #        xy=(x,y), xytext=(x/maxerr*1.15, y-.15), 
        #        arrowprops=dict(facecolor='black', shrink=0.1), 
        #        textcoords='axes fraction', xycoords='data', 
        #        horizontalalignment='right', verticalalignment='top')

        # Label the featured points with pure text, e.g. fig/cdf_2010-0409_puretxt.png.
        featstyle = 'puretxt'
        if x/maxerr > 0.7: ha = 'right'
        else: ha = 'left'
        plt.text(x, y,'\n %d%%: %.2fm'%(int(y*100), x),
             rotation=0, fontsize=14, color=feat_lc,
             horizontalalignment = ha,
             verticalalignment   = 'top',
             multialignment      = 'center')

    # Legend.
    plt.legend(shadow=True, loc=7)
    ltext = plt.gca().get_legend().get_texts()
    plt.setp(ltext[0], color=cdf_color)
    plt.setp(ltext[1], color=hist_color)

    figfilename = 'cdf_%s_%s.%s' % (figmainname, featstyle, ofmt)
    plt.savefig(figfilename)
    plt.close()


def plotCDF(X=None, Y=None, props=None, pts=None, verb=0):
    """ 
    plot 2D line(X,Y) and points(pts) with properties 'props' using gnuplot.
    Note: Commented lines go with gplot mp latex term.
    """
    #TODO: support more than one cdf plot: [ [X,Y], ... ]
    if not X or not Y: print 'Invalid input data!'; sys.exit(99)
    if not props: props = props_jpg
    g = Gnuplot.Gnuplot(debug=verb)
    g('set terminal %s font %s' % (props['term'], props['font']))
    outp = 'set output "%s"' % props['outfname']; g(outp)
    ti = 'set title "%s"' % props['title']; g(ti)

    if props['size']: g('set size %s' % props['size'])
    g('set border %s' % props['border'])
    if props['grid']: g('set grid %s' % props['grid'])
    g('set key %s' % props['key'])

    g.xlabel('%s' % props['xlabel'])
    g.ylabel('%s' % props['ylabel'])
    g('set xrange [%s:%s]' % (props['xrange'][0], props['xrange'][1])) 
    g('set yrange [%s:%s]' % (props['yrange'][0], props['yrange'][1])) 
    g('set xtics %s' % props['xtics']) 
    g('set ytics %s' % props['ytics']) 

    if props['with']: utils = props['with']
    else: utils = 'lp'
    if props['legend']: leg = props['legend']
    else: leg = props['title']

    gCDF = Gnuplot.Data(X, Y, title=props['legend'], with_=utils)

    x67, y67 = pts[0]; x95, y95 = pts[1]
    gPt67 = Gnuplot.Data(x67, y67, title='%.2fm: 67%%' % x67, with_='p pt 4 ps 2')
    gPt95 = Gnuplot.Data(x95, y95, title='%.2fm: 95%%' % x95, with_='p pt 8 ps 2')

    g.plot(gCDF, gPt67, gPt95)


def renderGMap(mapfile='html/map.htm', refpt=None, fix_err=None, mapcenter=None):
    """ 
        Plot point pairs  into GMap.
        refpt: [ reflat, reflon ]
       fix_err: [ [fixpoint1, err1], ... ]
    """
    icon_fix = Icon('fixloc'); icon_ref = Icon('refloc')
    cwd = os.getcwd()
    icon_fix.image  = cwd + icon_types['yellowdot'][1]
    icon_ref.image  = cwd + icon_types['reddot'][1]
    icon_fix.shadow = icon_ref.shadow = cwd + icon_types['dotshadow'][1]

    ptlist = []
    for idx,pt_err in enumerate(fix_err):
        fixloc = [ pt_err[0], pt_err[1] ]
        err = pt_err[2]
        ptFix = Point(loc=fixloc, 
                      txt=str(idx)+': Alg: '+'<br>'+str(fixloc)+'<br>Err: '+str(err)+'m', 
                      iconid='fixloc')     
        ptlist.append(ptFix)
    ptRef = Point(loc=refpt, 
                  txt='Ref: '+'<br>'+str(refpt), 
                  iconid='refloc')     
    ptlist.append(ptRef)

    gmap = GMap(maplist=[Map(pointlist=ptlist)], iconlist=[icon_fix, icon_ref])
    if mapcenter: gmap.maps[0].center = mapcenter
    else: gmap.maps[0].center = refpt
    gmap.maps[0].width = "1260px"; gmap.maps[0].height = "860px"
    gmap.maps[0].zoom  = 17

    print '\nicon types: (img: null when default)\n%s' % ('-'*35)
    for icon in gmap._icons: print 'id:\'%-5s\' img:\'%s\'' % (icon.id, icon.image)
    print 'maps: \n%s' % ('-'*35)
    for map in gmap.maps: 
        print 'id:\'%s\',\t(10 out of %d)points:' % (map.id, len(map.points))
        for point in map.points[:10]: 
            print point.getAttrs()

    open(mapfile, 'wb').write(gmap.genHTML())


def testLoc(wlanfake=0, gpsfake=False, verbose=False):
    # Get WLAN scanning results.
    len_visAPs, wifis = getWLAN(wlanfake)

    # Fix current position.
    fixloc = fixPos(len_visAPs, wifis, verbose)
    #fixloc = [ 39.922848,116.472895 ]
    print 'fixed location: \n%s' % fixloc

    # Get GPS referenced Position.
    if not gpsfake: refloc = getGPS()
    else: refloc = [ 39.922648,116.472895 ]
    print 'referenced location: \n%s' % refloc

    # Log the fixed and referenced positioning record.
    # Logging format: [ timestamp, MAC1|MAC2..., fLat, fLon, rLat, rLon ].
    timestamp = time.strftime('%Y-%m%d-%H%M')
    visMACs = '|'.join(wifis[0])
    #error = dist_unit(fixloc[0], fixloc[1], refloc[0], refloc[1])*RADIUS
    locline = [ timestamp, visMACs, fixloc[0], fixloc[1], refloc[0], refloc[1] ]
    print 'locline:\n%s' % locline

    date = time.strftime('%Y-%m%d')
    locfilename = LOCPATH + date + LOCSUFFIX
    dumpCSV(locfilename, locline)


def getHist(data=None):
    """ 
    Get statistical histogram for data sequence. 
    Returns
    -------
    hist as dictionary.
    """
    hist = {}
    for elem in set(data):
        hist[elem] = list(data).count(elem)
    return hist


def main():
    try: opts, args = getopt.getopt(sys.argv[1:], 
            "e:f:ghm:tv",
            ["eval=","fakewlan=","gpsfake","help","map=","test","verbose"])
    except getopt.GetoptError:
        print 'Error: getopt!\n'
        usage(); sys.exit(99)

    # Program terminated when NO argument followed!
    if not opts: usage(); sys.exit(0)

    verbose = False; wlanfake = 0; gpsfake = False
    eval = False; test = False; makemap = False

    for o,a in opts:
        if o in ("-e", "--eval"):
            if not os.path.isfile(a):
                print 'Loc file NOT exist: %s!' % a
                sys.exit(99)
            else: 
                eval = True
                makemap = True
                locfiles = [ arg for arg in sys.argv[2:] if not arg.startswith('-') ]
        elif o in ("-f", "--fake"):
            if a.isdigit(): 
                wlanfake = string.atoi(a)
                if wlanfake >= 0: continue
                else: pass
            else: pass
            print '\nIllegal fake WLAN scan ID: %s!' % a
            usage(); sys.exit(99)
        elif o in ("-g", "--gpsfake"):
            gpsfake = True
        elif o in ("-h", "--help"):
            usage(); sys.exit(0)
        elif o in ("-m", "--map"):
            if not os.path.isfile(a):
                print 'Loc file NOT exist: %s!' % a
                sys.exit(99)
            else: 
                makemap = True
                locfiles = [ arg for arg in sys.argv[2:] if not arg.startswith('-') ]
        elif o in ("-t", "--test"):
            test = True
        elif o in ("-v", "--verbose"):
            verbose = True
            pp = PrettyPrinter(indent=2)
        else:
            print 'Parameter NOT supported: %s' % o
            usage(); sys.exit(99)

    # Check if the logging dir exists.
    if not os.path.isdir(LOCPATH):
        try: 
            os.umask(0) #linux system default umask: 022.
            os.mkdir(LOCPATH,0777)
            #os.chmod(LOCPATH,0777)
        except OSError, errmsg:
            print "Failed: %d" % str(errmsg)
            sys.exit(99)

    if test: testLoc(wlanfake, gpsfake)

    if eval:
        for locfile in locfiles:
            # Evaluate the count, mean error, std deviation for location records in locfile,
            # optionally, the fixloc and refloc point pairs can be drawn in gmap.
            if not os.path.isfile(locfile):
                print 'loc file NOT exist: %s!' % locfile
                continue

            locin = csv.reader( open(locfile, 'r') )
            try:
                pointpairs = np.array([ locline for locline in locin ])[:,2:].astype(float)
            except csv.Error, e:
                sys.exit('\nERROR: %s, line %d: %s!\n' % (locfile, locin.line_num, e))
            fixcoords = pointpairs[:,:2]
            meanref = np.mean(pointpairs[:,2:], axis=0)
            # Referenced mean location for 2010-0409.
            timestamp = locfile[ locfile.rfind('/')+1 : locfile.rfind('.') ]
            if timestamp == '2010-0409': 
                meanref = [39.89574823, 116.344701]
            elif timestamp == '2010-0402_hq': 
                meanref = [39.909994, 116.353309]
            errors = [ dist_unit(flat, flon, meanref[0], meanref[1])*RADIUS
                       for flat,flon in fixcoords ]
            # fixpt_err: [ [lat1, lon1, err1], ... ].
            fixpt_err = np.append(fixcoords, [[err] for err in errors], axis=1)

            if verbose: 
                print 'Histogram(err: count):'
                pp.pprint( getHist(errors) )

            # Solve regular/cumulative histogram for 'errors'.
            pyplotCDF(data=errors, figmainname=timestamp)

            # Deprecated: Gnuplot style CDF plotting.
            #if maxerr < 10: 
            #    xtics = 1
            #elif 10 <= maxerr < 100: 
            #    xtics = 20
            #elif 100 <= maxerr < 500: 
            #    xtics = 50
            #elif 500 <= maxerr < 1000: 
            #    xtics = 75
            #elif 1000 <= maxerr < 2000: 
            #    xtics = 150
            #else:
            #    print '\n!!!Max Err: %10.2f!!!\n' % maxerr
            #    xtics = maxerr/10
            #xmax = (int(maxerr/xtics)+1)*xtics
            #x = range(0, xmax+5*xtics+1, xtics)
            #x, y, feat_pts = solveCDF(data=errors, pickedX=x) 

            #props_jpg['legend'] = locfile[locfile.rfind('/')+1:locfile.rfind('.')]
            #props_jpg['outfname'] = 'cdf_' + props_jpg['legend'] + '.jpg'
            #props_jpg['xrange'] = [0, xmax+5*xtics]
            #props_jpg['xtics'] = xtics
            #plotCDF(X=x, Y=y, props=props_jpg, pts=feat_pts, verb=0)

            # GMap html generation.
            if makemap:
                mapfname = 'html/map_' + timestamp + '.html'
                renderGMap(mapfile=mapfname, refpt=meanref, fix_err=fixpt_err)

            sys.exit(0)

    if makemap:
        for locfile in locfiles:
            # Make GMap with fix/ref point pairs in locfile(s).
            if not os.path.isfile(locfile):
                print 'loc file NOT exist: %s!' % locfile
                continue

            locin = csv.reader( open(locfile, 'r') )
            try:
                pointpairs = np.array([ locline for locline in locin ])[:,2:].astype(float)
            except csv.Error, e:
                sys.exit('\nERROR: %s, line %d: %s!\n' % (locfile, locin.line_num, e))
            fixcoords = pointpairs[:,:2]
            meanref = np.mean(pointpairs[:,2:], axis=0)
            # Referenced mean location for 2010-0409.
            timestamp = locfile[ locfile.rfind('/')+1 : locfile.rfind('.') ]
            if timestamp == '2010-0409': 
                meanref = [39.89574823, 116.344701]
            elif timestamp == '2010-0402_hq': 
                meanref = [39.909994, 116.353309]
            errors = [ [dist_unit(flat, flon, meanref[0], meanref[1])*RADIUS]
                       for flat,flon in fixcoords ]
            # fixpt_err: [ [lat1, lon1, err1], ... ].
            fixpt_err = np.append(fixcoords, errors, axis=1)
            timestamp = locfile[ locfile.rfind('/')+1 : locfile.rfind('.') ]
            mapfname = 'html/map_' + timestamp + '.html'
            renderGMap(mapfile=mapfname, refpt=meanref, fix_err=fixpt_err)


if __name__ == "__main__":
    try:
        import psyco
        psyco.bind(solveCDF)
        psyco.bind(getStats)
        psyco.bind(pyplotCDF)
        psyco.bind(plotCDF)
        psyco.bind(getHist)
        psyco.bind(renderGMap)
        psyco.bind(testLoc)
        #psyco.full()
        #psyco.log()
        #psyco.profile(0.3)
    except ImportError:
        pass

    #main()

    csvin = csv.reader( open(sys.argv[1],'r') )
    errs = np.array([ line for line in csvin ])[:,0].astype(float)

    pyplotCDF(errs, 'test')
