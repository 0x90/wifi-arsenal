#!/usr/bin/env python
""" subpanels.py - defines the subpanels called by the wraith Master panel """

__name__ = 'subpanels'
__license__ = 'GPL v3.0'
__version__ = '0.0.3'
__revdate__ = 'March 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                                  # file info etc
import re                                  # reg. exp.
import Tix                                 # Tix gui stuff
import mgrs                                # for mgrs2latlon conversions etc
import math                                # for conversions, calculations
from PIL import Image,ImageTk              # image input & support
import ConfigParser                        # config file parsing
import wraith                              # version info & constants
import wraith.widgets.panel as gui         # graphics suite
from wraith.radio.iw import IW_CHWS        # channel width list
from wraith.radio.iwtools import wifaces   # check nic validity
from wraith.dyskt.dyskt import parsechlist # channelist validity check

# Validation reg. exp.
IPADDR = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") # re for ip addr
MACADDR = re.compile("^([0-9A-F]{2}:){5}([0-9A-F]{2})$")    # re for mac addr (capital letters only)
GPSDID = re.compile("^[0-9A-F]{4}:[0-9A-F]{4}$")            # re for gps device id (capital letss only)

# Some constants
COPY = u"\N{COPYRIGHT SIGN}"

#### MENU PANELS

# Wraith->Configure
class WraithConfigPanel(gui.ConfigPanel):
    """ Display Wraith Configuration Panel """
    def __init__(self,toplevel,chief):
        gui.ConfigPanel.__init__(self,toplevel,chief,"Configure Wraith")

    def _makegui(self,frm):
        """ set up entry widgets """
        # Storage Configuration
        frmS = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmS.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmS,text='STORAGE').grid(row=0,column=0,columnspan=2,sticky=Tix.W)
        Tix.Label(frmS,text='Host: ').grid(row=1,column=0,sticky=Tix.W)
        self.txtHost = Tix.Entry(frmS,width=15)
        self.txtHost.grid(row=1,column=1,sticky=Tix.E)
        Tix.Label(frmS,text='DB: ').grid(row=2,column=0,sticky=Tix.W)
        self.txtDB = Tix.Entry(frmS,width=15)
        self.txtDB.grid(row=2,column=1,sticky=Tix.E)
        Tix.Label(frmS,text='User: ').grid(row=3,column=0,sticky=Tix.W)
        self.txtUser = Tix.Entry(frmS,width=15)
        self.txtUser.grid(row=3,column=1,sticky=Tix.E)
        Tix.Label(frmS,text='PWD: ').grid(row=4,column=0,sticky=Tix.W)
        self.txtPWD = Tix.Entry(frmS,width=15)
        self.txtPWD.grid(row=4,column=1,sticky=Tix.E)

        # Policy Configuration
        frmP = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmP.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmP,text='POLICY').grid(row=0,column=0,sticky=Tix.W)

        # polite
        Tix.Label(frmP,text="Polite:").grid(row=1,column=0,sticky=Tix.W)
        self.ptype = Tix.IntVar(self)
        self.rdoPoliteOn = Tix.Radiobutton(frmP,text='On',
                                           variable=self.ptype,value=1)
        self.rdoPoliteOn.grid(row=1,column=1,sticky=Tix.W)
        self.rdoPoliteOff = Tix.Radiobutton(frmP,text='Off',
                                            variable=self.ptype,value=0)
        self.rdoPoliteOff.grid(row=2,column=1,sticky=Tix.W)

        # separator label
        Tix.Label(frmP,text=" ").grid(row=1,column=2)

        # shutdown
        Tix.Label(frmP,text="Shutdown:").grid(row=1,column=3,sticky=Tix.W)
        self.stype = Tix.IntVar(self)
        self.rdoShutdownAuto = Tix.Radiobutton(frmP,text='Auto',
                                               variable=self.stype,value=1)
        self.rdoShutdownAuto.grid(row=1,column=4,sticky=Tix.W)
        self.rdoShutdownManual = Tix.Radiobutton(frmP,text='Manual',
                                                 variable=self.ptype,value=0)
        self.rdoShutdownManual.grid(row=2,column=4,sticky=Tix.W)

    def _initialize(self):
        """ insert values from config file into entry boxes """
        conf = ConfigParser.RawConfigParser()
        if not conf.read(wraith.WRAITHCONF):
            self.err("File Not Found","File wraith.conf was not found")
            return

        # in case the conf file is invalid, set to empty if not present
        self.txtHost.delete(0,Tix.END)
        if conf.has_option('Storage','host'):
            self.txtHost.insert(0,conf.get('Storage','host'))
        else: self.txtHost.insert(0,'')

        self.txtDB.delete(0,Tix.END)
        if conf.has_option('Storage','db'):
            self.txtDB.insert(0,conf.get('Storage','db'))
        else: self.txtDB.insert(0,'')

        self.txtUser.delete(0,Tix.END)
        if conf.has_option('Storage','user'):
            self.txtUser.insert(0,conf.get('Storage','user'))
        else: self.txtUser.insert(0,'')

        self.txtPWD.delete(0,Tix.END)
        if conf.has_option('Storage','pwd'):
            self.txtPWD.insert(0,conf.get('Storage','pwd'))
        else: self.txtPWD.insert(0,'')

        if conf.has_option('Policy','polite') and conf.get('Policy','polite').lower() == 'off':
            self.ptype.set(0)
        else:
            self.ptype.set(1)

        if conf.has_option('Policy','shutdown') and conf.get('Policy','shutdown').lower() == 'manual':
            self.stype.set(0)
        else:
            self.stype.set(1)

    def _validate(self):
        """ validate entries """
        host = self.txtHost.get()
        if re.match(IPADDR,host) is None and host != 'localhost':
            self.err("Invalid Input","Host %s is not valid" % host)
            return False
        if len(self.txtDB.get()) < 1 or len(self.txtDB.get()) > 15:
            self.err("Invalid Input","DB name must be between 1 and 15 characters")
            return False
        if len(self.txtUser.get()) < 1 or len(self.txtUser.get()) > 15:
            self.err("Invalid Input","User name must be between 1 and 15 characters")
            return False
        if len(self.txtPWD.get()) < 1 or len(self.txtPWD.get()) > 15:
            self.err("Invalid Input","Password must be between 1 and 15 characters")
            return False
        return True

    def _write(self):
        """ write entry inputs to config file """
        fout = None
        try:
            cp = ConfigParser.ConfigParser()
            cp.add_section('Storage')
            cp.set('Storage','host',self.txtHost.get())
            cp.set('Storage','db',self.txtDB.get())
            cp.set('Storage','user',self.txtUser.get())
            cp.set('Storage','pwd',self.txtUser.get())
            cp.add_section('Policy')
            cp.set('Policy','polite','on' if self.ptype else 'off')
            cp.set('Policy','shutdown','auto' if self.stype else 'manual')
            fout = open(wraith.WRAITHCONF,'w')
            cp.write(fout)
            fout.close()
        except IOError as e:
            self.err("File Error","Error <%s> writing to config file" % e)
        except ConfigParser.Error as e:
            self.err("Configuration Error","Error <%s> writing to config file" % e)
        else:
            self.info('Success',"Restart for changes to take effect")
        finally:
            if fout: fout.close()

# Tools->Convert
class ConvertPanel(gui.SimplePanel):
    """ several conversion utilities """
    def __init__(self,toplevel,chief):
        self._mgrs = mgrs.MGRS()
        gui.SimplePanel.__init__(self,toplevel,chief,"Conversions","widgets/icons/convert.png")

    def _body(self,frm):
        """ creates the body """
        frmGeo = Tix.Frame(frm,borderwidth=0)
        frmGeo.grid(row=0,column=0,sticky=Tix.W)
        Tix.Label(frmGeo,text='Lat/Lon: ').grid(row=0,column=0,sticky=Tix.W)
        self.txtLatLon = Tix.Entry(frmGeo,width=15)
        self.txtLatLon.grid(row=0,column=1,sticky=Tix.W)
        Tix.Label(frmGeo,text=' MGRS: ').grid(row=0,column=2,sticky=Tix.W)
        self.txtMGRS = Tix.Entry(frmGeo,width=15)
        self.txtMGRS.grid(row=0,column=3,sticky=Tix.W)
        Tix.Button(frmGeo,text='Convert',command=self.convertgeo).grid(row=0,column=4)
        frmPwr = Tix.Frame(frm,borderwidth=0)
        frmPwr.grid(row=1,column=0,sticky=Tix.E)
        Tix.Label(frmPwr,text="dBm: ").grid(row=0,column=0)
        self.txtdBm = Tix.Entry(frmPwr,width=8)
        self.txtdBm.grid(row=0,column=1)
        Tix.Label(frmPwr,text=" mBm: ").grid(row=0,column=2)
        self.txtmBm = Tix.Entry(frmPwr,width=8)
        self.txtmBm.grid(row=0,column=3)
        Tix.Label(frmPwr,text=" mW: ").grid(row=0,column=4)
        self.txtmW = Tix.Entry(frmPwr,width=8)
        self.txtmW.grid(row=0,column=5)
        Tix.Button(frmPwr,text='Convert',command=self.convertpwr).grid(row=0,column=6)
        frmBtns = Tix.Frame(frm,borderwidth=0)
        frmBtns.grid(row=2,column=0,sticky=Tix.N)
        Tix.Button(frmBtns,text='OK',command=self.delete).grid(row=0,column=0)
        Tix.Button(frmBtns,text='Clear',command=self.clear).grid(row=0,column=1)

    def convertgeo(self):
        """convert geo from lat/lon to mgrs or vice versa """
        # copied from LOBster
        m = self.txtMGRS.get()
        ll = self.txtLatLon.get()
        if m and ll: self.err('Error',"One field must be empty")
        else:
            if m:
                try:
                    ll = self._mgrs.toLatLon(m)
                    self.txtLatLon.insert(0,"%.3f %.3f" % (ll[0],ll[1]))
                except:
                    self.err('Error',"MGRS is not valid")
            elif ll:
                try:
                    ll = ll.split()
                    m = self._mgrs.toMGRS(ll[0],ll[1])
                    self.txtMGRS.insert(0,m)
                except:
                    self.err('Error',"Lat/Lon is not valid")

    def convertpwr(self):
        """ convert dBm to mW or vice versa """
        d = self.txtdBm.get()
        w = self.txtmW.get()
        m = self.txtmBm.get()
        if d and not (m or w):
            try:
                w = math.pow(10,(float(d)/10.0))
                m = 100 * float(d)
                self.txtmW.insert(0,'%.3f' % w)
                self.txtmBm.insert(0,'%.3f' % m)
            except:
                self.err('Error',"dBm is not valid")
        elif w and not (m or d):
            try:
                d = 10*math.log10(float(w))
                m = 100 * d
                self.txtdBm.insert(0,'%.3f' % d)
                self.txtmBm.insert(0,'%.3f' % m)
            except:
                self.err('Error',"dBm is not valid")
        elif m and not (d or m):
            try:
                d = float(m) / 100
                w = math.pow(10,(float(d)/10.0))
                self.txtdBm.insert(0,'%.3f' % d)
                self.txtmW.insert(0,'%.3f' % w)
            except:
                self.err('Error',"mBm is not valid")
        else: self.err('Error',"Two fields must be empty")

    def clear(self):
        """ clear all entries """
        self.txtLatLon.delete(0,Tix.END)
        self.txtMGRS.delete(0,Tix.END)
        self.txtdBm.delete(0,Tix.END)
        self.txtmBm.delete(0,Tix.END)
        self.txtmW.delete(0,Tix.END)

# Tools->Calculate(all)
class CalculatePanel(gui.SimplePanel):
    """
     Base calculator panel - a simple panel that displays specified entries and
     calculates a specified formula
    """
    def __init__(self,toplevel,chief,ttl,inputs,result):
        """
          inputs is a list of tuples of the form t = (label,width,type) where:
           label is the text to display in the entry's label
           width is the width (# of characters) for the entry
           type is the conversion to use on the text from the entry (as a string)
          result is a tuple t = (formula,measurement) such that
           formula is a string representing the mathematical formula to evaluate
           where each placeholder $i is substituted with the value in entry i
           i.e. "$0 * $1" results in the multiplication of the value in entry 0
           and entry 1
           and measurement is the answer's measurement (string)
        """
        self._entries = []
        self._inputs = inputs
        self._ans = Tix.StringVar()
        self._ans.set("")
        self._formula = result[0]
        self._meas = result[1]
        gui.SimplePanel.__init__(self,toplevel,chief,ttl,"widgets/icons/calculator.png")

    def _body(self,frm):
        """ creates the body """
        frmEnt = Tix.Frame(frm,borderwidth=0)
        frmEnt.grid(row=0,column=0,sticky=Tix.W)
        for i in xrange(len(self._inputs)):
            Tix.Label(frmEnt,text=" %s: " % self._inputs[i][0]).grid(row=0,column=(i*2))
            self._entries.append(Tix.Entry(frmEnt,width=self._inputs[i][1]))
            self._entries[i].grid(row=0,column=(i*2)+1)
        frmAns = Tix.Frame(frm,borderwidth=0)
        frmAns.grid(row=1,column=0,sticky=Tix.N)
        Tix.Label(frmAns,text="Answer: ").grid(row=0,column=0)
        Tix.Label(frmAns,width=25,textvariable=self._ans).grid(row=0,column=1)
        Tix.Label(frmAns,text=" %s" % self._meas).grid(row=0,column=2)
        frmBtns = Tix.Frame(frm,borderwidth=0)
        frmBtns.grid(row=2,column=0,sticky=Tix.N)
        Tix.Button(frmBtns,text="Calculate",command=self.calc).grid(row=0,column=0)
        Tix.Button(frmBtns,text="Reset",command=self.clear).grid(row=0,column=1)
        Tix.Button(frmBtns,text="Close",command=self.delete).grid(row=0,column=2)

    def calc(self):
        """ apply formula with entries """
        formula = self._formula
        # make sure no entries are empty substituting the value of the entry as
        # we go
        for i in xrange(len(self._entries)):
            if self._entries[i].get():
                formula = formula.replace('$%d' % i,"%s('%s')" % (self._inputs[i][2],self._entries[i].get()))
            else:
                self.err('Error',"All entries must be filled in")
                return

        # attempt to calculate
        try:
            self._ans.set(str(eval(formula)))
        except ValueError as e:
            self.err("Invalid Input","%s is not a valid input" % e.message.split(':')[1].strip())
        except Exception as e:
            self.err('Error',e)

    def clear(self):
        """ clear all entries """
        for entry in self._entries: entry.delete(0,Tix.END)
        self._ans.set('')

# View->DataBin
class DataBinPanel(gui.SimplePanel):
    """ DataBinPanel - displays a set of data bins for retrieved data storage """
    def __init__(self,toplevel,chief):
        self._bins = {}
        gui.SimplePanel.__init__(self,toplevel,chief,"Databin","widgets/icons/databin.png")

    def donothing(self): pass

    def _body(self,frm):
        """ creates the body """
        # add the bin buttons
        for b in wraith.BINS:
            try:
                self._bins[b] = {'img':ImageTk.PhotoImage(Image.open('widgets/icons/bin%s.png'%b))}
            except:
                self._bins[b] = {'img':None}
                self._bins[b]['btn'] = Tix.Button(frm,text=b,command=self.donothing)
            else:
                self._bins[b]['btn'] = Tix.Button(frm,image=self._bins[b]['img'],command=self.donothing)
            self._bins[b]['btn'].grid(row=0,column=wraith.BINS.index(b),sticky=Tix.W)

# Storage->Nidus-->Config
class NidusConfigPanel(gui.ConfigPanel):
    """ Display Nidus Configuration Panel """
    def __init__(self,toplevel,chief):
        gui.ConfigPanel.__init__(self,toplevel,chief,"Configure Nidus")

    def _makegui(self,frm):
        """ set up entry widgets """
        # SSE Configuration
        frmS = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmS.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmS,text='SSE').grid(row=0,column=0,columnspan=2,sticky=Tix.W)
        Tix.Label(frmS,text='Packets: ').grid(row=1,column=0,sticky=Tix.W)
        self.svar = Tix.IntVar()
        self.chkSave = Tix.Checkbutton(frmS,text="Save",border=0,
                                       variable=self.svar,command=self.cb)
        self.chkSave.grid(row=1,column=1,sticky=Tix.W)
        self.pvar = Tix.IntVar()
        self.chkPrivate = Tix.Checkbutton(frmS,text="Private",border=0,
                                          variable=self.pvar)
        self.chkPrivate.grid(row=1,column=2,sticky=Tix.E)
        Tix.Label(frmS,text='Path: ').grid(row=1,column=3,sticky=Tix.W)
        self.txtPCAPPath = Tix.Entry(frmS,width=25)
        self.txtPCAPPath.grid(row=1,column=4)
        Tix.Label(frmS,text="Max Size: ").grid(row=2,column=1,sticky=Tix.W)
        self.txtMaxSz = Tix.Entry(frmS,width=4)
        self.txtMaxSz.grid(row=2,column=2,sticky=Tix.W)
        Tix.Label(frmS,text="Max Files: ").grid(row=2,column=3,sticky=Tix.W)
        self.txtMaxFiles = Tix.Entry(frmS,width=4)
        self.txtMaxFiles.grid(row=2,column=4,columnspan=2,sticky=Tix.W)
        Tix.Label(frmS,text='Threads: ').grid(row=3,column=0,sticky=Tix.W)
        Tix.Label(frmS,text='Store: ').grid(row=3,column=1,sticky=Tix.W)
        self.txtNumStore = Tix.Entry(frmS,width=2)
        self.txtNumStore.grid(row=3,column=2,sticky=Tix.W)
        Tix.Label(frmS,text='Extract: ').grid(row=3,column=3,sticky=Tix.W)
        self.txtNumExtract = Tix.Entry(frmS,width=2)
        self.txtNumExtract.grid(row=3,column=4,sticky=Tix.W)

        # OUI Configuration
        frmO = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmO.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmO,text='OUI Path: ').grid(row=0,column=0,sticky=Tix.W)
        self.txtOUIPath = Tix.Entry(frmO,width=50)
        self.txtOUIPath.grid(row=0,column=1,sticky=Tix.E)

    def cb(self):
        """ Save Checkbutton callback: disable/enable Save options as necessary """
        if self.svar.get(): state = Tix.NORMAL
        else: state = Tix.DISABLED
        self.chkPrivate.configure(state=state)
        self.txtPCAPPath.configure(state=state)
        self.txtMaxSz.configure(state=state)
        self.txtMaxFiles.configure(state=state)

    def _initialize(self):
        """ insert values from config file into entry boxes """
        conf = ConfigParser.RawConfigParser()
        if not conf.read(wraith.NIDUSCONF):
            self.err("File Not Found","nidus.conf was not found")
            return

        # in case the conf file is invalid, set to empty if not present
        # SSE section
        try:
            save = int(conf.getboolean('SSE','save'))
            private = int(conf.getboolean('SSE','save_private'))
        except:
            save = 0
            private = 0
        self.txtPCAPPath.delete(0,Tix.END)
        if conf.has_option('SSE','save_path'):
            self.txtPCAPPath.insert(0,conf.get('SSE','save_path'))
        self.txtMaxSz.delete(0,Tix.END)
        if conf.has_option('SSE','save_maxsize'):
            self.txtMaxSz.insert(0,conf.get('SSE','save_maxsize'))
        self.txtMaxFiles.delete(0,Tix.END)
        if conf.has_option('SSE','save_maxfiles'):
            self.txtMaxFiles.insert(0,conf.get('SSE','save_maxfiles'))
        self.txtNumStore.delete(0,Tix.END)
        if conf.has_option('SSE','store_threads'):
            self.txtNumStore.insert(0,conf.get('SSE','store_threads'))
        else: self.txtNumStore.insert(0,'2')
        self.txtNumExtract.delete(0,Tix.END)
        if conf.has_option('SSE','extract_threads'):
            self.txtNumExtract.insert(0,conf.get('SSE','extract_threads'))
        else: self.txtNumExtract.insert(0,'2')

        # disable/enable as needed
        if save: state = Tix.NORMAL
        else: state = Tix.DISABLED
        self.chkPrivate.configure(state=state)
        self.txtPCAPPath.configure(state=state)
        self.txtMaxSz.configure(state=state)
        self.txtMaxFiles.configure(state=state)

        # OUI section
        self.txtOUIPath.delete(0,Tix.END)
        if conf.has_option('OUI','path'):
            self.txtOUIPath.insert(0,conf.get('OUI','Path'))
        else: self.txtOUIPath.insert(0,'/etc/aircrack-ng/airodump-ng-oui.txt')

    def _validate(self):
        """ validate entries """
        # if not saving pcaps, we ignore pcap options
        if self.svar.get():
            # for the pcap directory, convert to absolute path before checking existence
            pPCAP = self.txtPCAPPath.get()
            if not os.path.isabs(pPCAP):
                pPCAP = os.path.abspath(os.path.join('nidus',pPCAP))
            if not os.path.exists(pPCAP):
                self.err("Invalid Input","PCAP directory %s does not exist" % pPCAP)
                return False
            try:
                if int(self.txtMaxSz.get()) < 1:
                    self.err("Invalid Input","Max Size must be >= 1")
                    return False
            except ValueError:
                self.err("Invalid Input","Max Size must be an integer")
                return False
            try:
                if int(self.txtMaxFiles.get()) < 1:
                    self.err("Invalid Input","Max Files must be >= 1")
                    return False
            except ValueError:
                self.err("Invalid Input","Max files must be an integer")
                return False
        try:
            st = int(self.txtNumStore.get())
            if st < 1 or st > 10:
                self.err("Invalid Input","Number of store threads must be between 1 and 10")
                return False
        except ValueError:
            self.err("Invalid Input","Number of store threads must be an integer")
            return False
        try:
            et = int(self.txtNumExtract.get())
            if et < 1 or et > 10:
                self.err("Invalid Input","Number of extract threads must be between 1 and 10")
                return False
        except ValueError:
            self.err("Invalid Input","Number of extract threads must be an integer")
            return False
        if not os.path.isfile(self.txtOUIPath.get()):
            self.err("Invalid Input","OUI file %s is not valid" % self.txtOUIPath.get())
            return False
        return True

    def _write(self):
        """ write entry inputs to config file """
        fout = None
        try:
            cp = ConfigParser.ConfigParser()
            cp.add_section('SSE')
            cp.set('SSE','save','yes' if self.svar.get() else 'no')
            cp.set('SSE','save_private','yes' if self.pvar.get() else 'no')
            cp.set('SSE','save_path',self.txtPCAPPath.get())
            cp.set('SSE','save_maxsize',self.txtMaxSz.get())
            cp.set('SSE','save_maxfiles',self.txtMaxFiles.get())
            cp.set('SSE','store_threads',self.txtNumStore.get())
            cp.set('SSE','extract_threads',self.txtNumExtract.get())
            cp.add_section('OUI')
            cp.set('OUI','path',self.txtOUIPath.get())
            fout = open(wraith.NIDUSCONF,'w')
            cp.write(fout)
            fout.close()
        except IOError as e:
            self.err("File Error","Error <%s> writing to config file" % e)
        except ConfigParser.Error as e:
            self.err("Configuration Error","Error <%s> writing to config file" % e)
        else:
            self.info('Success',"Changes will take effect on next start")
        finally:
            if fout: fout.close()

# DySKT->Config
class DySKTConfigException(Exception): pass
class DySKTConfigPanel(gui.ConfigPanel):
    """ Display Nidus Configuration Panel """
    def __init__(self,toplevel,chief):
        gui.ConfigPanel.__init__(self,toplevel,chief,"Configure DySKT")

    def _makegui(self,frm):
        """ set up entry widgets """
        nb = Tix.NoteBook(frm)
        nb.add('recon',label='Recon')
        nb.add('collection',label='Collection')
        nb.add('gps',label='GPS')
        nb.add('misc',label='Misc.')
        nb.pack(expand=True,fill=Tix.BOTH,side=Tix.TOP)

        # Recon Tab Configuration
        frmR = Tix.Frame(nb.recon)
        frmR.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmR,text='NIC: ').grid(row=0,column=0,sticky=Tix.W+Tix.N)
        self.txtReconNic = Tix.Entry(frmR,width=5)
        self.txtReconNic.grid(row=0,column=1,sticky=Tix.W+Tix.N)
        Tix.Label(frmR,text=' ').grid(row=0,column=2,sticky=Tix.W)
        Tix.Label(frmR,text='Spoof: ').grid(row=0,column=3,sticky=Tix.W+Tix.N)
        self.txtReconSpoof = Tix.Entry(frmR,width=17)
        self.txtReconSpoof.grid(row=0,column=4,sticky=Tix.W+Tix.N)
        Tix.Label(frmR,text='Desc: ').grid(row=1,column=0,sticky=Tix.W+Tix.N)
        self.txtReconDesc = Tix.Text(frmR,width=42,height=3)
        self.txtReconDesc.grid(row=1,column=1,columnspan=4,sticky=Tix.E)

        # ANTENNA SUB SECTION
        frmRA = Tix.Frame(frmR,borderwidth=2,relief='sunken')
        frmRA.grid(row=2,column=1,columnspan=4,sticky=Tix.N+Tix.W)
        # ANTENNA SUBSECTION
        Tix.Label(frmRA,text='ANTENNA(S)').grid(row=0,column=0,columnspan=2,sticky=Tix.W)
        Tix.Label(frmRA,text="Number: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtReconAntNum = Tix.Entry(frmRA,width=2)
        self.txtReconAntNum.grid(row=1,column=1,sticky=Tix.W)
        Tix.Label(frmRA,text='Gain: ').grid(row=2,column=0,sticky=Tix.W)
        self.txtReconAntGain = Tix.Entry(frmRA,width=7)
        self.txtReconAntGain.grid(row=2,column=1,sticky=Tix.W)
        Tix.Label(frmRA,text=" ").grid(row=2,column=2)
        Tix.Label(frmRA,text="Type: ").grid(row=2,column=3,sticky=Tix.E)
        self.txtReconAntType = Tix.Entry(frmRA,width=15)
        self.txtReconAntType.grid(row=2,column=4,sticky=Tix.E)
        Tix.Label(frmRA,text='Loss: ').grid(row=3,column=0,sticky=Tix.W)
        self.txtReconAntLoss = Tix.Entry(frmRA,width=7)
        self.txtReconAntLoss.grid(row=3,column=1,sticky=Tix.W)
        Tix.Label(frmRA,text=" ").grid(row=3,column=2)
        Tix.Label(frmRA,text="XYZ: ").grid(row=3,column=3,sticky=Tix.E)
        self.txtReconAntXYZ = Tix.Entry(frmRA,width=15)
        self.txtReconAntXYZ.grid(row=3,column=4,sticky=Tix.E)
        # SCAN PATTERN SUB SECTION
        frmRS = Tix.Frame(frmR,borderwidth=2,relief='sunken')
        frmRS.grid(row=3,column=1,columnspan=4,sticky=Tix.N+Tix.W)
        Tix.Label(frmRS,text="SCAN PATTERN").grid(row=0,column=0,columnspan=5,sticky=Tix.W)
        Tix.Label(frmRS,text="Dwell: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtReconScanDwell = Tix.Entry(frmRS,width=5)
        self.txtReconScanDwell.grid(row=1,column=2,sticky=Tix.W)
        Tix.Label(frmRS,text=" ").grid(row=1,column=3)
        Tix.Label(frmRS,text="Start: ").grid(row=1,column=4,sticky=Tix.E)
        self.txtReconScanStart = Tix.Entry(frmRS,width=3)
        self.txtReconScanStart.grid(row=1,column=5,sticky=Tix.W)
        Tix.Label(frmRS,text="Scan: ").grid(row=2,column=0,sticky=Tix.W)
        self.txtReconScanScan = Tix.Entry(frmRS,width=12)
        self.txtReconScanScan.grid(row=2,column=2,sticky=Tix.W)
        Tix.Label(frmRS,text=" ").grid(row=2,column=3)
        Tix.Label(frmRS,text="Pass: ").grid(row=2,column=4,sticky=Tix.W)
        self.txtReconScanPass = Tix.Entry(frmRS,width=12)
        self.txtReconScanPass.grid(row=2,column=5,sticky=Tix.E)

        # Collection Tab Configuration
        frmC = Tix.Frame(nb.collection)
        frmC.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmC,text='NIC: ').grid(row=0,column=0,sticky=Tix.W+Tix.N)
        self.txtCollectionNic = Tix.Entry(frmC,width=5)
        self.txtCollectionNic.grid(row=0,column=1,sticky=Tix.W+Tix.N)
        Tix.Label(frmC,text=' ').grid(row=0,column=2,sticky=Tix.W)
        Tix.Label(frmC,text='Spoof: ').grid(row=0,column=3,sticky=Tix.W+Tix.N)
        self.txtCollectionSpoof = Tix.Entry(frmC,width=17)
        self.txtCollectionSpoof.grid(row=0,column=4,sticky=Tix.W+Tix.N)
        Tix.Label(frmC,text='Desc: ').grid(row=1,column=0,sticky=Tix.W+Tix.N)
        self.txtCollectionDesc = Tix.Text(frmC,width=42,height=3)
        self.txtCollectionDesc.grid(row=1,column=1,columnspan=4,sticky=Tix.E)

        # ANTENNA SUB SECTION
        frmCA = Tix.Frame(frmC,borderwidth=2,relief='sunken')
        frmCA.grid(row=2,column=1,columnspan=4,sticky=Tix.N+Tix.W)
        # ANTENNA SUBSECTION
        Tix.Label(frmCA,text='ANTENNA(S)').grid(row=0,column=0,columnspan=2,sticky=Tix.W)
        Tix.Label(frmCA,text="Number: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtCollectionAntNum = Tix.Entry(frmCA,width=2)
        self.txtCollectionAntNum.grid(row=1,column=1,sticky=Tix.W)
        Tix.Label(frmCA,text='Gain: ').grid(row=2,column=0,sticky=Tix.W)
        self.txtCollectionAntGain = Tix.Entry(frmCA,width=7)
        self.txtCollectionAntGain.grid(row=2,column=1,sticky=Tix.W)
        Tix.Label(frmCA,text=" ").grid(row=2,column=2)
        Tix.Label(frmCA,text="Type: ").grid(row=2,column=3,sticky=Tix.E)
        self.txtCollectionAntType = Tix.Entry(frmCA,width=15)
        self.txtCollectionAntType.grid(row=2,column=4,sticky=Tix.E)
        Tix.Label(frmCA,text='Loss: ').grid(row=3,column=0,sticky=Tix.W)
        self.txtCollectionAntLoss = Tix.Entry(frmCA,width=7)
        self.txtCollectionAntLoss.grid(row=3,column=1,sticky=Tix.W)
        Tix.Label(frmCA,text=" ").grid(row=3,column=2)
        Tix.Label(frmCA,text="XYZ: ").grid(row=3,column=3,sticky=Tix.E)
        self.txtCollectionAntXYZ = Tix.Entry(frmCA,width=15)
        self.txtCollectionAntXYZ.grid(row=3,column=4,sticky=Tix.E)
        # SCAN PATTERN SUB SECTION
        frmCS = Tix.Frame(frmC,borderwidth=2,relief='sunken')
        frmCS.grid(row=3,column=1,columnspan=4,sticky=Tix.N+Tix.W)
        Tix.Label(frmCS,text="SCAN PATTERN").grid(row=0,column=0,columnspan=5,sticky=Tix.W)
        Tix.Label(frmCS,text="Dwell: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtCollectionScanDwell = Tix.Entry(frmCS,width=5)
        self.txtCollectionScanDwell.grid(row=1,column=2,sticky=Tix.W)
        Tix.Label(frmCS,text=" ").grid(row=1,column=3)
        Tix.Label(frmCS,text="Start: ").grid(row=1,column=4,sticky=Tix.E)
        self.txtCollectionScanStart = Tix.Entry(frmCS,width=3)
        self.txtCollectionScanStart.grid(row=1,column=5,sticky=Tix.W)
        Tix.Label(frmCS,text="Scan: ").grid(row=2,column=0,sticky=Tix.W)
        self.txtCollectionScanScan = Tix.Entry(frmCS,width=12)
        self.txtCollectionScanScan.grid(row=2,column=2,sticky=Tix.W)
        Tix.Label(frmCS,text=" ").grid(row=2,column=3)
        Tix.Label(frmCS,text="Pass: ").grid(row=2,column=4,sticky=Tix.W)
        self.txtCollectionScanPass = Tix.Entry(frmCS,width=12)
        self.txtCollectionScanPass.grid(row=2,column=5,sticky=Tix.E)

        # GPS Tab Configuration
        # use a checkbutton & two subframes to differentiate betw/ fixed & dyanmic
        frmG = Tix.Frame(nb.gps)
        frmG.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        self.gvar = Tix.IntVar()
        self.chkFixed = Tix.Checkbutton(frmG,text="Fixed",border=0,
                                        variable=self.gvar,
                                        command=self.gpscb)
        self.chkFixed.grid(row=0,column=0,sticky=Tix.W)

        # separate dynamic and fixed
        frmGF = Tix.Frame(frmG,borderwidth=1,relief='sunken')
        frmGF.grid(row=1,column=0,sticky=Tix.W+Tix.N)
        Tix.Label(frmGF,text="FIXED").grid(row=0,column=0,sticky=Tix.W)
        Tix.Label(frmGF,text="Lat: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtLat = Tix.Entry(frmGF,width=10)
        self.txtLat.grid(row=1,column=1,sticky=Tix.W)
        Tix.Label(frmGF,text="Lon: ").grid(row=2,column=0,sticky=Tix.W)
        self.txtLon = Tix.Entry(frmGF,width=10)
        self.txtLon.grid(row=2,column=1,sticky=Tix.W)
        Tix.Label(frmGF,text="Alt: ").grid(row=3,column=0,sticky=Tix.W)
        self.txtAlt = Tix.Entry(frmGF,width=10)
        self.txtAlt.grid(row=3,column=1,sticky=Tix.W)
        Tix.Label(frmGF,text="Heading: ").grid(row=4,column=0,sticky=Tix.W)
        self.txtHeading = Tix.Entry(frmGF,width=3)
        self.txtHeading.grid(row=4,column=1,sticky=Tix.W)
        Tix.Label(frmG,text=' ').grid(row=0,column=1) # separate the frames
        frmGD = Tix.Frame(frmG,borderwidth=1,relief='sunken')
        frmGD.grid(row=1,column=2,sticky=Tix.E+Tix.N)
        Tix.Label(frmGD,text="DYNAMIC").grid(row=0,column=0,sticky=Tix.W)
        Tix.Label(frmGD,text="Port: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtGPSPort = Tix.Entry(frmGD,width=5)
        self.txtGPSPort.grid(row=1,column=1,sticky=Tix.W)
        Tix.Label(frmGD,text="Dev ID: ").grid(row=2,column=0,sticky=Tix.W)
        self.txtDevID = Tix.Entry(frmGD,width=9)
        self.txtDevID.grid(row=2,column=1,sticky=Tix.W)
        Tix.Label(frmGD,text="Poll: ").grid(row=3,column=0,sticky=Tix.W)
        self.txtPoll = Tix.Entry(frmGD,width=5)
        self.txtPoll.grid(row=3,column=1,sticky=Tix.W)
        Tix.Label(frmGD,text="EPX: ").grid(row=4,column=0,sticky=Tix.W)
        self.txtEPX = Tix.Entry(frmGD,width=5)
        self.txtEPX.grid(row=4,column=1,sticky=Tix.W)
        Tix.Label(frmGD,text="EPY: ").grid(row=5,column=0,sticky=Tix.W)
        self.txtEPY = Tix.Entry(frmGD,width=5)
        self.txtEPY.grid(row=5,column=1,sticky=Tix.W)

        # misc tab
        frmM = Tix.Frame(nb.misc)
        frmM.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        frmMS = Tix.Frame(frmM,border=1,relief='sunken')
        frmMS.grid(row=0,column=0,sticky=Tix.W)
        Tix.Label(frmMS,text='STORAGE').grid(row=0,column=0,sticky=Tix.W)
        self.cvar = Tix.IntVar()
        self.chkCollated = Tix.Checkbutton(frmMS,text='Collated',border=0,variable=self.cvar)
        self.chkCollated.grid(row=1,column=0,sticky=Tix.W)
        Tix.Label(frmMS,text=' Host: ').grid(row=1,column=1)
        self.txtStoreHost = Tix.Entry(frmMS,width=15)
        self.txtStoreHost.grid(row=1,column=2)
        Tix.Label(frmMS,text=' Port: ').grid(row=1,column=3)
        self.txtStorePort = Tix.Entry(frmMS,width=5)
        self.txtStorePort.grid(row=1,column=4)
        frmML = Tix.Frame(frmM,border=1,relief='sunken')
        frmML.grid(row=1,column=0,sticky=Tix.W)
        Tix.Label(frmML,text="LOCAL").grid(row=0,column=0,sticky=Tix.W)
        Tix.Label(frmML,text="Region: ").grid(row=1,column=0,sticky=Tix.W)
        self.txtRegion = Tix.Entry(frmML,width=2)
        self.txtRegion.grid(row=1,column=1)
        Tix.Label(frmML,text=" C2C: ").grid(row=1,column=2,sticky=Tix.W)
        self.txtC2CPort = Tix.Entry(frmML,width=5)
        self.txtC2CPort.grid(row=1,column=3)


    def _initialize(self):
        """ insert values from config file into entry boxes """
        cp = ConfigParser.RawConfigParser()
        if not cp.read(wraith.DYSKTCONF):
            self.err("File Not Found","File dyskt.conf was not found")
            return

        # start by reading the recon radio details
        self.txtReconNic.delete(0,Tix.END)
        if cp.has_option('Recon','nic'):
            self.txtReconNic.insert(0,cp.get('Recon','nic'))
        self.txtReconSpoof.delete(0,Tix.END)
        if cp.has_option('Recon','spoof'):
            self.txtReconSpoof.insert(0,cp.get('Recon','spoof'))
        self.txtReconDesc.delete(1.0,Tix.END)
        if cp.has_option('Recon','desc'):
            self.txtReconDesc.insert(Tix.END,cp.get('Recon','desc'))
        self.txtReconAntNum.delete(0,Tix.END)
        if cp.has_option('Recon','antennas'):
            self.txtReconAntNum.insert(0,cp.get('Recon','antennas'))
        self.txtReconAntGain.delete(0,Tix.END)
        if cp.has_option('Recon','antenna_gain'):
            self.txtReconAntGain.insert(0,cp.get('Recon','antenna_gain'))
        self.txtReconAntType.delete(0,Tix.END)
        if cp.has_option('Recon','antenna_type'):
            self.txtReconAntType.insert(0,cp.get('Recon','antenna_type'))
        self.txtReconAntLoss.delete(0,Tix.END)
        if cp.has_option('Recon','antenna_loss'):
            self.txtReconAntLoss.insert(0,cp.get('Recon','antenna_loss'))
        self.txtReconAntXYZ.delete(0,Tix.END)
        if cp.has_option('Recon','antenna_xyz'):
            self.txtReconAntXYZ.insert(0,cp.get('Recon','antenna_xyz'))
        self.txtReconScanDwell.delete(0,Tix.END)
        if cp.has_option('Recon','dwell'):
            self.txtReconScanDwell.insert(0,cp.get('Recon','dwell'))
        self.txtReconScanStart.delete(0,Tix.END)
        if cp.has_option('Recon','scan_start'):
            self.txtReconScanStart.insert(0,cp.get('Recon','scan_start'))
        self.txtReconScanScan.delete(0,Tix.END)
        if cp.has_option('Recon','scan'):
            self.txtReconScanScan.insert(0,cp.get('Recon','scan'))
        self.txtReconScanPass.delete(0,Tix.END)
        if cp.has_option('Recon','pass'):
            self.txtReconScanPass.insert(0,cp.get('Recon','pass'))

        # then the collection radio details
        self.txtCollectionNic.delete(0,Tix.END)
        if cp.has_option('Collection','nic'):
            self.txtCollectionNic.insert(0,cp.get('Collection','nic'))
        self.txtCollectionSpoof.delete(0,Tix.END)
        if cp.has_option('Collection','spoof'):
            self.txtCollectionSpoof.insert(0,cp.get('Collection','spoof'))
        self.txtCollectionDesc.delete(1.0,Tix.END)
        if cp.has_option('Collection','desc'):
            self.txtCollectionDesc.insert(Tix.END,cp.get('Collection','desc'))
        self.txtCollectionAntNum.delete(0,Tix.END)
        if cp.has_option('Collection','antennas'):
            self.txtCollectionAntNum.insert(0,cp.get('Collection','antennas'))
        self.txtCollectionAntGain.delete(0,Tix.END)
        if cp.has_option('Collection','antenna_gain'):
            self.txtCollectionAntGain.insert(0,cp.get('Collection','antenna_gain'))
        self.txtCollectionAntType.delete(0,Tix.END)
        if cp.has_option('Collection','antenna_type'):
            self.txtCollectionAntType.insert(0,cp.get('Collection','antenna_type'))
        self.txtCollectionAntLoss.delete(0,Tix.END)
        if cp.has_option('Collection','antenna_loss'):
            self.txtCollectionAntLoss.insert(0,cp.get('Collection','antenna_loss'))
        self.txtCollectionAntXYZ.delete(0,Tix.END)
        if cp.has_option('Collection','antenna_xyz'):
            self.txtCollectionAntXYZ.insert(0,cp.get('Collection','antenna_xyz'))
        self.txtCollectionScanDwell.delete(0,Tix.END)
        if cp.has_option('Collection','dwell'):
            self.txtCollectionScanDwell.insert(0,cp.get('Collection','dwell'))
        self.txtCollectionScanStart.delete(0,Tix.END)
        if cp.has_option('Collection','scan_start'):
            self.txtCollectionScanStart.insert(0,cp.get('Collection','scan_start'))
        self.txtCollectionScanScan.delete(0,Tix.END)
        if cp.has_option('Collection','scan'):
            self.txtCollectionScanScan.insert(0,cp.get('Collection','scan'))
        self.txtCollectionScanPass.delete(0,Tix.END)
        if cp.has_option('Collection','pass'):
            self.txtCollectionScanPass.insert(0,cp.get('Collection','pass'))

        # gps entries
        try:
            fixed = int(cp.getboolean('GPS','fixed'))
        except:
            fixed = 0
        self.gvar.set(fixed)
        self.txtLat.delete(0,Tix.END)
        if cp.has_option('GPS','lat'): self.txtLat.insert(0,cp.get('GPS','lat'))
        self.txtLon.delete(0,Tix.END)
        if cp.has_option('GPS','lon'): self.txtLon.insert(0,cp.get('GPS','lon'))
        self.txtAlt.delete(0,Tix.END)
        if cp.has_option('GPS','alt'): self.txtAlt.insert(0,cp.get('GPS','alt'))
        self.txtHeading.delete(0,Tix.END)
        if cp.has_option('GPS','heading'): self.txtHeading.insert(0,cp.get('GPS','heading'))
        self.txtGPSPort.delete(0,Tix.END)
        if cp.has_option('GPS','port'): self.txtGPSPort.insert(0,cp.get('GPS','port'))
        self.txtDevID.delete(0,Tix.END)
        if cp.has_option('GPS','devid'): self.txtDevID.insert(0,cp.get('GPS','devid'))
        self.txtPoll.delete(0,Tix.END)
        if cp.has_option('GPS','poll'): self.txtPoll.insert(0,cp.get('GPS','poll'))
        self.txtEPX.delete(0,Tix.END)
        if cp.has_option('GPS','epx'): self.txtEPX.insert(0,cp.get('GPS','epx'))
        self.txtEPY.delete(0,Tix.END)
        if cp.has_option('GPS','epy'): self.txtEPY.insert(0,cp.get('GPS','epy'))
        self.gpscb() # enable/disable entries

        # misc entries
        try:
            collated = int(cp.getboolean('Storage','collated'))
        except:
            collated = 0
        self.cvar.set(collated)
        self.txtStoreHost.delete(0,Tix.END)
        if cp.has_option('Storage','host'): self.txtStoreHost.insert(0,cp.get('Storage','host'))
        self.txtStorePort.delete(0,Tix.END)
        if cp.has_option('Storage','port'): self.txtStorePort.insert(0,cp.get('Storage','port'))
        self.txtRegion.delete(0,Tix.END)
        if cp.has_option('Local','region'): self.txtRegion.insert(0,cp.get('Local','region'))
        self.txtC2CPort.delete(0,Tix.END)
        if cp.has_option('Local','C2C'): self.txtC2CPort.insert(0,cp.get('Local','C2C'))

    def _validate(self):
        """ validate entries """
        # start with the recon radio details
        nic = self.txtReconNic.get()
        if not nic:
            self.err("Invalid Recon Input","Radio nic must be specified")
            return False
        elif not nic in wifaces():
            self.warn("Not Found","Recon radio may not be wireless")
        spoof = self.txtReconSpoof.get().upper()
        if spoof and re.match(MACADDR,spoof) is None:
            self.err("Invalid Recon Input","Spoofed MAC addr %s is not valid")
            return False

        # process antennas, if # > 0 then force validation of all antenna widgets
        if self.txtReconAntNum.get():
            try:
                nA = int(self.txtReconAntNum.get())
                if nA:
                    try:
                        if len(map(float,self.txtReconAntGain.get().split(','))) != nA:
                            raise DySKTConfigException("Number of gain is invalid")
                    except ValueError:
                        raise DySKTConfigException("Gain must be float or list of floats")
                    if len(self.txtReconAntType.get().split(',')) != nA:
                        raise DySKTConfigException("Number of types is invalid")
                    try:
                        if len(map(float,self.txtReconAntLoss.get().split(','))) != nA:
                            raise DySKTConfigException("Number of loss is invalid")
                    except:
                        raise DySKTConfigException("Loss must be float or list of floats")
                    try:
                        xyzs = self.txtReconAntXYZ.get().split(',')
                        if len(xyzs) != nA:
                            raise DySKTConfigException("Number of xyz is invalid")
                        for xyz in xyzs:
                            xyz = xyz.split(':')
                            if len(xyz) != 3:
                                raise DySKTConfigException("XYZ must be three integers")
                            map(int,xyz)
                    except ValueError:
                        raise DySKTConfigException('XYZ must be integer')
            except ValueError:
                self.err("Invalid Recon Input","Number of antennas must be numeric")
                return False
            except DySKTConfigException as e:
                self.err("Invalid Recon Input",e)
                return False

        # process scan patterns
        try:
            float(self.txtReconScanDwell.get())
        except:
            self.err("Invalid Recon Input","Scan dwell must be float")
            return False
        start = self.txtReconScanStart.get()
        try:
            if start:
                if ':' in start: ch,chw = start.split(':')
                else:
                    ch = start
                    chw = None
                ch = int(ch)
                if chw and not chw in IW_CHWS:
                    raise RuntimeError("Specified channel width is not valid")
        except ValueError:
            self.err("Invalid Recon Input","Scan start must be integer")
            return False
        except Exception as e:
            self.err("Invalid Recon Input",e)
            return False
        try:
            parsechlist(self.txtReconScanScan.get(),'scan')
            parsechlist(self.txtReconScanPass.get(),'pass')
        except ValueError as e:
            self.err("Invalid Recon Input",e)
            return False

        # then collection radio details
        nic = self.txtCollectionNic.get()
        if nic:
            if not nic in wifaces(): self.warn("Not Found","Radio may not be wireless")
            spoof = self.txtCollectionSpoof.get().upper()
            if spoof and re.match(MACADDR,spoof) is None:
                self.err("Invalid Colleciton Input","Spoofed MAC address is not valid")
                return False

            # process the antennas - if antenna number is > 0 then force validation of
            # all antenna widgets
            if self.txtCollectionAntNum.get():
                try:
                    nA = int(self.txtCollectionAntNum.get())
                    if nA:
                        try:
                            if len(map(float,self.txtCollectionAntGain.get().split(','))) != nA:
                                raise DySKTConfigException("Number of gain is invalid")
                        except ValueError:
                            raise DySKTConfigException("Gain must be float or list of floats")
                        if len(self.txtCollectionAntType.get().split(',')) != nA:
                            raise DySKTConfigException("Number of types is invalid")
                        try:
                            if len(map(float,self.txtCollectionAntLoss.get().split(','))) != nA:
                                raise DySKTConfigException("Number of loss is invalid")
                        except:
                            raise DySKTConfigException("Loss must be float or list of floats")
                        try:
                            xyzs = self.txtCollectionAntXYZ.get().split(',')
                            if len(xyzs) != nA:
                                raise DySKTConfigException("Number of xyz is invalid")
                            for xyz in xyzs:
                                xyz = xyz.split(':')
                                if len(xyz) != 3:
                                    raise DySKTConfigException("XYZ must be three integers")
                                map(int,xyz)
                        except ValueError:
                            raise DySKTConfigException("XYZ must be integer")
                except ValueError:
                    self.err("Invalid Collection Input","Number of antennas must be numeric")
                    return False
                except DySKTConfigException as e:
                    self.err("Invalid Collection Input",e)
                    return False

            # process scan patterns
            try:
                float(self.txtCollectionScanDwell.get())
            except:
                self.err("Invalid Collection Input", "Scan dwell must be float")
                return False
            start = self.txtCollectionScanStart.get()
            try:
                if start:
                    if ':' in start: ch,chw = start.split(':')
                    else:
                        ch = start
                        chw = None
                    ch = int(ch)
                    if chw and not chw in IW_CHWS:
                        raise RuntimeError("Specified channel width is not valid")
            except ValueError:
                self.err("Invalid Collection Input", "Scan start must be integer")
                return False
            except Exception as e:
                self.err("Invalid Collection Input",e)
                return False
            try:
                parsechlist(self.txtCollectionScanScan.get(),'scan')
                parsechlist(self.txtCollectionScanPass.get(),'pass')
            except ValueError as e:
                self.err("Invalid Collection Input",e)
                return False

        # gps - only process enabled widgets
        if self.gvar.get():
            # fixed is set
            try:
                float(self.txtLat.get())
                float(self.txtLon.get())
            except:
                self.err("Invalid GPS Input","Lat/Lon must be floats")
                return False
            try:
                float(self.txtAlt.get())
            except:
                self.err("Invalid GPS Input","Altitude must be a float")
                return False
            hdg = self.txtHeading.get()
            try:
                hdg = int(hdg)
                if hdg < 0 or hdg > 360: raise RuntimeError("")
            except:
                self.err("Invalid GPS Input","Heading must be an integer between 0 and 360")
                return False
        else:
            # dynamic is set
            port = self.txtGPSPort.get()
            try:
                port = int(port)
                if port < 1024 or port > 65535: raise RuntimeError("")
            except ValueError:
                self.err("Invalid GPS Input","Device port must be a number between 1024 and 65535")
                return False
            if re.match(GPSDID,self.txtDevID.get().upper()) is None:
                self.err("Invalid GPS Input","GPS Dev ID is invalid")
                return False
            try:
                if float(self.txtPoll.get()) < 0: raise RuntimeError("")
            except:
                self.err("Invalid GPS Input","Poll must be numeric and greater than 0")
                return False
            try:
                float(self.txtEPX.get())
                float(self.txtEPY.get())
            except:
                self.err("Invalid GPS Input","EPX/EPY must be numeric or 'inf'")
                return False

        # misc entries
        host = self.txtStoreHost.get()
        if re.match(IPADDR,host) is None and host != 'localhost':
            self.err("Invalid Storage Input","Host is not a valid address")
        port = self.txtStorePort.get()
        try:
            port = int(port)
            if port < 1024 or port > 65535: raise RuntimeError("")
        except ValueError:
            self.err("Invalid Storage Input","Host Port must be a number between 1024 and 65535")
            return False
        region = self.txtRegion.get()
        if region and len(region) != 2:
            self.err("Invalid Local Input","Region must be 2 characters")
            return False
        port = self.txtC2CPort.get()
        try:
            port = int(port)
            if port < 1024 or port > 65535: raise RuntimeError("")
        except:
            self.err("Invalid Local Input","C2C Port must be a number between 1024 and 65535")
            return False

        return True

    def _write(self):
        """ write entry inputs to config file """
        fout = None
        try:
            cp = ConfigParser.ConfigParser()
            cp.add_section('Recon')
            cp.set('Recon','nic',self.txtReconNic.get())
            if self.txtReconSpoof.get(): cp.set('Recon','spoof',self.txtReconSpoof.get())
            nA = self.txtReconAntNum.get()
            if nA:
                cp.set('Recon','antennas',self.txtReconAntNum.get())
                cp.set('Recon','antenna_gain',self.txtReconAntGain.get())
                cp.set('Recon','antenna_loss',self.txtReconAntLoss.get())
                cp.set('Recon','antenna_type',self.txtReconAntType.get())
                cp.set('Recon','antenna_xyz',self.txtReconAntXYZ.get())
            desc = self.txtReconDesc.get(1.0,Tix.END).strip()
            if desc: cp.set('Recon','desc',desc)
            cp.set('Recon','dwell',self.txtReconScanDwell.get())
            cp.set('Recon','scan',self.txtReconScanScan.get())
            cp.set('Recon','pass',self.txtReconScanPass.get())
            cp.set('Recon','scan_start',self.txtReconScanStart.get())
            if self.txtCollectionNic.get():
                cp.add_section('Collection')
                cp.set('Collection','nic',self.txtCollectionNic.get())
                if self.txtCollectionSpoof.get():
                    cp.set('Collection','spoof',self.txtCollectionSpoof.get())
                nA = self.txtCollectionAntNum.get()
                if nA:
                    cp.set('Collection','antennas',self.txtCollectionAntNum.get())
                    cp.set('Collection','antenna_gain',self.txtCollectionAntGain.get())
                    cp.set('Collection','antenna_loss',self.txtCollectionAntLoss.get())
                    cp.set('Collection','antenna_type',self.txtCollectionAntType.get())
                    cp.set('Collection','antenna_xyz',self.txtCollectionAntXYZ.get())
                desc = self.txtCollectionDesc.get(1.0,Tix.END).strip()
                if desc: cp.set('Collection','desc',desc)
                cp.set('Collection','dwell',self.txtCollectionScanDwell.get())
                cp.set('Collection','scan',self.txtCollectionScanScan.get())
                cp.set('Collection','pass',self.txtCollectionScanPass.get())
                cp.set('Collection','scan_start',self.txtCollectionScanStart.get())
            cp.add_section('GPS')
            fixed = self.gvar.get()
            cp.set('GPS','fixed','yes' if fixed else 'no')
            if fixed:
                cp.set('GPS','lat',self.txtLat.get())
                cp.set('GPS','lon',self.txtLon.get())
                cp.set('GPS','alt',self.txtAlt.get())
                cp.set('GPS','heading',self.txtHeading.get())
            else:
                cp.set('GPS','port',self.txtGPSPort.get())
                cp.set('GPS','devid',self.txtDevID.get())
                cp.set('GPS','poll',self.txtPoll.get())
                cp.set('GPS','epx',self.txtEPX.get())
                cp.set('GPS','epy',self.txtEPY.get())
            cp.add_section('Storage')
            cp.set('Storage','collated','yes' if self.cvar.get() else 'no')
            cp.set('Storage','host',self.txtStoreHost.get())
            cp.set('Storage','port',self.txtStorePort.get())
            region = self.txtRegion.get()
            c2cport = self.txtC2CPort.get()
            if region or c2cport:
                cp.add_section('Local')
                if region: cp.set('Local','region',region)
                if c2cport: cp.set('Local','C2C',c2cport)
            fout = open(wraith.DYSKTCONF,'w')
            cp.write(fout)
            fout.close()
        except IOError as e:
            self.err("File Error","Error <%s> writing to config file" % e)
        except ConfigParser.Error as e:
            self.err("Configuration Error","Error <%s> writing to config file" % e)
        else:
            self.info('Success',"Restart for changes to take effect")
        finally:
            if fout: fout.close()

    def gpscb(self):
        """ enable/disable gps entries as necessary """
        if self.gvar.get():
            # fixed is on enable only fixed entries
            self.txtLat.configure(state=Tix.NORMAL)
            self.txtLon.configure(state=Tix.NORMAL)
            self.txtAlt.configure(state=Tix.NORMAL)
            self.txtHeading.configure(state=Tix.NORMAL)
            self.txtGPSPort.configure(state=Tix.DISABLED)
            self.txtDevID.configure(state=Tix.DISABLED)
            self.txtPoll.configure(state=Tix.DISABLED)
            self.txtEPX.configure(state=Tix.DISABLED)
            self.txtEPY.configure(state=Tix.DISABLED)
        else:
            # fixed is off enable only dynamic entries
            self.txtLat.configure(state=Tix.DISABLED)
            self.txtLon.configure(state=Tix.DISABLED)
            self.txtAlt.configure(state=Tix.DISABLED)
            self.txtHeading.configure(state=Tix.DISABLED)
            self.txtGPSPort.configure(state=Tix.NORMAL)
            self.txtDevID.configure(state=Tix.NORMAL)
            self.txtPoll.configure(state=Tix.NORMAL)
            self.txtEPX.configure(state=Tix.NORMAL)
            self.txtEPY.configure(state=Tix.NORMAL)

# Help-->About
class AboutPanel(gui.SimplePanel):
    """ AboutPanel - displays a simple About Panel """
    def __init__(self,toplevel,chief):
        gui.SimplePanel.__init__(self,toplevel,chief,"About Wraith","widgets/icons/about.png")

    def _body(self,frm):
        self.logo = ImageTk.PhotoImage(Image.open("widgets/icons/wraith-banner.png"))
        Tix.Label(frm,bg='white',image=self.logo).grid(row=0,column=0,sticky=Tix.N)
        Tix.Label(frm,text="wraith-rt %s" % wraith.__version__,
                  fg='white',font=("Roman",16,'bold')).grid(row=1,column=0,sticky=Tix.N)
        Tix.Label(frm,text="Wireless reconnaissance, collection, assault and exploitation toolkit",
                  fg='white',font=("Roman",8,'bold')).grid(row=2,column=0,sticky=Tix.N)
        Tix.Label(frm,text="Copyright %s %s %s" % (COPY,
                                                   wraith.__date__.split(' ')[1],
                                                   wraith.__email__),
                  fg='white',font=('Roman',8,'bold')).grid(row=3,column=0,sticky=Tix.N)