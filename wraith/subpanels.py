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
import tkMessageBox as tkMB                # info dialogs
from PIL import Image,ImageTk              # image input & support
import ConfigParser                        # config file parsing
import wraith                              # version info & constants
import wraith.widgets.panel as gui         # graphics suite
from wraith.radio.iwtools import wifaces   # check nic validity

# Validation reg. exp.
IPADDR = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") # reg exp for ip addr
MACADDR = re.compile("^([0-9A-F]{2}:){5}([0-9A-F]{2})$")    # reg exp for mac addr (capital letters only)

class DataBinPanel(gui.SimplePanel):
    """ DataBinPanel - displays a set of data bins for retrieved data storage """
    def __init__(self,toplevel,chief):
        gui.SimplePanel.__init__(self,toplevel,chief,"Databin","widgets/icons/databin.png")

    def donothing(self): pass

    def _body(self):
        """ creates the body """
        self._bins = {}
        frm = Tix.Frame(self)
        frm.pack(side=Tix.TOP,expand=False)

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

class AboutPanel(gui.SimplePanel):
    """ AboutPanel - displays a simple About Panel """
    def __init__(self,toplevel,chief):
        gui.SimplePanel.__init__(self,toplevel,chief,"About Wraith","widgets/icons/about.png")

    def _body(self):
        frm = Tix.Frame(self)
        frm.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        self.logo = ImageTk.PhotoImage(Image.open("widgets/icons/wraith-banner.png"))
        Tix.Label(frm,bg="white",image=self.logo).grid(row=0,column=0,sticky=Tix.N)
        Tix.Label(frm,
                  text="wraith-rt %s" % wraith.__version__,
                  fg="white",
                  font=("Roman",16,'bold')).grid(row=1,column=0,sticky=Tix.N)
        Tix.Label(frm,
                  text="Wireless assault, reconnaissance, collection and exploitation toolkit",
                  fg="white",
                  font=("Roman",8,'bold')).grid(row=2,column=0,sticky=Tix.N)

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
            tkMB.showerror("File Not Found","File wraith.conf was not found",
                           parent=self)
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
            tkMB.showerror("Invalid Input",
                           "Host %s is not valid" % host,
                           parent=self)
            return False
        if len(self.txtDB.get()) < 1 or len(self.txtDB.get()) > 15:
            tkMB.showerror("Invalid Input",
                           "DB name must be between 1 and 15 characters",
                           parent=self)
            return False
        if len(self.txtUser.get()) < 1 or len(self.txtUser.get()) > 15:
            tkMB.showerror("Invalid Input",
                           "User name must be between 1 and 15 characters",
                           parent=self)
            return False
        if len(self.txtPWD.get()) < 1 or len(self.txtPWD.get()) > 15:
            tkMB.showerror("Invalid Input",
                           "Password must be between 1 and 15 characters",
                           parent=self)
            return False
        return True

    def _write(self):
        """ write entry inputs to config file """
        try:
            conf = ConfigParser.ConfigParser()

            # storage section
            conf.add_section('Storage')
            conf.set('Storage','host',self.txtHost.get())
            conf.set('Storage','db',self.txtDB.get())
            conf.set('Storage','user',self.txtUser.get())
            conf.set('Storage','pwd',self.txtUser.get())

            # policy section
            conf.add_section('Policy')
            conf.set('Policy','polite','on' if self.ptype else 'off')
            conf.set('Policy','shutdown','auto' if self.stype else 'manual')

            fout = open(wraith.WRAITHCONF,'w')
            conf.write(fout)
            fout.close()
        except IOError as e:
            tkMB.showerror("File Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        except ConfigParser.Error as e:
            tkMB.showerror("Configuration Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        else:
            tkMB.showinfo('Success',
                          "Restart for changes to take effect",
                          parent=self)

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
            tkMB.showerror("File Not Found",
                           "File nidus.conf was not found",
                           parent=self)
            return

        # in case the conf file is invalid, set to empty if not present
        # SSE section
        try:
            save = int(conf.getboolean('SSE','save'))
            private = int(conf.getboolean('SSE','save_private'))
        except:
            save = 0
            private  =0
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
                tkMB.showerror("Invalid Input",
                               "PCAP directory %s does not exist" % pPCAP,
                               parent=self)
                return False
            try:
                sz = int(self.txtMaxSz.get())
                if sz < 1:
                    tkMB.showerror("Invalid Input",
                                   "Max Size must be >= 1",
                                   parent=self)
                    return False
            except ValueError:
                tkMB.showerror("Invalid Input",
                               "Max Size must be an integer",
                               parent=self)
                return False
            try:
                sz = int(self.txtMaxFiles.get())
                if sz < 1:
                    tkMB.showerror("Invalid Input",
                                   "Max Files must be >= 1",
                                   parent=self)
                    return False
            except ValueError:
                tkMB.showerror("Invalid Input",
                               "Max files must be an integer",
                               parent=self)
                return False
        try:
            st = int(self.txtNumStore.get())
            if st < 1 or st > 10:
                tkMB.showerror("Invalid Input",
                               "Number of store threads must be between 1 and 10",
                               parent=self)
                return False
        except ValueError:
            tkMB.showerror("Invalid Input",
                           "Number of store threads must be an integer",
                           parent=self)
            return False
        try:
            et = int(self.txtNumExtract.get())
            if et < 1 or et > 10:
                tkMB.showerror("Invalid Input",
                               "Number of extract threads must be between 1 and 10",
                               parent=self)
                return False
        except ValueError:
            tkMB.showerror("Invalid Input",
                           "Number of extract threads must be an integer",
                           parent=self)
            return False
        if not os.path.isfile(self.txtOUIPath.get()):
            tkMB.showerror("Invalid Input",
                           "OUI file %s is not valid" % self.txtOUIPath.get(),
                           parent=self)
            return False
        return True

    def _write(self):
        """ write entry inputs to config file """
        fout = None
        try:
            conf = ConfigParser.ConfigParser()

            # SSE section
            conf.add_section('SSE')
            conf.set('SSE','save','yes' if self.svar.get() else 'no')
            conf.set('SSE','save_private','yes' if self.pvar.get() else 'no')
            conf.set('SSE','save_path',self.txtPCAPPath.get())
            conf.set('SSE','save_maxsize',self.txtMaxSz.get())
            conf.set('SSE','save_maxfiles',self.txtMaxFiles.get())
            conf.set('SSE','store_threads',self.txtNumStore.get())
            conf.set('SSE','extract_threads',self.txtNumExtract.get())

            # OUI section
            conf.add_section('OUI')
            conf.set('OUI','path',self.txtOUIPath.get())

            fout = open(wraith.NIDUSCONF,'w')
            conf.write(fout)
            fout.close()
        except IOError as e:
            tkMB.showerror("File Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        except ConfigParser.Error as e:
            tkMB.showerror("Configuration Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        else:
            tkMB.showinfo('Success',
                          "Changes will take effect on next start",
                          parent=self)

class DySKTConfigException(Exception): pass
class DySKTConfigPanel(gui.ConfigPanel):
    """ Display Nidus Configuration Panel """
    def __init__(self,toplevel,chief):
        gui.ConfigPanel.__init__(self,toplevel,chief,"Configure DySKT")

    def _makegui(self,frm):
        """ set up entry widgets """
        # Recon Configuration
        frmR = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmR.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        Tix.Label(frmR,text='RECON').grid(row=0,column=0,columnspan=6,sticky=Tix.W)
        Tix.Label(frmR,text='NIC: ').grid(row=1,column=0,sticky=Tix.W+Tix.N)
        self.txtReconNic = Tix.Entry(frmR,width=5)
        self.txtReconNic.grid(row=1,column=1,sticky=Tix.W+Tix.N)
        rbtn = Tix.Button(frmR,text='Check',command=lambda:self.checknic(self.txtReconNic))
        rbtn.grid(row=1,column=2,sticky=Tix.W)
        Tix.Label(frmR,text='Spoof: ').grid(row=1,column=3,sticky=Tix.W+Tix.N)
        self.txtReconSpoof = Tix.Entry(frmR,width=17)
        self.txtReconSpoof.grid(row=1,column=4,sticky=Tix.W+Tix.N)
        Tix.Label(frmR,text='Desc: ').grid(row=2,column=0,sticky=Tix.W+Tix.N)
        self.txtReconDesc = Tix.Text(frmR,width=42,height=3)
        self.txtReconDesc.grid(row=2,column=1,columnspan=4,sticky=Tix.E)

        # ANTENNA SUB SECTION
        frmRA = Tix.Frame(frmR,borderwidth=2,relief='sunken')
        frmRA.grid(row=4,column=1,columnspan=4,sticky=Tix.N+Tix.W)
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
        frmRS.grid(row=5,column=1,columnspan=4,sticky=Tix.N+Tix.W)
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

        # Collection Configuration
        frmC = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmC.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

        # GPS Configuration
        frmG = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmG.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

        # Storage Configuration
        frmS = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmS.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

        # Local configuration
        frmL = Tix.Frame(frm,borderwidth=2,relief='sunken')
        frmL.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

    def _initialize(self):
        """ insert values from config file into entry boxes """
        conf = ConfigParser.RawConfigParser()
        if not conf.read(wraith.DYSKTCONF):
            tkMB.showerror("File Not Found","File dyskt.conf was not found",parent=self)
            return

        # start by reading the recon radio details
        self.txtReconNic.delete(0,Tix.END)
        if conf.has_option('Recon','nic'):
            self.txtReconNic.insert(0,conf.get('Recon','nic'))
        self.txtReconSpoof.delete(0,Tix.END)
        if conf.has_option('Recon','spoof'):
            self.txtReconSpoof.insert(0,conf.get('Recon','spoof'))
        self.txtReconDesc.delete(1.0,Tix.END)
        if conf.has_option('Recon','desc'):
            self.txtReconDesc.insert(Tix.END,conf.get('Recon','desc'))
        self.txtReconAntNum.delete(0,Tix.END)
        if conf.has_option('Recon','antennas'):
            self.txtReconAntNum.insert(0,conf.get('Recon','antennas'))
        self.txtReconAntGain.delete(0,Tix.END)
        if conf.has_option('Recon','antenna_gain'):
            self.txtReconAntGain.insert(0,conf.get('Recon','antenna_gain'))
        self.txtReconAntType.delete(0,Tix.END)
        if conf.has_option('Recon','antenna_type'):
            self.txtReconAntType.insert(0,conf.get('Recon','antenna_type'))
        self.txtReconAntLoss.delete(0,Tix.END)
        if conf.has_option('Recon','antenna_loss'):
            self.txtReconAntLoss.insert(0,conf.get('Recon','antenna_loss'))
        self.txtReconAntXYZ.delete(0,Tix.END)
        if conf.has_option('Recon','antenna_xyz'):
            self.txtReconAntXYZ.insert(0,conf.get('Recon','antenna_xyz'))
        self.txtReconScanDwell.delete(0,Tix.END)
        if conf.has_option('Recon','dwell'):
            self.txtReconScanDwell.insert(0,conf.get('Recon','dwell'))
        self.txtReconScanStart.delete(0,Tix.END)
        if conf.has_option('Recon','start'):
            self.txtReconScanStart.insert(0,conf.get('Recon','start'))
        self.txtReconScanScan.delete(0,Tix.END)
        if conf.has_option('Recon','scan'):
            self.txtReconScanScan.insert(0,conf.get('Recon','scan'))
        self.txtReconScanPass.delete(0,Tix.END)
        if conf.has_option('Recon','pass'):
            self.txtReconScanPass.insert(0,conf.get('Recon','pass'))

    def _validate(self):
        """ validate entries """
        # start the recon radio details
        #self.txtReconNic.get(0,Tix.END)
        nic = self.txtReconNic.get()
        if not nic:
            tkMB.showerror("Invalid Input",
                            "The Recon radio nic must be specified",
                            parent=self)
            return False
        elif not nic in wifaces():
            tkMB.showwarning("Not Found",
                             "Recond radio %s may not be wireless" % nic)
        spoof = self.txtReconSpoof.get()
        if re.match(MACADDR,spoof) is None:
            tkMB.showerror("Invalid Input",
                           "Spoofed mac addr %s is not valid" % spoof,
                           parent=self)
            return False
        #ignore self.txtReconDesc.delete(1.0,Tix.END)
        if self.txtReconAntNum.get():
            try:
                nA = int(self.txtReconAntNum.get())
                try:
                    gain = map(float,self.txtReconAntGain.get().split(','))
                    if len(gain) != nA: raise DySKTConfigException('Number of gain and number of antennas do not match')
                except:
                    raise DySKTConfigException('Gain must be float or list of floats')
                atype = map(float,self.txtReconAntType.get().split(','))
                if len(atype) != nA: raise DySKTConfigException('Number of types and number of antennas do not match')
                try:
                    gain = map(float,self.txtReconAntLoss.get().split(','))
                    if len(gain) != nA: raise DySKTConfigException('Number of loss and number of antennas do not match')
                except:
                    raise DySKTConfigException('Loss must be float or list of floats')
                try:
                    xyzs = self.txtReconAntXYZ.get().split(',')
                    if len(xyzs) != nA: raise DySKTConfigException('Number of xyz and number of antennas do not match')
                    for xyz in xyzs:
                        xyz = xyz.split(':')
                        if len(xyz) != 3: raise DySKTConfigException('XYZ must be three integers')
                        map(int,xyz)
                except ValueError:
                    raise DySKTConfigException('XYZ must be integer')
            except ValueError:
                tkMB.showerror("Invalid Input",
                               "Number of antennas must be numeric",
                               parent=self)
                return False
            except DySKTConfigException as e:
                tkMB.showerror("Invalid Input",e,parent=self)
                return False

        self.txtReconScanDwell.delete(0,Tix.END)
        self.txtReconScanStart.delete(0,Tix.END)
        self.txtReconScanScan.delete(0,Tix.END)
        self.txtReconScanPass.delete(0,Tix.END)
        return True

    def _write(self):
        """ write entry inputs to config file """
        fout = None
        try:
            conf = ConfigParser.ConfigParser()

            fout = open(wraith.DYSKTCONF,'w')
            conf.write(fout)
            fout.close()
        except IOError as e:
            tkMB.showerror("File Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        except ConfigParser.Error as e:
            tkMB.showerror("Configuration Error",
                           "Error <%s> writing to config file" % e,
                           parent=self)
        else:
            tkMB.showinfo('Success',
                          "Restart for changes to take effect",
                          parent=self)

    def checknic(self,txt):
        """ validates nic is a wireless network interface """
        nic = txt.get()
        if not nic: return
        if nic in wifaces():
            tkMB.showinfo('Found',"%s is a valid wireless NIC" % nic,parent=self)
        else:
            tkMB.showinfo("Not Found","%s is not present and/or a valid wireless NIC" % nic,parent=self)