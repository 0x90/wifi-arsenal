#!/usr/bin/env python
""" panel.py - defines a suite of graphical windows called panes

Defines a graphic suite based on Tix where a set of non-modal panels operate under
the control of a master panel and execute tasks, display information independently
of (or in conjuction with) this panel and other panels. (Think undocked windows)
Panels can be configured so that they can be opened, closed, "raised", minimized
by the user or only by a calling panel.
NOTE:
 a panel may be a master panel and a slave panel.
 one and only panel will be "The Master" Panel

This was actually written in 2009 but was forgotten after two deployments.
Dragging it back out IOT to use a subset for the LOBster program, I noticed that
there were a lot of small errors, irrelevant or redudant code and code that just
did not make sense. So, I am starting basically from scratch and adding the code
for subclasses as they becomes necessary.

 TODO:
   3) handle no icons or invalid icon paths
   4) issues happen with the TailLogger after the corresponding logfile is deleted
   5) create a method in MasterPanel to handle creation of signular pattern i.e.
     panel = self.getpanels(desc,False)
     if not panel:
        t = Tix.Toplevel()
        pnl = PanelClase(t,self,argc)
        self.addpanel(pnl.name,gui.PanelRecord(t,pnl,desc))
      else:
        panel[0].tk.deiconify()
        panel[0].tk.lift()
"""

__name__ = 'panel'
__license__ = 'GPL v3.0'
__version__ = '0.13.6'
__date__ = 'March 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os                         # files operations etc
import time                       # dtg parsing etc
import pickle                     # load and dump
import threading                  # for threads
import Queue                      # for Queue class and Empty exception
import Tix                        # Tix widgets
import tkMessageBox as tkMB       # info dialogs
import tkFileDialog as tkFD       # file gui dialogs
import tkSimpleDialog as tkSD     # input dialogs
from PIL import Image,ImageTk     # image input & support

#### PANEL EXCEPTIONS ####
class PanelException(Exception): pass # TopLevel generic error

class PanelRecord(tuple):
    """
     a record of a panel used as an item in a list of active "slave" panels
      tk - toplevel
      pnl - access this panel's methods
      desc - string description of this panel
    """
    # noinspection PyInitNewSignature
    def __new__(cls,tk,pnl,desc):
        return super(PanelRecord,cls).__new__(cls,tuple([tk,pnl,desc]))
    @property
    def tk(self): return self[0]
    @property
    def pnl(self): return self[1]
    @property
    def desc(self): return self[2]

#### helper dialogs

class PasswordDialog(tkSD.Dialog):
    """ PasswordDialog - (Modal) prompts user for password, hiding input """
    def __init__(self,parent):
        tkSD.Dialog.__init__(self,parent)
        self.entPWD = None
        self.canceled = False
    def body(self,master):
        self.title('sudo Password')
        Tix.Label(master,text='Password: ').grid(row=0,column=1)
        self.entPWD = Tix.Entry(master,show='*')
        self.entPWD.grid(row=0,column=1)
        return self.entPWD
    def validate(self):
        if self.entPWD.get() == '': return 0
        return 1
    def apply(self):
        self.pwd = self.entPWD.get()

#### SUPER GUI CLASSES ####

class Panel(Tix.Frame):
    """
     Panel: This is the base class from which which all non-modal gui classes are
      derived
      1) traps the exit from the title bar and passes it to delete()
      2) maintains a dictionary of opened slave panels
        self._panels[panelname] => panelrecord where:
         panelname is the unique name given by Toplevel._name
         panelrec is a PanelRecord tuple
        NOTE: there may be multiple panels with the same desc but all panels
        can be uniquely identified by the self.name
      3) provides functionality to handle storage/retrieval/deletion of slave
         panels
        
     Derived classes must implement
      delete - user exit trap
      close - normal close

     Derive classes should implement
      notifyclose if the derived class needs to process closing slaves
    """
    # noinspection PyProtectedMember
    def __init__(self,toplevel,iconPath=None):
        """
         toplevel - this is the Toplevel widget for this panel (managed directly
          by the window manger)
         iconPath - path of icon (if one) to display the title bar
        """
        Tix.Frame.__init__(self,toplevel)
        self.appicon = ImageTk.PhotoImage(Image.open(iconPath)) if iconPath else None
        if self.appicon: self.tk.call('wm','iconphoto',self.master._w,self.appicon)
        self.master.protocol("WM_DELETE_WINDOW",self.delete)
        self._panels = {}

    # properties/attributes
    @property
    def name(self): return self._name

    # virtual methods

    def delete(self):
        """ user initiated (from title bar) """
        raise NotImplementedError("Panel::delete")
    def close(self):
        """ master panel initiated """
        raise NotImplementedError("Panel::close")

    #### slave panel storage functions

    def notifyclose(self,name):
        """ slave panel known by name is notifying of a pending close """
        del self._panels[name]

    def addpanel(self,name,panelrec):
        """ adds the panel record panelrec having with unique name to internal """
        self._panels[name] = panelrec

    def killpanel(self,name):
        """ force the panel identifed by name to quit - panel may not cleanup """
        if not name in self._panels: return
        self._panels[name].tk.destroy()
        del self._panels[name]

    def deletepanel(self,name):
        """ delete the panel with name and remove it from the internal dict """
        if not name in self._panels: return
        self._panels[name].pnl.close()
        del self._panels[name]

    def deletepanels(self,desc):
        """ deletes all panels with desc """
        for panel in self.getpanels(desc,False):
            panel.pnl.close()
            del self._panels[panel.pnl.name]

    def getpanel(self,desc,pnlOnly=True):
        """
         returns the first panel with desc or None
         if pnlOnly is True returns the panel object otherwise returns the
         PanelRecord
        """
        for name in self._panels:
            if self._panels[name].desc == desc:
                if pnlOnly: return self._panels[name].pnl
                else: return self._panels[name]
        return None
        
    def getpanels(self,desc,pnlOnly=True):
        """
         returns all panels with desc or [] if there are none open
         if pnlOnly is True returns the panel object otherwise returns the
         PanelRecord
        """
        opened = []
        for name in self._panels:
            if self._panels[name].desc == desc:
                if pnlOnly:
                    opened.append(self._panels[name].pnl)
                else:
                    opened.append(self._panels[name])
        return opened

    def haspanel(self,desc):
        """ returns True if there is at least one panel with desc """
        for name in self._panels:
            if self._panels[name].desc == desc: return True
        return False

    def numpanels(self,desc):
        """ returns a count of all panels with desc """
        n = 0
        for name in self._panels:
            if self._panels[name].desc == desc: n +=1
        return n

    def closepanels(self):
        """ notifies all open panels to close """
        for name in self._panels: self._panels[name].pnl.close()

    # message box methods
    def err(self,t,m): tkMB.showerror(t,m,parent=self)
    def warn(self,t,m): tkMB.showwarning(t,m,parent=self)
    def info(self,t,m): tkMB.showinfo(t,m,parent=self)
    def ask(self,t,m,opts=None):
        if opts == 'retrycancel': return tkMB.askretrycancel(t,m,parent=self)
        elif opts == 'yesno': return tkMB.askyesno(t,m,parent=self)
        elif opts == 'okcancel': return tkMB.askokcancel(t,m,parent=self)
        else: return tkMB.askquestion(t,m,parent=self)

class SlavePanel(Panel):
    """
     SlavePanel - defines a slave panel which has a controlling panel. i.e. it
     is opened dependant on and controlled by another panel. The name can be
     a misnomer as this class can also control slave panels

     Derived classes must implement:
      _shutdown: perform necessary cleanup functionality
      reset: Master panel is requesting the panel to reset itself
      update: Master panel is requesting the panel to update itself

    Derived classes should override:
     delete if they want to dissallow user from closing the panel
     notifyclose if they need to further handle closing Slave panels

     NOTE: The SlavePanel itself has no methods to define gui widgets, i.e.
      menu, main frame etc
    """
    def __init__(self,toplevel,chief,iconPath=None):
        """ chief is the controlling (Master) panel """
        Panel.__init__(self,toplevel,iconPath)
        self._chief = chief

    def _shutdown(self):
        """ cleanup functionality prior to quitting """
        raise NotImplementedError("SlavePanel::_shutdown")

    def reset(self):
        """ reset to original/default setup """
        raise NotImplementedError("SlavePanel::reset")

    def update(self):
        """ something has changed, update ourselve """
        raise NotImplementedError("SlavePanel::update")

    def delete(self):
        """user initiated - notify master of request to close """
        self._chief.notifyclose(self.name)
        self.close()

    def close(self):
        """
         master panel is notifying us to close, notify any slave panels to close,
         cleanup, then quit
        """
        self.closepanels()
        self._shutdown()
        self.master.destroy()

class SimplePanel(SlavePanel):
    """
     Defines a simple panel with body. Should be used to define simple description
     panels with minimal user interaction displaying static data. SimplePanels are
     not expected to have any slave panels. Additionally, showing static data,
     SimplePanels are not expected to display information that needs to be
     updated or reset.

     Derived class must implement:
      _body: define gui widgets
      in addition to SlavePanel::_shutdown, SlavePanel::reset, SlavePanel::update

     Derived class should override:
      reset,update if dynamic data is being displayed
      _shutdown if any cleanup needs to be performed prior to closing
    """
    def __init__(self,toplevel,chief,title,iconpath=None):
        SlavePanel.__init__(self,toplevel,chief,iconpath)
        self.master.title(title)
        self.pack(expand=True,fill=Tix.BOTH,side=Tix.TOP)
        frm = Tix.Frame(self)
        frm.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)
        self._body(frm)
    def _body(self,frm): raise NotImplementedError("SimplePanel::_body")
    def reset(self): pass
    def update(self): pass
    def _shutdown(self): pass

class ConfigPanel(SlavePanel):
    """
     Configuration file view/edit panel. Provides a frame for input widgets and
     a button frame with
      ok: writes new values to config file and exits
      apply: writes new values to config file
      widgetreset: resets to original file (not to be confused with SlavePanel::Reset)
      cancel: exits without writing to config file

     Derived classes must implement
      _makegui add widgets to view/edit configuration file entries
      _initialize initial entry of config file values into the widgets. It is
        also used by the reset to button
      _validate validate entries before writing (derived class must handle
       displaying error messages to user) returns True if all widget entries
       are valid, False otherwise
      _write writes the values of the entries into the config file
    """
    def __init__(self,toplevel,chief,title):
        """ initialize configuration panel """
        SlavePanel.__init__(self,toplevel,chief,"widgets/icons/config.png")
        self.master.title(title)
        self.pack(expand=True,fill=Tix.BOTH,side=Tix.TOP)

        # set up the input widget frame
        frmConfs = Tix.Frame(self)
        self._makegui(frmConfs)
        frmConfs.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

        # set up the button widget frame
        frmBtns = Tix.Frame(self)
        frmBtns.pack(side=Tix.TOP)

        # four buttons, Ok, Apply, Reset and Cancel
        Tix.Button(frmBtns,text='OK',command=self.ok).grid(row=0,column=0)
        Tix.Button(frmBtns,text='Apply',command=self.apply).grid(row=0,column=1)
        Tix.Button(frmBtns,text='Reset',command=self.widgetreset).grid(row=0,column=2)
        Tix.Button(frmBtns,text='Cancel',command=self.cancel).grid(row=0,column=3)

        # insert values from config file
        self._initialize()

    def _makegui(self,frm): raise NotImplementedError("ConfigPanel::_makegui")
    def _initialize(self): raise NotImplementedError("ConfigPanel::_initialize")
    def _validate(self): raise NotImplementedError("ConfigPanel::_validate")
    def _write(self): raise NotImplementedError("ConfigPanel::_write")

    # Slave Panel abstract methods we do not need for this class
    def reset(self): pass
    def update(self): pass
    def _shutdown(self): pass

    def ok(self):
        """ validate entries and if good write to file then close """
        if self._validate():
            self._write()
            self.delete()

    def apply(self):
        """ validate entries and if good, write to file but leave open """
        if self._validate(): self._write()

    def widgetreset(self):
        """ reset entries to orginal configuration file """
        self._initialize()

    def cancel(self):
        """ make now changes and close """
        self.delete()

class ListPanel(SlavePanel):
    """
     ListPanel - A simple SlavePanel with a ScrolledHList which displays
     information and the option to add widgets to a topframe and/or bottom frame.
     Derived classes can configure the ScrolledHList's number of columns, and
     whether or not to include headers for the columns.

     NOTE: this class does not define any methods to insert/remove/delete from
      this list

     Derived classes should implement:
      topframe if any widgets need to be added to the top frame
      bottomframe if any widgets need to be added to the bottom frame
    """
    def __init__(self,toplevel,chief,ttl,sz,cols=1,httl=None,iconPath=None):
        SlavePanel.__init__(self,toplevel,chief,iconPath)
        self.master.title(ttl)
        self.pack(expand=True,fill=Tix.BOTH,side=Tix.TOP)

        # create and allow derived classes to setup top frame
        frmTop = Tix.Frame(self)
        if self.topframe(frmTop): frmTop.pack(side=Tix.TOP,expand=False)

        # need hdr value for HList init
        hdr = True
        if not httl: hdr = False

        # setup the hlist
        self.frmMain = Tix.Frame(self)
        self.frmMain.pack(side=Tix.TOP,fill=Tix.BOTH,expand=True)

        # create the scrolled hlist
        # NOTE: if necessary, should be able to use Tree as below
        # self.slist = Tree(self.frmMain,options='hlist.columns %d hlist.header %d' % (cols,hdr))
        self.slist = Tix.ScrolledHList(self.frmMain,
                                       options='hlist.columns %d hlist.header %d' % (cols,hdr))

        # configure the hlist
        self.list = self.slist.hlist                       # get the hlist
        if sz: self.list.config(width=sz[0],height=sz[1])  # set the width/height
        self.list.config(selectforeground='black')         # set to black or it dissappears
        self.list.config(selectmode='extended')            # allow multiple selects
        self.list.config(separator='\t')                   # use tab ignoring special chars

        style = {}
        style['header'] = Tix.DisplayStyle(Tix.TEXT,
                                           refwindow=self.list,
                                           anchor=Tix.CENTER)
        for i in range(len(httl)):
            self.list.header_create(i,itemtype=Tix.TEXT,text=httl[i],
                                      style=style['header'])

        # and pack the scrolled list
        self.slist.pack(expand=True,fill=Tix.BOTH,side=Tix.LEFT)

        # allow a bottom frame
        frmBottom = Tix.Frame(self)
        if self.bottomframe(frmBottom):
            frmBottom.pack(side=Tix.TOP,expand=False)

    # noinspection prPyUnusedLocal
    def topframe(self,frm): return None # override to add widgets to topframe
    # noinspection PyUnusedLocal
    def bottomframe(self,frm): return None # override to add widgets to bottomframe

#### LOG MESSAGE TYPES ####
LOG_NOERR = 0
LOG_WARN  = 1
LOG_ERR   = 2
LOG_NOTE  = 3

class LogPanel(ListPanel):
    """
     a singular panel which display information pertaining to the "program",
     cannot be closed by the user only by the MasterPanel
    """
    def __init__(self,toplevel,chief):
        ListPanel.__init__(self,toplevel,chief,"Log",(60,8),2,[],"widgets/icons/log.png")
        self._l = threading.Lock()                              # lock on writing
        self._n = 0                                             # current number of entries
        self._LC = [Tix.DisplayStyle(Tix.TEXT,                  # display styles
                                    refwindow=self.list,
                                    foreground='Green',
                                    selectforeground='Green'),
                   Tix.DisplayStyle(Tix.TEXT,
                                    refwindow=self.list,
                                    foreground='Yellow',
                                    selectforeground='Yellow'),
                   Tix.DisplayStyle(Tix.TEXT,
                                    refwindow=self.list,
                                    foreground='Red',
                                    selectforeground='Red'),
                   Tix.DisplayStyle(Tix.TEXT,
                                    refwindow=self.list,
                                    foreground='Blue',
                                    selectforeground='Blue')]
        self._symbol = ["[+] ","[?] ","[-] ","[!] "]           # type symbols
    def delete(self): pass    # user can never close only the primary chief
    def reset(self): pass     # nothing needs to be reset
    def update(self): pass    # nothing needs to be updated
    def _shutdown(self): pass # nothing needs to be cleaned up
    def logwrite(self,msg,mtype=LOG_NOERR):
        """ writes message msg of type mtype to the log """
        self._l.acquire()
        try:
            entry = str(self._n)
            self.list.add(entry,itemtype=Tix.TEXT,text=time.strftime('%H:%M:%S'))
            self.list.item_create(entry,1,text=self._symbol[mtype] + msg)
            self.list.item_configure(entry,0,style=self._LC[mtype])
            self.list.item_configure(entry,1,style=self._LC[mtype])
            self._n += 1
            self.list.yview('moveto',1.0)
        except:
            pass
        finally:
            self._l.release()

class TailLogger(threading.Thread):
    """ periodically reads the specified logfile and returns any new 'lines' """
    def __init__(self,q,cb,errcb,polltime,logfile):
        """
         initialize the thread
          q - event queue
          cb - callback function for new lines
          errcb - callback function to report any errors
          polltime - time to sleep between polls
          logfile - logfile to tail
         NOTE: the parameter cmd must be initialized/set with all keys and starting
          values beforing being passed to __init__, any key:value pairs set after
          initialized will not be 'seen' by the thread
        """
        threading.Thread.__init__(self)
        self._q = q              # command queue from caller
        self._errcb = errcb      # error callback to report failures
        self._pause = polltime   # time to sleep between file checks
        self._lf = logfile       # path of file to monitor
        self._cb = cb            # callback for new lines
        self._ctime = None       # last time logfile was changed
        self._offset = None      # offset of last file

    def run(self):
        """ polls until told to stop or internal error is encountered """
        # get intial file metadata and any intial lines
        try:
            self._ctime = os.stat(self._lf).st_ctime # get current change time
            fin = open(self._lf,'r')                 # open file
            lines = fin.readlines()                  # read all lines
            self._offset = fin.tell()                # get current offset
            fin.close()                              # close the file
            self._cb(lines)                          # forward the lines
        except Exception as e:
            self._errcb(e)
            return

        while True:
            try:
                tkn = self._q.get(True,self._pause)
                if tkn == '!STOP!': break
                # no other commands expected ATT
            except Queue.Empty:
                # nothing on the queue, see if anything has changed
                try:
                    ctime = os.stat(self._lf).st_ctime # latest change time
                    if ctime != self._ctime:           # any changes?
                        fin = open(self._lf,'r')       # open for reading
                        fin.seek(self._offset-1)       # go to last read position
                        lines = fin.readlines()        # read all new lines
                        self._offset = fin.tell()      # get new position
                        fin.close()                    # close the file
                        self._ctime = ctime            # update change time
                        self._cb(lines)                # forward newly read lines
                except Exception as e:
                    self._errcb(e)
                    break

class TailLogPanel(ListPanel):
    """ Displays log data from a file - graphically similar to tail -f <file> """
    def __init__(self,toplevel,chief,ttl,polltime,logfile):
        """ initializes TailLogPanel to read from the file specified logfile """
        ListPanel.__init__(self,toplevel,chief,ttl,(60,8),1,[],"widgets/icons/log.png")
        self._n = 0
        self._lf = logfile
        if not os.path.exists(logfile) and not os.path.isfile(logfile):
            self._chief.logwrite("Log File %s does not exist" % logfile,LOG_ERR)
            return
        self._polltime = polltime
        self._logPoller = None
        self._threadq = None
        self._startlogger()

    # CALLBACKS
    def newlines(self,lines):
        """ callback for polling thread to pass new data """
        for line in lines:
            entry = str(self._n)
            self.list.add(entry,itemtype=Tix.TEXT,text=line.strip())
            self._n += 1
            self.list.yview('moveto',1.0)

    def logerror(self,err):
        """ received error callback for polling thread """
        self._chief.logwrite("Log for %s failed %s" % (os.path.split(self._lf)[1],
                                                       err),LOG_ERR)

    # VIRTUAL METHOD OVERRIDES

    def reset(self):
        """ resets the log panel """
        # stop the polling thread and join
        self._shutdown()

        # reset internal structures and clear the list
        if self._n:
            self._n = 0
            self.list.delete_all()

        # reset the log poller
        self._startlogger()

    def update(self): pass # no need to implement

    def _shutdown(self):
        """ clean up our polling thread """
        # stop polling thread and wait for it to finish
        if self._logPoller:
            self._threadq.put('!STOP!')
            self._logPoller.join()

    def _startlogger(self):
        try:
            self._threadq = Queue.Queue()
            self._logPoller = TailLogger(self._threadq,self.newlines,self.logerror,
                                         self._polltime,self._lf)
            self._logPoller.start()
        except Exception as e:
            self._logPoller = None
            self._chief.logwrite("Log for %s failed %s" % (self._lf,e))

class MasterPanel(Panel):
    """
     the MasterPanel is the primary panel which controls the flow of the overall
     program. The MasterPanel defines a class meant to handle the primary data,
     opening, closing children panels etc.
     
     Derived classes should implement:
      _initialize -> if there is functionality that should be started
      _shutdown -> if there is functionality that should be cleanly stopped
      _makemenu -> to implement any menu
      getstate -> if there is a State of the main panel that needs to be known
       by slave panels
      showpanel -> derive for use in toolsload (loads saved panel configs)
      delete and close if the derived class must further handle shutting down
    """
    def __init__(self,toplevel,ttl,datatypes=None,logpanel=True,iconPath=None):
        """
         ttl - title of the window/panel
         datatypes - list of strings for data bins, etc
         logpanel - if True, will initiate a logpanel
         iconPath - path of image to show as icon for this panel
        """
        Panel.__init__(self,toplevel,iconPath)
        self.tk = toplevel
        self.menubar = None
        
        # data bins, registered panels, and what data is hidden, selected
        self.audit_registered = {} # panels auditing for notification
        self.bin = {}              # data dictionaries
        self.hidden = {}           # keys of hidden data in bin
        self.selected = {}         # keys of selected data in bin
        for datatype in datatypes:
            self.audit_registered[datatype] = []
            self.bin[datatype] = {}
            self.hidden[datatype] = []
            self.selected[datatype] = []   

        # set the title
        self.master.title(ttl)
        self.grid(sticky=Tix.W+Tix.N+Tix.E+Tix.S)
        
        # try and make the menu
        self._makemenu()
        try:
            self.master.config(menu=self.menubar)
        except AttributeError:
            self.master.tk.call(self.master,"config","-menu",self.menubar)
            
        # make the log panel?
        if logpanel: self.viewlog()

        # initialiez
        self._initialize()

        # is there a default toolset saved?
        if os.path.exists('default.ts'): self.guiload('default.ts')
        self.update_idletasks()

    # Panel overrides

    def delete(self):
        """ title bar exit trap """
        self.close()

    def close(self):
        """ cleanly exits - shuts down as necessary """
        ans = self.ask('Quit?','Really Quit')
        if ans == 'no':
            return
        else:
            self.logwrite('Quitting...')
            #self.closepanels()
            self._shutdown()
            self.quit()

    def notifyclose(self,name):
        """
         override notifyclose, before allowing requesting panel to close,
         deregister it we need to remove all notification requests from
         the panel before deleting it
        """
        if name in self._panels: self.audit_deregister(name)
        del self._panels[name]

    def _initialize(self): pass
    def _shutdown(self): pass
    def _makemenu(self): pass
    def showpanel(self,t): raise NotImplementedError("MasterPanel::showpanel")

    @property
    def getstate(self): return None

    def viewlog(self):
        """ displays the log panel """
        panel = self.getpanels("log",False)
        if not panel:
            t =Tix.Toplevel()
            pnl = LogPanel(t,self)
            self.addpanel(pnl._name,PanelRecord(t,pnl,"log"))
            pnl.update_idletasks()
            t.wm_geometry("-0-0")
        else:
            panel[0].tk.deiconify()
            panel[0].tk.lift()

    def unimplemented(self):
        """ displays info dialog with not implmented message """
        self.info('Not Implemented',"This function not currently implemented")
        
    def guisave(self):
        """ saves current toolset configuration """
        fpath = tkFD.asksaveasfilename(title='Save Toolset',
                                       filetypes=[('Toolset files','*.ts')])
        if fpath:
            gs = self.tk.winfo_geometry().split('+')
            ts = {}
            for panel in self._panels:
                c = self._panels[panel]
                c.pnl.update_idletasks()
                if c.desc != 'log':
                    if c.desc in ts:
                        ts[c.desc].append(c.tk.winfo_geometry())
                    else:
                        ts[c.desc] = [c.tk.winfo_geometry()]
            try:
                f = open(fpath,'wb')
                pickle.dump(ts,f)
                f.close()
            except Exception as e:
                self.logwrite(e,LOG_ERR)

    def guiload(self,fpath=None):
        """ loads a saved toolset configuration """
        if not fpath:
            fpath = tkFD.askopenfilename(title='Open Toolset',
                                        filetypes=[('Toolset files','*.ts')],
                                        parent=self)
        
        if fpath:
            # open & get the saved windows + their geometry
            try:
                f = open(fpath,'rb')
                ts = pickle.load(f)
                f.close()
            except Exception as e:
                self.logwrite(e,LOG_ERR)
            else:
                # for each saved open it (unless it already exists) and move to 
                # saved position
                for t in ts:
                    self.deletepanels(t)
                    for _ in ts[t]: self.showpanel(t)
                
                    i = 0
                    for panel in self.getpanels(t,False):
                        panel.tk.wm_geometry(ts[t][i])
                        i += 1

    def logwrite(self,msg,mtype=LOG_NOERR):
        """ writes msg to log or shows in error message """
        log = self.getpanel("log",True)
        if log:
            log.logwrite(msg,mtype)
        elif mtype == LOG_ERR:
             self.err('Error',msg)

    # Panel/date update functionality

    def audit_register(self,dtype,name):
        """ register panel for dtype audits """
        self.audit_registered[dtype].append(name)

    def audit_deregister(self,name):
        """
         deregister panel from all audits
        """
        for registered in self.audit_registered:
            if name in self.audit_registered[registered]:
                self.audit_registered[registered].remove(name)

    def hideentries(self,dtype,name,ids):
        """
         notification that the panel name is hiding ids - will notify all audit 
         registered panels that these ids are hidden
        """
        self.hidden[dtype].extend(ids)
        for panel in self.audit_registered[dtype]:
            if panel != name:
                self._panels[panel].pnl.notifyhiddencb(dtype,ids)

    def selectentries(self,dtype,name,ids):
        """
         notification that the panel name has selected ids - will notify all audit
         registered panels that these ids are selected
        """
        self.selected[dtype] = ids
        for panel in self.audit_registered[dtype]:
            if panel != name: 
                self._panels[panel].pnl.notifyselectcb(dtype,ids)
        
    def restorehidden(self,dtype,name):
        """
         notification that the panel name is restoring ids - will notify all audit
        registered panels that all ids are being restored
        """
        h = self.hidden[dtype]
        self.hidden[dtype] = []
        for panel in self.audit_registered[dtype]:
            if panel != name:
                self._panels[panel].pnl.notifyrestorecb(dtype,h)

    def updatepanels(self):
        """ notify open panels something has changed """
        # use keys() to handle event where a panel may close itself
        for name in self._panels: self._panels[name].pnl.update()

    def resetpanels(self):
        """ notify open panels everything is reset """
        for name in self._panels: self._panels[name].pnl.reset()