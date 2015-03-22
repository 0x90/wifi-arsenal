#!/usr/bin/env python

# example helloworld2.py

import pygtk
pygtk.require('2.0')
import gtk

class WifiTapGui:

    # another callback
    def delete_event(self, widget, event, data=None):
        gtk.main_quit()
        return False

    def init_config_tab(self):
        self.entries['config'] = {}
        entries = {}

        hbox = gtk.HBox()
        tap_dialog = gtk.Frame("Tap Interface")
        tap_dialog.add(gtk.Layout())

        # Name
        tap_dialog.get_child().put(gtk.Label("Name:"),5,8)
        entries['name'] = gtk.Entry()
        tap_dialog.get_child().put(entries['name'],42,5)
        # IPv4 address
        tap_dialog.get_child().put(gtk.Label("IPv4 Address:"),5,42)
        entries['ipv4'] = gtk.Entry()
        tap_dialog.get_child().put(entries['ipv4'],80,39)
        # IPv6 address
        tap_dialog.get_child().put(gtk.Label("IPv6 Address:"),5,76)
        entries['ipv6'] = gtk.Entry()
        tap_dialog.get_child().put(entries['ipv6'],80,73)

        self.entries['config']['tap'] = entries
        hbox.pack_start(tap_dialog)

        inject_dialog = gtk.Frame("Frame Injection")
        inject_dialog.add(gtk.Layout())

        entries = {}
        # Interface
        inject_dialog.get_child().put(gtk.Label("Interface:"),5,8)
        entries['intf'] = gtk.Entry(15)
        inject_dialog.get_child().put(entries['intf'],62,5)
        # Rate
        inject_dialog.get_child().put(gtk.Label("Rate (Mbt/s):"),5,42)
        entries['rate'] = gtk.combo_box_new_text()
        for r in '  1','  2','5.5','  6','  9',' 11',' 12',' 18',' 24',' 36',' 48',' 54':
            entries['rate'].append_text(r)
        inject_dialog.get_child().put(entries['rate'],82,35)
        #HGI
        inject_dialog.get_child().put(gtk.Label("HGI:"),170,42)
        entries['hgi'] = gtk.CheckButton()
        inject_dialog.get_child().put(entries['hgi'],190,35)
        # Source MAC
        inject_dialog.get_child().put(gtk.Label("Source MAC:"),5,76)
        entries['smac'] = gtk.Entry(17)
        inject_dialog.get_child().put(entries['smac'],78,73)
        # BSSID
        inject_dialog.get_child().put(gtk.Label("Target AP MAC:"),5,110)
        entries['bssid'] = gtk.Entry(17)
        inject_dialog.get_child().put(entries['bssid'],92,107)
        # Retry Count`
        inject_dialog.get_child().put(gtk.Label("Retry Count:"),5,144)
        entries['retries'] = gtk.Entry(3)
        entries['retries'].set_width_chars(3)
        inject_dialog.get_child().put(entries['retries'],79,141)
        # Sequence Control
        inject_dialog.get_child().put(gtk.Label("Sequence Ctl:"),140,144)
        entries['seq_ctl'] = gtk.CheckButton()
        inject_dialog.get_child().put(entries['seq_ctl'],216,137)
        # WEP toggle
        inject_dialog.get_child().put(gtk.Label("WEP:"),5,178)
        entries['wep'] = gtk.CheckButton()
        inject_dialog.get_child().put(entries['wep'],30,172)
        # WEP Key
        inject_dialog.get_child().put(gtk.Label("Key:"),17,202)
        entries['wep_key'] = gtk.Entry()
        inject_dialog.get_child().put(entries['wep_key'],40,199)
        # WEP ID
        inject_dialog.get_child().put(gtk.Label("ID:"),17,231)
        entries['wep_id'] = gtk.Entry()
        inject_dialog.get_child().put(entries['wep_id'],40,227)

        self.entries['config']['inject'] = entries
        hbox.pack_start(inject_dialog)

        bbox = gtk.HButtonBox()
        bbox.set_layout(gtk.BUTTONBOX_END)

        entries = {}
        for b in 'start','stop','apply':
            entries[b] = gtk.Button(label=b.capitalize())
            entries[b].connect("clicked", self.config_button, b)
            bbox.pack_start(entries[b])

        vbox = gtk.VBox()
        vbox.pack_start(hbox)
        vbox.pack_start(bbox,expand=False)

        return vbox

    def config_button(self,button,name):
        print("%s was pushed" % name)

    def __init__(self):
        self.entries = {}

        # Create a new window
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.main_vbox = gtk.VBox()
        self.window.add(self.main_vbox)

        # This is a new call, which just sets the title of our
        # new window to "Hello Buttons!"
        self.window.set_title("WifiTap")
        self.window.set_default_size(640,480)

        # Here we just set a handler for delete_event that immediately
        # exits GTK.
        self.window.connect("delete_event", self.delete_event)

        # Sets the border width of the window.
        self.window.set_border_width(10)

        # We create a box to pack widgets into.  This is described in detail
        # in the "packing" section. The box is not really visible, it
        # is just used as a tool to arrange widgets.
        self.notebook1 = gtk.Notebook()
        self.tab1 = self.init_config_tab()
        self.notebook1.append_page(self.tab1,gtk.Label("Configuration"))

        self.status_bar = gtk.Statusbar()

        # Put the box into the main window.
        self.main_vbox.add(self.notebook1)
        self.main_vbox.pack_start(self.status_bar,expand=False)

        self.window.show_all()

def main():
    gtk.main()

if __name__ == "__main__":
    wt_gui = WifiTapGui()
    main()

