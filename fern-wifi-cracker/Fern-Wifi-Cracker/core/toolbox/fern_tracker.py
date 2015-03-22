import os
import thread
import sqlite3

import tracker_core

from gui.geotrack import *
from core  import variables

from PyQt4 import QtGui,QtCore

fern_map_access = tracker_core.Fern_Geolocation()

class Fern_geolocation_tracker(QtGui.QDialog,Ui_fern_geotrack):
    '''Main windows class'''
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.database_accesspoint = {}  # Holds all database accesspoint name and mac details
        self.idlelize_items()
        self.set_database_access_points()
        self.display_html(variables.html_instructions_message)

        self.connect(self.database_radio,QtCore.SIGNAL("clicked()"),self.set_database_mode)
        self.connect(self.insert_mac_radio,QtCore.SIGNAL("clicked()"),self.set_mac_mode)
        self.connect(self.track_button,QtCore.SIGNAL("clicked()"),self.launch_tracker)
        self.connect(self,QtCore.SIGNAL("network timeout"),self.internet_connection_error)
        self.connect(self,QtCore.SIGNAL("display map"),self.display_map)


    #
    # Database process methods
    #
    def database_items(self):
        ''' return list of database items'''
        database = sqlite3.connect(os.getcwd() + '/key-database/Database.db')
        database_connection = database.cursor()
        database_connection.execute('select * from keys')
        database_items = database_connection.fetchall()
        database.close()
        return database_items


    def set_database_access_points(self):
        ''' fill combobox with database accesspoint
            details
        '''
        if self.database_items():
            self.database_radio.setChecked(True)
            self.target_combo.setEditable(False)
            for data_ in self.database_items():
                if fern_map_access.isValid_Mac(data_[1]):
                    self.database_accesspoint[str(data_[0])] = str(data_[1])  # {'GLASS_HAWK':'0C:67:34:12:89:76'}
            self.target_combo.addItems(sorted(self.database_accesspoint.keys()))
        else:
            self.target_combo.setEditable(True)
            self.insert_mac_radio.setChecked(True)

    #
    # User option methods
    #
    def set_database_mode(self):
        ''' Change combo mode and insert database details'''
        if self.database_items():
            self.database_radio.setChecked(True)
            self.target_combo.setEditable(False)
            self.set_database_access_points()
        else:
            self.target_combo.setEditable(True)
            self.insert_mac_radio.setChecked(True)
            QtGui.QMessageBox.warning(self,'Empty Database entries',variables.database_null_error.strip('/n'))
            self.target_combo.setFocus()
            self.target_combo.clear()



    def set_mac_mode(self):
        ''' Change combo mode for manual mac-address insertion'''
        self.target_combo.setEditable(True)
        self.insert_mac_radio.setChecked(True)
        self.target_combo.setFocus()
        self.target_combo.clear()

    def get_unprocessed_mac(self):
        if self.database_radio.isChecked():
            access_point = str(self.target_combo.currentText())
            mac_address = self.database_accesspoint[access_point]
        else:
            mac_address = str(self.target_combo.currentText())
        return mac_address


    #
    # Fern Track initialization
    #
    def launch_tracker(self):
        ''' Evaluate user options and sets tracker class variables'''
        self.idlelize_items()
        self.display_html(str())
        if self.database_radio.isChecked():
            fern_map_access.set_mac_address(self.get_unprocessed_mac())
            self.track_button.setText('Tracking...')
            thread.start_new_thread(self.display_tracking,())
        else:
            if fern_map_access.isValid_Mac(self.get_unprocessed_mac()):
                fern_map_access.set_mac_address(self.get_unprocessed_mac())
                self.track_button.setText('Tracking...')
                thread.start_new_thread(self.display_tracking,())
            else:
                QtGui.QMessageBox.warning(self,'Invalid Mac Address',variables.invalid_mac_address_error.strip('/n'))
                self.display_html(variables.html_instructions_message)
                self.target_combo.setFocus()


    #
    # Map Display methods
    #
    def display_html(self,html):
        '''Displays map or error pages'''
        self.map_viewer.setHtml(html)


    def display_map(self):
        '''Set map display'''
        self.activate_items()
        self.display_html(fern_map_access.get_fern_map())


    def display_tracking(self):
        ''' Processes and displays map '''
        if int(variables.commands.getstatusoutput('ping www.google.com -c 3')[0]):
            self.emit(QtCore.SIGNAL("network timeout"))
        else:
            self.emit(QtCore.SIGNAL("display map"))

    #
    # Error display messages
    #
    def internet_connection_error(self):
        '''Displays Internet error messages'''
        self.idlelize_items()
        self.display_html(variables.html_network_timeout_error)


    #
    # Co-ordinate details
    #
    def idlelize_items(self):
        '''Set GUI objects to idle mode'''
        self.mac_address_label.setText("Mac Address:")
        self.country_label.setText("Country:")
        self.latitude_label.setText("Latitude:")
        self.city_label.setText("City: ")
        self.longitude_label.setText("Longitude:")
        self.street_label.setText("Street:")
        self.accuracy_label.setText("Accuracy:")
        self.country_code_label.setText("Country Code:")
        self.track_button.setText("Track")


    def activate_items(self):
        '''Active and fill GUI objects with details'''
        full_geo_details = fern_map_access.get_all_geoinfo()
        try:
            self.mac_address_label.setText("Mac Address: <font color=green><b>%s</b></font>"%\
                                            (self.get_unprocessed_mac()))
        except(KeyError):pass
        try:
            self.country_label.setText("Country: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['address']['country']))
        except(KeyError):pass
        try:
            self.latitude_label.setText("Latitude: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['latitude']))
        except(KeyError):pass
        try:
            self.city_label.setText("City: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['address']['city']))
        except(KeyError):pass
        try:
            self.longitude_label.setText("Longitude: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['longitude']))
        except(KeyError):pass
        try:
            self.street_label.setText("Street: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['address']['street']))
        except(KeyError):pass
        try:
            self.accuracy_label.setText("Accuracy: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['accuracy']))
        except(KeyError):pass
        try:
            self.country_code_label.setText("Country Code: <font color=green><b>%s</b></font>"%\
                                        (full_geo_details['location']['address']['country_code']))
        except(KeyError):pass
        try:
            self.track_button.setText("Track")
        except(KeyError):pass











