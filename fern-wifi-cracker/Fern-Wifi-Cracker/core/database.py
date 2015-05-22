import core
from gui.database import *
from core.functions import *
from core.variables import *

#
#  Class for Database key entries
#
class database_dialog(QtGui.QDialog,database_ui):
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        self.display_keys()

        self.connect(self.insert_button,QtCore.SIGNAL("clicked()"),self.insert_row)
        self.connect(self.delete_button,QtCore.SIGNAL("clicked()"),self.delete_row)
        self.connect(self.save_button,QtCore.SIGNAL("clicked()"),self.save_changes)




    def display_keys(self):
        connection = sqlite3.connect('key-database/Database.db')
        query = connection.cursor()
        query.execute('''select * from keys''')
        items = query.fetchall()
        query.close()

        for iterate in range(len(items)):              # Update QTable with entries from Database and

            tuple_sequence = items[iterate]

            if len(tuple_sequence) == 4:                      # If we have access point mac-address absent
                access_point_var = tuple_sequence[0]
                mac_address_var = '\t'
                encryption_var = tuple_sequence[1].upper()
                key_var = tuple_sequence[2]
                channel_var = tuple_sequence[3]
            else:
                access_point_var = tuple_sequence[0]
                mac_address_var = tuple_sequence[1]
                encryption_var = tuple_sequence[2].upper()
                key_var = tuple_sequence[3]
                channel_var = tuple_sequence[4]

            self.key_table.insertRow(iterate)

            access_point_display = QtGui.QTableWidgetItem()
            mac_address_display = QtGui.QTableWidgetItem()
            encryption_display = QtGui.QTableWidgetItem()
            key_display = QtGui.QTableWidgetItem()
            channel_display = QtGui.QTableWidgetItem()

            access_point_display.setText(QtGui.QApplication.translate("Dialog", "%s"%(access_point_var), None, QtGui.QApplication.UnicodeUTF8))
            self.key_table.setItem(iterate,0,access_point_display)

            mac_address_display.setText(QtGui.QApplication.translate("Dialog", "%s"%(mac_address_var), None, QtGui.QApplication.UnicodeUTF8))
            self.key_table.setItem(iterate,1,mac_address_display)

            encryption_display.setText(QtGui.QApplication.translate("Dialog", "%s"%(encryption_var), None, QtGui.QApplication.UnicodeUTF8))
            self.key_table.setItem(iterate,2,encryption_display)

            key_display.setText(QtGui.QApplication.translate("Dialog", "%s"%(key_var), None, QtGui.QApplication.UnicodeUTF8))
            self.key_table.setItem(iterate,3,key_display)

            channel_display.setText(QtGui.QApplication.translate("Dialog", "%s"%(channel_var), None, QtGui.QApplication.UnicodeUTF8))
            self.key_table.setItem(iterate,4,channel_display)



    def insert_row(self):
        self.key_table.insertRow(0)

    def delete_row(self):
        current_row = int(self.key_table.currentRow())
        self.key_table.removeRow(current_row)

    def save_changes(self):
        row_number = self.key_table.rowCount()
        fern_database_query('''delete from keys''')    # Truncate the "keys" table

        for controller in range(row_number):
            try:
                access_point1 = QtGui.QTableWidgetItem(self.key_table.item(controller,0))   # Get Cell content
                mac_address1 = QtGui.QTableWidgetItem(self.key_table.item(controller,1))
                encryption1 = QtGui.QTableWidgetItem(self.key_table.item(controller,2))
                key1 = QtGui.QTableWidgetItem(self.key_table.item(controller,3))
                channel1 = QtGui.QTableWidgetItem(self.key_table.item(controller,4))

                access_point = str(access_point1.text())                                    # Get cell content text
                mac_address = str(mac_address1.text())
                encryption2 = str(encryption1.text())
                encryption = encryption2.upper()
                key = key1.text()
                channel = channel1.text()

                if not (bool(access_point) and bool(mac_address) and bool(encryption) and bool(key) and bool(channel)):
                    raise(TypeError)

                set_key_entries(access_point,mac_address,encryption,key,channel)       # Write enrties to database

            except(TypeError):
                QtGui.QMessageBox.warning(self,"Empty Database Entries",\
                    "There are some fields with whitespaces,Please enter empty spaces with Access Point related data")
                break

        self.emit(QtCore.SIGNAL('update database label'))               # Update the Entries label on Main window


