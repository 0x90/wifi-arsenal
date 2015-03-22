# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'untitled.ui'
#
# Created: Thu Oct 14 08:16:19 2010
#      by: PyQt4 UI code generator 4.7.7
#
# WARNING! All changes made in this file will be lost!
import os
from main_window import font_size
from PyQt4 import QtCore, QtGui

font_setting = font_size()

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class settings(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(427, 133)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("%s/resources/wifi_5.png"%(os.getcwd()))), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Dialog.setWindowIcon(icon)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(-20, 90, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.buttonBox.setFont(font)
        self.channel_combobox = QtGui.QComboBox(Dialog)
        self.channel_combobox.setGeometry(QtCore.QRect(170, 20, 121, 21))
        self.channel_combobox.setObjectName(_fromUtf8("channel_combobox"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.channel_combobox.setFont(font)
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(110, 20, 61, 16))
        self.label.setObjectName(_fromUtf8("label"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.label.setFont(font)
        self.label_2 = QtGui.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(10, -10, 91, 111))
        self.label_2.setText(_fromUtf8(""))
        self.label_2.setPixmap(QtGui.QPixmap(_fromUtf8("%s/resources/radio-wireless-signal-icone-5919-96.png"%(os.getcwd()))))
        self.label_2.setObjectName(_fromUtf8("label_2"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.label_2.setFont(font)
        self.xterm_checkbox = QtGui.QCheckBox(Dialog)
        self.xterm_checkbox.setGeometry(QtCore.QRect(300, 20, 171, 17))
        self.xterm_checkbox.setObjectName(_fromUtf8("xterm_checkbox"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.xterm_checkbox.setFont(font)
        self.label_3 = QtGui.QLabel(Dialog)
        self.label_3.setGeometry(QtCore.QRect(110, 50, 311, 16))
        font = QtGui.QFont()
        font.setWeight(50)
        font.setBold(False)
        self.label_3.setFont(font)
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.label_3.setFont(font)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.label_4 = QtGui.QLabel(Dialog)
        self.label_4.setGeometry(QtCore.QRect(10, 90, 101, 16))
        self.label_4.setObjectName(_fromUtf8("label_4"))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.label_4.setFont(font)
        self.label_5 = QtGui.QLabel(Dialog)
        self.label_5.setGeometry(QtCore.QRect(100, 90, 46, 13))
	font = QtGui.QFont()
	font.setPointSize(font_setting)
	self.label_5.setFont(font)
        font = QtGui.QFont()
        font.setWeight(75)
        font.setBold(False)
        self.label_5.setFont(font)
        self.label_5.setObjectName(_fromUtf8("label_5"))

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)


    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Access Point Scan Preferences", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("Dialog", "Channel:", None, QtGui.QApplication.UnicodeUTF8))
        self.xterm_checkbox.setText(QtGui.QApplication.translate("Dialog", "Enable XTerms", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("Dialog", "Automatic scan to all channels is Default without XTerm", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("Dialog", "\t <font color=green>Activated</font>", None, QtGui.QApplication.UnicodeUTF8))
        self.label_5.setText(QtGui.QApplication.translate("Dialog", "", None, QtGui.QApplication.UnicodeUTF8))

