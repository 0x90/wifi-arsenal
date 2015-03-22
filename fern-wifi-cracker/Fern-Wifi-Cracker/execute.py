#!/usr/bin/env python

import os
import sys
import time
import shutil
import commands
from PyQt4 import QtGui,QtCore


def initialize():
    'Set Working directory'
    if 'core' in os.listdir(os.getcwd()):
        create_directory()
    else:
        variable = sys.argv[0]
        direc = os.path.dirname(variable)
        if direc:
            os.chdir(direc)
        create_directory()


def restore_files():
    '''Fern 1.2 update algorithm fails to update the new version files
        therefore this piece of code corrects that defect when running
        the program after an update from 1.2'''

    update_directory = '/tmp/Fern-Wifi-Cracker/'

    for old_file in os.listdir(os.getcwd()):
        if os.path.isfile(os.getcwd() + os.sep + old_file) and old_file != '.font_settings.dat':
            os.remove(os.getcwd() + os.sep + old_file)
                                                                    # Delete all old directories except the "key-database" directory
    for old_directory in os.listdir(os.getcwd()):
        if os.path.isdir(os.getcwd() + os.sep + old_directory) and old_directory != 'key-database':
            shutil.rmtree(os.getcwd() + os.sep + old_directory)

    for update_file in os.listdir('/tmp/Fern-Wifi-Cracker'):        # Copy New update files to working directory
        if os.path.isfile(update_directory + update_file):
            shutil.copyfile(update_directory + update_file,os.getcwd() + os.sep + update_file)
        else:
            shutil.copytree(update_directory + update_file,os.getcwd() + os.sep + update_file)

    for new_file in os.listdir(os.getcwd()):
        os.chmod(os.getcwd() + os.sep + new_file,0777)




def create_directory():
    'Create directories and database'

    if not os.path.exists('fern-settings'):
        os.mkdir('fern-settings')                               # Create permanent settings directory
    if not os.path.exists('key-database'):                      # Create Database directory if it does not exist
        os.mkdir('key-database')


def cleanup():
    'Kill all running processes'
    commands.getstatusoutput('killall airodump-ng')
    commands.getstatusoutput('killall aircrack-ng')
    commands.getstatusoutput('killall airmon-ng')
    commands.getstatusoutput('killall aireplay-ng')



initialize()

if 'core' not in os.listdir(os.getcwd()):
    restore_files()

from core import *
functions.database_create()
from gui import *


if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    run = fern.mainwindow()

    pixmap = QtGui.QPixmap("%s/resources/screen_splash.png" % (os.getcwd()))
    screen_splash = QtGui.QSplashScreen(pixmap,QtCore.Qt.WindowStaysOnTopHint)
    screen_splash.setMask(pixmap.mask())
    screen_splash.show()
    app.processEvents()

    time.sleep(3)

    screen_splash.finish(run)
    run.show()
    app.exec_()

    cleanup()
    sys.exit()

