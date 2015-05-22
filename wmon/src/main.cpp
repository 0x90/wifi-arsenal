/*
 *  Wireless Network Monitor
 *
 *  Copyright 2011 David Garcia Villalba, Daniel López Rovira, Marc Portoles Comeras and Albert Cabellos Aparicio
 *
 *  This file is part of wmon.
 *
 *  wmon is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  wmon is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with wmon.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef QTGUI
#include <QApplication>
#include "QtGUI.h"
#else
#include "ConsoleGUI.h"
#endif

#include "NetManager.h"
#include "FileGUI.h"
#include "GUIEventDispatcher.h"
#include <iostream>
#include <vector>
#include <list>
#include <algorithm>
#include <stdlib.h>
#include <getopt.h>
using namespace std;

void error(string msg) {
    cerr << "Error: " << msg << endl;
    exit(1);
}

bool isANumber(char* str) {
    for (unsigned int i = 0; str[i] != '\0'; ++i) {
        if (str[i] < '0' or str[i] > '9') return false;
    }
    return true;
}

// Pre: str is a number 
int getNumber(char* str) {
    int res = 0;
    for (unsigned int i = 0; str[i] != '\0'; ++i) {
        res = res*10 + str[i] - '0';
    }
    return res;
}

int main(int argc, char* argv[]) {
    static struct option longOptions[] = {
        {"interface", required_argument, NULL, 'i'}, // Interface to use
        {"channel",   required_argument, NULL, 'c'}, // Channels to scan
        {"ctime",     required_argument, NULL, 't'}, // Channel time
        {"ectime",    required_argument, NULL, 'e'}, // Empty channel time
        // Add: TIMETODISCARD ¿Analayzer sleep time?
        {"file",      required_argument, NULL, 'f'}, // File to write the output
        {"help",      no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };
    
    list<unsigned short> channels;
    string interface, filePath;
    unsigned int channelTime = NetManager::DEFAULTCHANNELTIME;
    unsigned int emptyChannelTime = NetManager::DEFAULTEMPTYCHANNELTIME;
    
    char op;
    while ((op = getopt_long(argc, argv, "i:c:t:e:f:h",
                             longOptions, NULL)) != -1) {
        switch (op) {
            case 'i':
                if (not interface.empty()) error("--interface or -i only can be used once");
                interface = string(optarg);
                break;
                
            case 'c':
                if (not isANumber(optarg)) error("--channel or -c needs a natural number");
                { unsigned short channel = getNumber(optarg);
                if (channel == 0) error("--channel or -c must be greater than 0");
                if (find(channels.begin(), channels.end(), channel) == channels.end()) channels.push_back(channel); }
                break;
                
            case 't':
                if (not isANumber(optarg)) error("--ctime or -t needs a natural number");
                channelTime = getNumber(optarg);
                break;
                
            case 'e':
                if (not isANumber(optarg)) error("--ectime or -e needs a natural number");
                emptyChannelTime = getNumber(optarg);
                break;
                
            case 'f':
                filePath = string(optarg);
                break;
            
            case 'h':
                cout << "Ussage: " << argv[0] << " [option]*" << endl << endl;
                cout << "Options:" << endl;
                cout << "    -h, --help: Prints this help" << endl;
                cout << "    -i interface, --interface interface: Sets the interface to use (example: -i wlan0)" << endl;
                cout << "        By default tries to open one interface" << endl;
                cout << "    -c channel, --channel channel: Configures the channels to scan (example: -c 1 -c 9)." << endl;
                cout << "        By default is all the channels between 1 and 13" << endl;
                cout << "    -t seconds, --ctime seconds: Time that the program will be in every channel" << endl;
                cout << "        By default 8 seconds, 5 is the minimum value" << endl;
                cout << "    -e seconds, --ectime seconds: Time that the program will be in every channel withouth capture any packet" << endl;
                cout << "        By default 1 seconds. Needs to be less or equal than --ctime and greater or equal than 0" << endl;
                cout << "    -f path, --file path: Generates a output in the indicated file" << endl;
                exit(0);
            
            default:
                error("Unrecognized argument.");
        }
    }
    
    if (emptyChannelTime == 0) error("Empty channel time (--ectime, -e) must be greater than 0");
    if (channelTime < 5) error("Channel time (--ctime, -t) must be greater or equal than 5");
    if (emptyChannelTime > channelTime) error("Empty channel time (--ectime, -e) must be less or equal than channel time (--ctime, -t)");

    vector<string> ifaces = NetManager::list80211Interfaces();
    if (interface.empty() and not ifaces.empty()) interface = ifaces[0];
    if (interface.empty()) error("Can't select an interface.");

    FileGUI* fileGUI = NULL;
    if (not filePath.empty()) {
        fileGUI = new FileGUI(filePath.c_str());
        if (not fileGUI->fileOK()) error("FileGUI error");
    }
    
    NetManager nm(interface);
    if (not nm.isMonitorInterfaceCreated()) error("Can't create monitor interface. The program needs root privileges.");
    
    if (not channels.empty()) nm.setChannels(channels);
    nm.setChannelTime(channelTime);
    nm.setEmptyChannelTime(emptyChannelTime);
    
    if (fileGUI != NULL) GUIEventDispatcher::registerGUI(fileGUI);
    
    #ifdef QTGUI
    QApplication app(argc, argv);
    QtGUI gui(ifaces);
    gui.setNetManager(&nm);
    #else
    ConsoleGUI gui;
    #endif
    
    GUIEventDispatcher::registerGUI(&gui);
    GUIEventDispatcher::run();
    
    nm.startMonitoring();
    
    #ifdef QTGUI
    gui.show();
    app.exec();
    #else
    gui.loop();
    #endif
    
    GUIEventDispatcher::stop();
    nm.stopMonitoring();
    nm.removeMonitorInterface();
    
    if (fileGUI != NULL) delete fileGUI;
}

