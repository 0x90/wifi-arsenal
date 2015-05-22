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

#include "ConsoleGUI.h"
#include "Utils.h"
#include <ncurses.h>
#include <sstream>
#include <iomanip>

#define KEY_ESC (27)
#define insertSortCode(code) ({pthread_mutex_lock(&dataMutex);\
                               code;\
                               pthread_mutex_lock(&guiMutex);\
                               printSortKeys();\
                               wrefresh(main);\
                               stats.sort(generalSort);\
                               drawList();\
                               pthread_mutex_unlock(&guiMutex);\
                               pthread_mutex_unlock(&dataMutex);})

bool ConsoleGUI::disappearedAtBottom;
bool (* ConsoleGUI::sortMethod)(const NetStats& i, const NetStats& j);

ConsoleGUI::ConsoleGUI() {
    channel = 0;
    currentIndex = 0;
    disappearedAtBottom = true;
    sortMethod = sortByChannel;
    pthread_mutex_init(&guiMutex, NULL);
    pthread_mutex_init(&dataMutex, NULL);
    initScreen();
}

ConsoleGUI::~ConsoleGUI() {
    if (not isendwin()) endwin();
    pthread_mutex_destroy(&guiMutex);
    pthread_mutex_destroy(&dataMutex);
}

void ConsoleGUI::loop() {
    int ch;
    while ((ch = getch()) != KEY_ESC) {
        switch (ch & ~0x20) {
            case KEY_RESIZE:
                doResize();
                break;
            
            case KEY_UP: // Scroll up
                scrollWindow(-1);
                break;
                
            case KEY_DOWN: // Scroll down
                scrollWindow(1);
                break;
                
            case SORTKEYLOSSBOTTOM: // 100% loss at the bottom
                insertSortCode(disappearedAtBottom = not disappearedAtBottom);
                break;
                
            case SORTKEYBSSID: // Sort by BSSID
                insertSortCode(sortMethod = sortByBSSID);
                break;
                
            case SORTKEYCHANNEL: // Sort by Channel
                insertSortCode(sortMethod = sortByChannel);
                break;
                
            case SORTKEYUTILIZATION: // Sort by Utilization
                insertSortCode(sortMethod = sortByUtilization);
                break;
                
            case SORTKEYLOSS: // Sort by Loss
                insertSortCode(sortMethod = sortByLoss);
                break;
                
            case SORTKEYRSSI: // Sort by RSSI
                insertSortCode(sortMethod = sortByRSSI);
                break;
                
            case SORTKEYSSID: // Sort by SSID
                insertSortCode(sortMethod = sortBySSID);
                break;
        }
    }
}

void ConsoleGUI::updateChannel(unsigned short channel, const std::list<NetStats>& stats) {
    pthread_mutex_lock(&dataMutex);
    for (std::list<NetStats>::const_iterator net = stats.begin(); net != stats.end(); ++net) {
        bool tr = false;
        std::list<NetStats>::iterator storedNet;
        for (storedNet = this->stats.begin(); not tr and storedNet != this->stats.end();) {
            tr = Utils::sameNetwork(*storedNet, *net);
            if (not tr) ++storedNet;
        }
        
        if (tr) *storedNet = *net;
        else this->stats.push_back(*net);
    }
    
    this->stats.sort(generalSort);
    
    pthread_mutex_lock(&guiMutex);
    drawList();
    pthread_mutex_unlock(&guiMutex);
    pthread_mutex_unlock(&dataMutex);
}

void ConsoleGUI::updateScanChannel(unsigned short channel) {
    pthread_mutex_lock(&guiMutex);
    this->channel = channel;
    printChannel();
    pthread_mutex_unlock(&guiMutex);
}

void ConsoleGUI::updateRemainingChannelTime(int seconds) {
    pthread_mutex_lock(&guiMutex);
    std::stringstream ss;
    if (seconds >= 0) ss << std::setfill(' ') << std::setw(3) << seconds;
    else ss << "---";
    
    mvwprintw(main, 0, 51, ss.str().c_str());
    wrefresh(main);
    pthread_mutex_unlock(&guiMutex);
}

void ConsoleGUI::addNetwork(const NetStats& net, int line, bool lineSeparator) {
    std::stringstream ss;
    ss.setf(std::ios::fixed);
    ss.precision(2);
    Utils::writeBytes(ss, net.bssid, 6);
    
    ss << std::setfill(' ');
    ss << " " << std::setw(3) << net.channel;
    if (net.loss < 1) {
        ss << " " << std::setw(6) << net.weightedDelay*100 << "%%";
        ss << " " << std::setw(6) << net.loss*100 << "%%";
        ss << " " << std::setw(4) << net.rssi << " dBm";
    }
    else ss << "   ---     ---      ---  ";
    ss << " " << (net.ok ? "Y":"N");
    ss << " " << net.protection;
    for (unsigned int i = net.protection.size(); i < 4; ++i) ss << " ";
    ss << " " << net.ssid;
    
    mvwprintw(listNetworks, line, 0, ss.str().substr(0, ncols - 2).c_str());
    if (lineSeparator) mvwhline(listNetworks, line + 1, 0, 0, ncols - 2);
}

void ConsoleGUI::initScreen() {
    main = initscr();
    wattron(main, A_BOLD);
    
    keypad(stdscr, TRUE); // Enable special keys (arrows and ESC)
    noecho();
    curs_set(0); // No blinking cursor
    
    getmaxyx(main, nrows, ncols);

    listNetworks = newwin(nrows - 3, ncols - 2, 2, 1);
    
    drawMainWindow();
}

void ConsoleGUI::doResize() {
    pthread_mutex_lock(&guiMutex);
    getmaxyx(main, nrows, ncols);
    wresize(listNetworks, nrows - 3, ncols - 2);
    drawMainWindow();
    drawList();
    pthread_mutex_unlock(&guiMutex);
}

void ConsoleGUI::drawMainWindow() {
    wclear(main);
    box(main, 0, 0);
    mvwprintw(main, 1, 1, "BSSID              Ch Utiliz.    Loss     RSSI V Sec. SSID");
    mvwprintw(main, 0, 1, "[Current channel:     | Time left in the channel:    ]");
    mvwprintw(main, nrows - 1, 1, "[Keys: Up | Down |             (Sort by) |   (--- at bottom) | ESC]");
    
    printChannel();
    printSortKeys();
    wrefresh(main);
}

void ConsoleGUI::printChannel() {
    std::stringstream ss;
    if (channel > 0) ss << std::setfill(' ') << std::setw(3) << channel;
    else ss << "---";
    
    mvwprintw(main, 0, 19, ss.str().c_str());
    wrefresh(main);
}

void ConsoleGUI::printChar(WINDOW* window, int y, int x, char ch, bool reverse) {
    if (reverse) wattron(window, A_REVERSE);
    mvwaddch(window, y, x, ch);
    if (reverse) wattroff(window, A_REVERSE);
}

void ConsoleGUI::printSortKeys() {
    printChar(main, nrows - 1, FIRSTSORTLETTER,      SORTKEYBSSID,       sortMethod == sortByBSSID);
    printChar(main, nrows - 1, FIRSTSORTLETTER + 2,  SORTKEYCHANNEL,     sortMethod == sortByChannel);
    printChar(main, nrows - 1, FIRSTSORTLETTER + 4,  SORTKEYUTILIZATION, sortMethod == sortByUtilization);
    printChar(main, nrows - 1, FIRSTSORTLETTER + 6,  SORTKEYLOSS,        sortMethod == sortByLoss);
    printChar(main, nrows - 1, FIRSTSORTLETTER + 8,  SORTKEYRSSI,        sortMethod == sortByRSSI);
    printChar(main, nrows - 1, FIRSTSORTLETTER + 10, SORTKEYSSID,        sortMethod == sortBySSID);
    
    printChar(main, nrows - 1, FIRSTSORTLETTER + 24, SORTKEYLOSSBOTTOM, disappearedAtBottom);
}

void ConsoleGUI::drawList() {
    if (isendwin()) return;
    
    int maxY = nrows - 3;
    unsigned int numElem = maxY/2;
    
    unsigned int startIndex = currentIndex;
    unsigned int endIndex = startIndex + numElem;
    if (endIndex > stats.size()) {
        if (stats.size() > numElem) currentIndex = startIndex = stats.size() - numElem;
        else startIndex = 0;
        
        endIndex = stats.size();
    }
    
    wclear(listNetworks);
    
    std::list<NetStats>::const_iterator netStats = stats.begin();
    advance(netStats, startIndex);
    for (int line = 0; startIndex < endIndex; line += 2, ++startIndex, ++netStats) {
        addNetwork(*netStats, line, startIndex != endIndex - 1);
    }
    wrefresh(listNetworks);
}

void ConsoleGUI::scrollWindow(int offset) {
    pthread_mutex_lock(&dataMutex);
    pthread_mutex_lock(&guiMutex);
    currentIndex += offset;
    if (currentIndex < 0) currentIndex = 0;
    else if (currentIndex >= stats.size()) currentIndex = stats.size() - 1;
    
    drawList();
    pthread_mutex_unlock(&guiMutex);
    pthread_mutex_unlock(&dataMutex);
}

bool ConsoleGUI::generalSort(const NetStats& i, const NetStats& j) {
    if (disappearedAtBottom) {
        if (i.loss == 1 and j.loss < 1) return false;
        if (j.loss == 1 and i.loss < 1) return true;
    }
    
    return sortMethod(i, j);
}

bool ConsoleGUI::sortByBSSID(const NetStats& i, const NetStats& j) {
    for (int aux = 0; aux < sizeof(i.bssid); ++aux) {
        if (i.bssid[aux] < j.bssid[aux]) return true;
        if (i.bssid[aux] > j.bssid[aux]) return false;
    }
    
    return sortByChannel(i, j);
}

bool ConsoleGUI::sortByChannel(const NetStats& i, const NetStats& j) {
    if (i.channel < j.channel) return true;
    if (i.channel > j.channel) return false;
    
    // i.channel == j.channel
    for (int aux = 0; aux < sizeof(i.bssid); ++aux) {
        if (i.bssid[aux] < j.bssid[aux]) return true;
        if (i.bssid[aux] > j.bssid[aux]) return false;
    }
    
    return i.ssid < j.ssid;
}

bool ConsoleGUI::sortByUtilization(const NetStats& i, const NetStats& j) {
    if (i.weightedDelay != j.weightedDelay) return i.weightedDelay < j.weightedDelay;
    
    return sortByChannel(i, j);
}

bool ConsoleGUI::sortByLoss(const NetStats& i, const NetStats& j) {
    if (i.loss != j.loss) return i.loss < j.loss;
    
    return sortByChannel(i, j);
}

bool ConsoleGUI::sortByRSSI(const NetStats& i, const NetStats& j) {
    if (i.loss == 1 and j.loss < 1) return false;
    if (j.loss == 1 and i.loss < 1) return true;
    
    if (i.rssi != j.rssi) return i.rssi > j.rssi;
    
    return sortByChannel(i, j);
}

bool ConsoleGUI::sortBySSID(const NetStats& i, const NetStats& j) {
    if (i.ssid != j.ssid) return i.ssid < j.ssid;
    
    return sortByChannel(i, j);
}

