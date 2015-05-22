#! /usr/bin/env python
import curses

import WifiSpy
import utils

from optparse import OptionParser
from scapy.all import Dot11
from operator import itemgetter

class infoWindow(object):
    def __init__(self, sub_win, lines, cols, essid, ap, mode, quality):
        self.stdscr = sub_win
        self.lines = lines
        self.cols = cols
        
        self.__clear_window(True)
        self.stdscr.box()
        
        self.stdscr.addstr(1, 2, "Essid:", curses.A_BOLD)
        self.stdscr.addstr(1, 9, essid)
        self.stdscr.addstr(2, 5, "AP:", curses.A_BOLD)
        self.stdscr.addstr(2, 9, ap)
        self.stdscr.addstr(3, 3, "Mode:", curses.A_BOLD)
        self.stdscr.addstr(3, 9, mode)
        self.stdscr.addstr(4, 2, "Quality:", curses.A_BOLD)
                
        max_equal_cols = self.cols - 13
        quality_length = quality * (max_equal_cols) / 100
        if quality_length > max_equal_cols:
            quality_length = max_equal_cols
        if quality_length == 0:
            quality_length = 1
        self.stdscr.hline(4, 11, '=', quality_length)
                
        self.stdscr.addstr(6, 2, "Clients:", curses.A_BOLD)
        self.current_line = 7
        self.current_col = 4
        
    def __clear_window(self, clear_all=False):
        if (clear_all):
            self.stdscr.erase()
        else:
            for i in xrange(7, self.lines-1):
                self.stdscr.hline(i, 1, " ", self.cols-2)
                
    def add_client(self, addr):
        self.stdscr.addstr(self.current_line, self.current_col, addr)
        self.current_line += 1
        if (self.current_line == self.lines - 1):
            self.current_line = 7
            self.current_col += 19
            if (self.current_col + 17 > self.cols):
                self.current_col = 4
    
    def clear_clients(self):
        self.__clear_window()
        self.current_line = 7
        
class messagesWindow(object):
    def __init__(self, sub_win, lines, cols):
        self.stdscr = sub_win
        self.lines = lines
        self.cols = cols
        
        self.messages = []
        self.current_line = 2
        
        self.__clear_window(True)
        self.stdscr.addstr(1, 2, "Messages:", curses.A_BOLD)
        self.stdscr.box()
        
    def __clear_window(self, all=False):
        if (all):
            self.stdscr.erase()
        else:
            for i in xrange(2, self.lines-1):
                self.stdscr.hline(i, 1, " ", self.cols-2)
                
    def __build_screen(self):
        current_line = 2
        for message in self.messages:
            self.stdscr.addstr(current_line, 4, message)
            current_line += 1
            
    def add_message(self, action):
        message = action[0] + ": " + action[1]
        self.messages.append(message)
        
        if (self.current_line+1 == self.lines):
            self.messages.pop(0)
            self.__clear_window()
            self.__build_screen()
        else:
            self.stdscr.addstr(self.current_line, 4, message)
            self.current_line += 1
        

class WSpyCurses(object):
    def __init__(self, win, interface, level):
        self.line_pos = 2
        self.first_result = self.selected_result = 0 
        self.stdscr = win
        self.results = []
        self.wifispy = WifiSpy.WifiSpy(interface)
                
        # Configure screen
        curses.curs_set(0)
        self.stdscr.nodelay(1)
        self.stdscr.timeout(0)
        
        # Put the interface it in managed mode
        # to perform the scanning
        self.wifispy.level = level
        self.wifispy.set_iface_in_managed_mode()      
        
        # Show scanning message
        self.stdscr.box()
        self.stdscr.addstr(curses.LINES/2, curses.COLS/2 - 5, "Scanning...",
                                curses.A_BOLD)
        self.stdscr.refresh()
        
        # Get and populate results
        self.results = self.wifispy.get_scanning_results()
        
        # Rebuild the screen with the results
        self.__clear_screen()
        self.__build_screen(self.first_result, True)                
        self.__highlight_line(self.line_pos, self.selected_result)
        
    def __update_screen_sorting_by(self, sort_key):
        self.results = sorted(self.results, key=itemgetter(sort_key))
        self.__build_screen(self.first_result)
        self.__highlight_line(self.line_pos, self.selected_result)
        
    def __update_results(self):
        self.results = self.wifispy.get_scanning_results()
        
    def __highlight_line(self, line, result):
        self.stdscr.hline(line, 1, " ", curses.COLS - 2)
        self.__build_line(line, result, True)
               
    def __move_line(self, pos):
        """
        This function moves the selected line one position up or down and
        updates the screen if pos == 1 moves the line up if pos == -1 moves 
        the line down.
        """

        # Update temporal vars
        temp_line = self.line_pos + pos
        temp_res = self.selected_result + pos
        
        # Check that we are not out of bounds
        if temp_line > curses.LINES - 2: temp_line = curses.LINES - 2
        #if temp_line == len(self.results): temp_line -= pos
        if temp_line < 2: temp_line = 2
         
        if temp_res < 0: temp_res = 0
        if temp_res == len(self.results): temp_res = len(self.results) - 1
        
        # Check if we are in the limits
        if (self.selected_result ==  len(self.results) - 1 and pos == 1)\
            or (self.selected_result == 0 and pos == -1):
                return
        
        # Check if we have to repaint the results
        if self.line_pos ==  curses.LINES - 2 and pos == 1:
            self.first_result += 1
            self.__build_screen(self.first_result)
            
        if self.line_pos == 2 and pos == -1 and len(self.results) >\
         (curses.LINES - 3):
            self.first_result -= 1
            self.__build_screen(self.first_result)
        
        # Update the line
        self.stdscr.hline(self.line_pos, 1, " ", curses.COLS - 2)
        self.__build_line(self.line_pos, self.selected_result)
        self.__highlight_line(temp_line, temp_res)
        
        # Upfate vars
        self.line_pos = temp_line
        self.selected_result = temp_res
            
        self.stdscr.refresh()

    def __rebuild_screen(self):
        self.__clear_screen()
        self.__build_screen(self.first_result)
        self.__highlight_line(self.line_pos, self.selected_result)
        self.stdscr.refresh()
        
    def __clear_screen(self, all = False):
        if (all):
            self.stdscr.erase()
        else:
            for i in xrange(3, curses.LINES-1):
                self.stdscr.hline(i, 1, " ", curses.COLS-2)
            
    def __build_screen(self, first_result, build_header=False):
        """
        This function is used to populate the screen starting with the 
        specified result, it also can build the header line if is needed
        """
        temp_line = 2
        temp_result = first_result
        if (build_header):
            self.stdscr.box()
            # Build header line
            pos_col = 5        
            self.stdscr.addstr(1, pos_col, "Essid", curses.A_BOLD)
            pos_col += curses.COLS / 6 
            self.stdscr.addstr(1, pos_col, "AP", curses.A_BOLD)
            pos_col += curses.COLS / 5
            self.stdscr.addstr(1, pos_col, "Channel", curses.A_BOLD) 
            pos_col += curses.COLS / 8
            self.stdscr.addstr(1, pos_col, "Rate", curses.A_BOLD)
            pos_col += curses.COLS / 8
            self.stdscr.addstr(1, pos_col, "Mode", curses.A_BOLD)
            pos_col += curses.COLS / 8
            self.stdscr.addstr(1, pos_col, "Quality", curses.A_BOLD)
            pos_col += curses.COLS / 8
            self.stdscr.addstr(1, pos_col, "Encr", curses.A_BOLD)
            
        for i in self.results:
            if temp_line < curses.LINES - 1:
                self.stdscr.hline(temp_line, 1, " ", curses.COLS - 2)
                self.__build_line(temp_line, temp_result)
                temp_line += 1
                temp_result += 1
                
    def __build_line(self, line, res, use_bold=False):
        """
        This function prints a line on the screen parsing the scanned results
        """
        pos_col = 5
        
        if len(self.results[res]["Essid"]) > 5:
            pos_col = 4
        
        if use_bold:
            self.stdscr.addstr(line, pos_col, self.results[res]["Essid"],
                                curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, self.results[res]["Essid"])
            
        pos_col = 5 + curses.COLS / 10
        if use_bold:
            self.stdscr.addstr(line, pos_col, self.results[res]["Ap"], 
                               curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, self.results[res]["Ap"])
        
        pos_col += curses.COLS / 3  - (curses.COLS / 25)
        if use_bold:
            self.stdscr.addstr(line, pos_col, 
                               self.results[res]["Channel"].__str__(),
                               curses.A_BOLD)
        else:
            self.stdscr.addstr(line, 
                               pos_col, self.results[res]["Channel"].__str__())
            
        pos_col += curses.COLS / 9
        rate =  (self.results[res]["Bitrate"] / 1000000).__str__() + " Mb"
        if use_bold:
            self.stdscr.addstr(line, pos_col, rate, curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, rate)
            
        pos_col += curses.COLS / 8
        if use_bold:
            self.stdscr.addstr(line, pos_col, self.results[res]["Mode"],
                               curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, self.results[res]["Mode"])
            
        pos_col += curses.COLS / 7
        if use_bold:
            self.stdscr.addstr(line, pos_col,
                               self.results[res]["Quality"].__str__(),
                               curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, 
                               self.results[res]["Quality"].__str__())
            
        pos_col += curses.COLS / 8
        if self.results[res]["Encryption"]:
            if self.results[res]["Wpa"]:
                enc = "Wpa"
            else:
                enc = "Wep"
        else:
            enc = "No"
        
        if use_bold:
            self.stdscr.addstr(line, pos_col, enc, curses.A_BOLD)
        else:
            self.stdscr.addstr(line, pos_col, enc)
            
    def run(self):
        while True:
            curses.napms(100)
            
            ch = self.stdscr.getch()

            if ch == ord('q'):
                self.stdscr.erase()
                return 0
            
            elif ch == curses.KEY_UP:
                self.__move_line(-1)
                                
            elif ch == curses.KEY_DOWN:
                self.__move_line(1)
                
            elif ch == ord('i'):
                height = (curses.LINES/6) * 3;  width = (curses.COLS/6) * 4;
                temp_win = self.stdscr.subwin(height, width, curses.LINES/6 - 1, \
                                              curses.COLS/6)
                essid = self.results[self.selected_result]['Essid']
                ap = self.results[self.selected_result]['Ap']
                mode = self.results[self.selected_result]['Mode']
                quality = self.results[self.selected_result]['Quality']
                channel = self.results[self.selected_result]['Channel']
                
                info_window = infoWindow(temp_win, height, width, essid, ap, \
                                         mode, quality)
                
                height = (curses.LINES/6)*2; width = (curses.COLS/6) * 4
                temp_win = self.stdscr.subwin(height, width, (curses.LINES/6)*4 - 1, \
                                              curses.COLS/6)
                
                messages_window = messagesWindow(temp_win, height, width)
                
                self.stdscr.overwrite(info_window.stdscr)
                self.stdscr.overwrite(messages_window.stdscr)
                info_window.stdscr.refresh()
                messages_window.stdscr.refresh()

                # Put the interface in monitor mode and retrieve packtes
                self.wifispy.channel = channel
                self.wifispy.ap = ap                
                self.wifispy.set_iface_in_monitor_mode()
                
                while True:
                    self.wifispy.update()
                    clients = self.wifispy.get_clients_from_network()
                    actions = self.wifispy.get_actions_from_network()
                    
                    if len(clients):
                        info_window.clear_clients()
                        for client in clients:
                            info_window.add_client(client)
                        info_window.stdscr.refresh()
                            
                    if len(actions):
                        for action in actions:
                            messages_window.add_message(action)
                        messages_window.stdscr.refresh()
                    
                    if self.stdscr.getch() != -1:
                        break

                self.wifispy.set_iface_in_managed_mode()
                self.__rebuild_screen()

            elif ch == ord('r') or ch == ord('R'):
                # Show scanning message
                temp_win = self.stdscr.subwin(1, 13, curses.LINES/2, curses.COLS/2 - 5)
                temp_win.addstr(0, 0, "Scanning...", curses.A_BOLD)
                temp_win.refresh()
                
                # Update results and screen
                self.__update_results()
                self.__rebuild_screen()
                
            # Sort values
            elif ch == ord('e') or ch == ord('E'):
                if (ch == ord('e')):
                    self.__update_screen_sorting_by('Essid')
                else:
                    self.__update_screen_sorting_by('Essid')
            elif ch == ord('a') or ch == ord('A'):
                self.__update_screen_sorting_by('Ap')
            elif ch == ord('c') or ch == ord('C'):
                self.__update_screen_sorting_by('Channel')
            elif ch == ord('l') or ch == ord('L'):
                self.__update_screen_sorting_by('Quality')
            elif ch == ord('d') or ch == ord('D'):
                self.__update_screen_sorting_by('Bitrate')
            elif ch == ord('m') or ch == ord('M'):
                self.__update_screen_sorting_by('Mode')
            elif ch == ord('t') or ch == ord('T'):
                self.__update_screen_sorting_by('Encryption')
            elif ch == ord('f') or ch == ord('F'):
                self.results.reverse()
                self.__build_screen(self.first_result)
                self.__highlight_line(self.line_pos, self.selected_result)
                
            # Help window
            elif ch == ord('h') or ch == ord('H'):
                height = 13;  width = 26;
                temp_win = self.stdscr.subwin(height, width, curses.LINES/2-(height/2), curses.COLS/2-(width/2))
                temp_win.box()
                
                # Clean the help window
                for i in xrange(1, height - 1):
                    temp_win.hline(i, 1, " ", width - 2)
                
                # Fill the help window
                line = 1; first_col = 2; second_col = 6;
                temp_win.addstr(line, first_col, "h -", curses.A_BOLD)
                temp_win.addstr(line, second_col, "Show help")
                temp_win.addstr(line+1, first_col, "i -", curses.A_BOLD)
                temp_win.addstr(line+1, second_col, "Show info windows")
                temp_win.addstr(line+2, first_col, "r -", curses.A_BOLD)
                temp_win.addstr(line+2, second_col, "Rescan")
                temp_win.addstr(line+3, first_col, "f -", curses.A_BOLD)
                temp_win.addstr(line+3, second_col, "Reverse results")
                temp_win.addstr(line+4, first_col, "a -", curses.A_BOLD)
                temp_win.addstr(line+4, second_col, "Sort by AP")
                temp_win.addstr(line+5, first_col, "e -", curses.A_BOLD)
                temp_win.addstr(line+5, second_col, "Sort by Essid")
                temp_win.addstr(line+6, first_col, "d -", curses.A_BOLD)
                temp_win.addstr(line+6, second_col, "Sort by Rate")
                temp_win.addstr(line+7, first_col, "m -", curses.A_BOLD)
                temp_win.addstr(line+7, second_col, "Sort by Mode")
                temp_win.addstr(line+8, first_col, "l -", curses.A_BOLD)
                temp_win.addstr(line+8, second_col, "Sort by Quality")
                temp_win.addstr(line+9, first_col, "c -", curses.A_BOLD)
                temp_win.addstr(line+9, second_col, "Sort by Channel")
                temp_win.addstr(line+10, first_col, "t -", curses.A_BOLD)
                temp_win.addstr(line+10, second_col, "Sort by Encryption")
                
                # Update the main window and wait for the user
                self.stdscr.overwrite(temp_win)
                temp_win.getkey()                
                self.__rebuild_screen()
                

def main(win):
    if (curses.COLS < 80):
        print("At least 80 columns are needed to work properly")
        return 0
    if (curses.LINES < 24):
        print("At least 24 lines are needed to work properly")
        return 0
    
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface",
                  help="Specify the network interface")
    parser.add_option("-l", "--level", dest="level", default="medium",
                  help="Specify the level (low, medium, high")
    
    (options, args) = parser.parse_args()
    if options.interface == None:
        wifaces = utils.get_wireless_ifaces()
        if len(wifaces):
            options.interface = wifaces[0]
        else:
            print("Not able to autodetect the wireless interface please specify one")
            return 0
        
    w = WSpyCurses(win, options.interface, options.level)
    w.run()

curses.wrapper(main)