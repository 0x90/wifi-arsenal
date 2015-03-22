'''
Created on 04.09.2010

@author: basti
'''

import os
import logging
import re

import airxploit.fuckup

class PluginController(object):
    '''
    read plugin dirs
    load plugins on demand
    '''
    
    def __init__(self, pcc):
        self.pcc = pcc
        self.scanner = {}
        self._plugins = {}
        self._plugins["exploit"] = {}
        self._plugins["scanner"] = {}
        self._plugins["discovery"] = {}

    
    def import_plugins(self, category):
        '''
        read a plugin dir
        import all plugins
        return hash of plugins with plugin name => plugin with package 
        '''        
        plugins = {}

        if os.path.exists("src/airxploit"):
            plugin_base_dir = "src/airxploit"
        else:
            plugin_base_dir = "airxploit"
            
        for plugin_file in os.listdir(plugin_base_dir + "/" + category):
            if re.search(r"__init__", plugin_file) == None and re.search(r"py$", plugin_file):
                plugin_name = re.sub(r".py$", "", plugin_file)
                plugin = "airxploit." + category + "." + plugin_name
                logging.debug(str(self.__class__) + " importing plugin " + plugin)
                eval("__import__('" + plugin + "')")
                plugins[plugin_name] = plugin
        return plugins

    def init_plugins(self):
        '''
        read all plugins
        generate closures for loading plugins
        plugins will not be loaded immediately cause they register themself for events in __init__
        '''        
        for category in ("scanner", "discovery", "exploit"):
            for name in self.import_plugins(category):
                self._plugins[category][name] = lambda s, category, name: self.init_plugin(category, name)

    def init_plugin(self, category, name):
        '''
        init the given plugin
        '''
        logging.debug(str(self.__class__) + " Load plugin " + "airxploit." + category + "." + name + "." + name.capitalize() + category.capitalize()) 
        return eval("airxploit." + category + "." + name + "." + name.capitalize() + category.capitalize() + "(self.pcc)")

    def show_plugins(self, category):
        '''
        show all plugins of a category
        '''
        if category in self._plugins:
            return self._plugins[category]
    
    def load_plugin(self, category, plugin):
        '''
        init one or all plugins of a given category
        '''    
        if category in self._plugins:
            if plugin == "all" or plugin == "":
                for p in self._plugins[category]:
                    if category == "scanner":
                        self.scanner[p] = self._plugins[category][p](self, category, p)
                    else:
                        self._plugins[category][p](self, category, p)
            elif plugin in self._plugins[category]:
                if category == "scanner":
                    self.scanner[plugin] = self._plugins[category][plugin](self, category, plugin)
                else:
                    self._plugins[category][plugin](self, category, plugin)
            else:
                raise airxploit.fuckup.not_a_command.NotACommand()
