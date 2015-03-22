from ConfigParser import ConfigParser, NoOptionError
from rpyutils import printd, Level


class ConfigHeader(object):
    def __init__(self, fp):
        self.fp = fp
        self.first_line = True
        self.dummy_section = '[fakeap]\n'

    def readline(self):
        if self.first_line:
            self.first_line = False
            return self.dummy_section
        else:
            return self.fp.readline()


class Conf(ConfigParser):
    def __init__(self, path):
        ConfigParser.__init__(self)  # ConfigParser is an old-style class... Can't user 'super'
        self.path = path
        self.readfp(ConfigHeader(open(path)))

    def get(self, key, default=None):
        value = None
        try:
            value = ConfigParser.get(self, 'fakeap', key)
        except NoOptionError as e:
            value = default
            printd("Option '%s' not specified in config file. Using default." % e.option, Level.WARNING)

        printd("%s -> %s" % (key, value), Level.INFO)

        return value
