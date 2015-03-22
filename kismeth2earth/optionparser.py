# kismet2earth 1.0
# Author: Andrea Grandi <a.grandi AT gmail com>
# License: GPL2
# Copyright: Andrea Grandi 2010 - This code is partially based on PyKismetKml (http://code.google.com/p/pykismetkml)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import optparse

class OptionParser (optparse.OptionParser):
    def check_required (self, opt, stop):
        option = self.get_option(opt)
        if getattr(self.values, option.dest) is None:
            if stop:
                return False
            else:
                self.error("%s option not supplied" % option)
        else:
            return True
