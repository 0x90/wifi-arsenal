"""
  Copyright notice
  ================
  
  Copyright (C) 2011
      Roberto Paleari     <roberto.paleari@gmail.com>
      Alessandro Reina    <alessandro.reina@gmail.com>
  
  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.
  
  HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with
  this program. If not, see <http://www.gnu.org/licenses/>.
  
"""

import threading
import datetime, base64
from xml.sax.saxutils import escape as xmlescape

# Synchronization decorator
def synchronized(lock):
    def wrap(f):
        def new_function(*args, **kw):
            lock.acquire()
            try:
                return f(*args, **kw)
            finally:
                lock.release()
        return new_function
    return wrap

class HttpHistoryEntry:
    def __init__(self, idz, oreq = None, mreq = None, ores = None, mres = None):
        self.id   = idz         # Entry identified (mandatory)
        self.setOriginalRequest(oreq)
        self.setOriginalResponse(ores)
        self.setMangledRequest(mreq)
        self.setMangledResponse(mres)

    def setOriginalRequest(self, r):
        if r is None:
            t = None
        else:
            t = datetime.datetime.now()
        self.oreq_time = t
        self.oreq = r

    def setOriginalResponse(self, r):
        if r is None:
            t = None
        else:
            t = datetime.datetime.now()
        self.ores_time = t
        self.ores = r

    def setMangledRequest(self, r):
        if r is None:
            t = None
        else:
            t = datetime.datetime.now()
        self.mreq_time = t
        self.mreq = r

    def setMangledResponse(self, r):
        if r is None:
            t = None
        else:
            t = datetime.datetime.now()
        self.mres_time = t
        self.mres = r

class HttpHistory:
    # Synchronization lock
    lock  = threading.Lock()

    def __init__(self):
        self.__history = []

    @synchronized(lock)
    def allocate(self):
        idz = len(self.__history)
        h = HttpHistoryEntry(idz = idz)
        self.__history.append(h)
        return idz

    @synchronized(lock)
    def __getitem__(self, idz):
        return self.__history[idz]

    def count(self):
        """
        Count requests and responses. Return a tuple (#req, #res).
        """
        nreq, nres = 0, 0
        for entry in self.__history:
            if entry.oreq is not None:
                nreq += 1
            if entry.ores is not None:
                nres += 1
        return nreq, nres

    def dumpXML(self):
        t = datetime.datetime.now()

        # Document header
        s = """\
<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>
<Head>
  <Timestamp>%s</Timestamp>
</Head>
<Entries>
""" % t

        # Process single HTTP entries
        for entry in self.__history:
            s += "  <Entry>\n"
            s += "    <ID>%d</ID>\n" % entry.id

            for attr, name in [
                ("oreq", "OriginalRequest"),
                ("mreq", "MangledRequest"),
                ("ores", "OriginalResponse"),
                ("mres", "MangledResponse"),
                ]:

                v = getattr(entry, attr)
                t = getattr(entry, attr + "_time")
                if v is not None:
                    s += """\
    <%s>
      <Timestamp>%s</Timestamp>
      <Data>
""" % (name, t)

                    # Process entry headers
                    for hname, hvalues in v.headers.iteritems():
                        for hvalue in hvalues:
                            s += """\
          <Header>
            <Name>%s</Name>
            <Value>%s</Value>
          </Header>
""" % (xmlescape(hname), xmlescape(hvalue))

                    # Process entry body and close tag
                    s += """\
        <Body>%s</Body>
      </Data>
    </%s>
""" % (base64.encodestring(v.body), name)

            s += "  </Entry>\n"

        s += "</Entries>\n"

        return s

