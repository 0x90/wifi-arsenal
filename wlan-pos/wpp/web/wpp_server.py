#!/usr/bin/env python
#import datetime as dt
#import re

from wpp.location import fixPos
from wpp.config import XHTML_IMT, wpplog, mc, GOOG_AVAIL


class LimitedStream(object):
    '''
    LimitedStream wraps another stream in order to not allow reading from it
    past specified amount of bytes.
    '''
    def __init__(self, stream, limit, buf_size=64 * 1024 * 1024):
        self.stream = stream
        self.remaining = limit
        self.buffer = ''
        self.buf_size = buf_size

    def _read_limited(self, size=None):
        if size is None or size > self.remaining:
            size = self.remaining
        if size == 0:
            return ''
        result = self.stream.read(size)
        self.remaining -= len(result)
        return result

    def read(self, size=None):
        if size is None:
            result = self.buffer + self._read_limited()
            self.buffer = ''
        elif size < len(self.buffer):
            result = self.buffer[:size]
            self.buffer = self.buffer[size:]
        else: # size >= len(self.buffer)
            result = self.buffer + self._read_limited(size - len(self.buffer))
            self.buffer = ''
        return result

def hgweb_handler(environ, start_response):
    from mercurial import demandimport; demandimport.enable()
    #from mercurial.hgweb.hgwebdir_mod import hgwebdir
    #from mercurial.hgweb.request import wsgiapplication
    from mercurial.hgweb import hgweb
     
    hgweb_conf = '/etc/mercurial/hgweb.conf'
    #make_web_app = hgwebdir(hgweb_conf)
    hg_webapp = hgweb(hgweb_conf)
     
    #hg_webapp = wsgiapplication(make_web_app)
    return hg_webapp(environ, start_response)

def index(environ, start_response):
    """This function will be mounted on "/" and display a link
    to the hello world page."""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return ['''Hello World Application, This is the Hello World application: 
               continue 'hello/\'''']

def hello(environ, start_response):
    """Like the example above, but it uses the name specified in the URL."""
    import cgi
    # get the name from the url if it was specified there.
    args = environ['myapp.url_args']
    if args:
        subject = cgi.escape(args[0])
    else:
        subject = 'World'
    start_response('200 OK', [('Content-Type', 'text/html')])
    return ['''Hello %(subject)s, 
               Good to see u %(subject)s!''' % {'subject': subject}]

def not_found(environ, start_response):
    """Called if no URL matches."""
    start_response('404 Empty WPP request msg!', [('Content-Type', 'text/plain')])
    return ['Empty WPP request msg!\n']

def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `myapp.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.
    """
    path = environ.get('PATH_INFO', '').lstrip('/')
    for regex, callback in urls:
        match = re.search(regex, path)
        if match is not None:
            print regex, callback
            environ['myapp.url_args'] = match.groups()
            return callback(environ, start_response)
    return not_found(environ, start_response)

def print_sec_msec():
    t = dt.datetime.now()
    print 'start time(s-ms) --> %s-%s' % (t.second, t.microsecond)

def wpp_handler(environ, start_response):
    """WPP posreq handler"""
    if 'CONTENT_LENGTH' in environ:
        #posreq = LimitedStream(environ['wsgi.input'], int(environ['CONTENT_LENGTH'])).read()
        posreq = environ['wsgi.input'].read()
        wpplog.info(posreq) #TODO:avoid multi-process log garbling.
        if posreq:
            posreq = posreq.split('dtd">')
            if len(posreq) == 1: # del xml-doc declaration.
                posreq = posreq[0].split('?>')
                if len(posreq) == 1: posreq = posreq[0]
                else: posreq = posreq[1] 
            else: posreq = posreq[1] # del xml-doc declaration.
            posresp = fixPos(posreq=posreq, has_google=GOOG_AVAIL, mc=mc)
            start_response('200 OK', [('Content-Type', XHTML_IMT),('Content-Length', str(len(posresp)) )])
            wpplog.info('%s\n%s' % (posresp,'='*30))
            return [ posresp ]
    return not_found(environ, start_response)

# map urls to functions
urls = [
    #(r'^$', index),
    (r'wlan/distribution$', wpp_handler),
    #(r'wlan/hg$', hgweb_handler),
    #(r'hello/?$', hello),
    #(r'hello/(.+)$', hello),
]


if __name__ == "__main__":
    try:
        import psyco
        psyco.bind(wpp_handler)
        psyco.bind(application)
        #psyco.full()
        #psyco.log()
        #psyco.profile(0.3)
    except ImportError:
        pass

    port = 8080

    # Gevent server.
    #from gevent.wsgi import WSGIServer
    #httpd = WSGIServer(('', port), wpp_handler, spawn=None)
    #httpd.backlog = 256
    #httpd.log = False
    # Meinheld server.
    from meinheld import server
    server.listen(("0.0.0.0", port))
    # Bjoern server.
    #import bjoern
    #bjoern.listen(wpp_handler, '0.0.0.0', port)
    # Gunicorn 
    # $gunicorn -b :8080 -w 5 wpp_server:wpp_handler
    # $gunicorn -b :8080 -w 5 -k "egg:meinheld#gunicorn_worker" wpp_server:wpp_handler
    # $gunicorn -b :8080 -w 5 -k "egg:gunicorn#gevent" wpp_server:wpp_handler
    # $gunicorn -b :8080 -w 5 -k "egg:gevent#gunicorn_worker" wpp_server:wpp_handler

    
    # Get IP address.
    from wpp.util.net import getIP
    ipaddr = getIP()
    if 'wlan0' in ipaddr:
        ipaddr = ipaddr['wlan0']
    else:
        ipaddr = ipaddr['eth0']
    print 'Starting up HTTP server on %s:%d ...' % (ipaddr, port)

    # Respond to requests until process is killed
    #httpd.serve_forever() # Gevent
    #bjoern.run() # bjoern
    server.run(wpp_handler) # Meinheld
