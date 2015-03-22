#!/usr/bin/env python
#coding:utf-8
import time
from gevent import monkey; monkey.patch_all()
from gevent.event import Event

from bottle import route, post, request, static_file, app
from bottle import jinja2_view as view

cache = []
new_message_event = Event()

@route('/chatbox')
@view('index')
def index():
    return {'messages': cache}

@post('/chatbox/put')
def put_message():
    message = request.forms.get('message','')
    cache.append( '[%s]: %s' % (time.strftime('%Y/%m/%d %X'), message.decode('utf-8')) )
    new_message_event.set()
    new_message_event.clear()
    return 'OK'

@post('/chatbox/poll')
def poll_message():
    new_message_event.wait()
    return dict(data=[cache[-1]])

@route('/chatbox/static/:filename', name='static')
def static_files(filename):
    return static_file(filename, root='./static/')


if __name__ == '__main__':
    import bottle
    bottle.debug(True)
    bottle.run(app=app(), host='0.0.0.0', port=5000, server='gevent')
