# Author: Tomasz bla Fortuna
# License: GPLv2

"""Handles main file and additional static files.

In general in a normal deployment this would be outside Flask.
"""

import os

from flask import Blueprint

static_folder = '../../static'

static = Blueprint('static', __name__,
                   template_folder='templates',
                   static_folder=static_folder)

@static.route('/')
def index():
    "Main page"
    return static.send_static_file('index.html')

@static.route('/css/<path:filename>')
def css(filename):
    path = os.path.join('css', filename)
    return static.send_static_file(path)

@static.route('/js/<path:filename>')
def js(filename):
    path = os.path.join('js', filename)
    return static.send_static_file(path)

@static.route('/templates/<path:filename>')
def templates(filename):
    path = os.path.join('templates', filename)
    return static.send_static_file(path)
