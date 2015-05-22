# Author: Tomasz bla Fortuna
# License: GPLv2

import os
from flask import Flask, g
import wifistalker

# Configure
app = Flask('wifistalker')
app.debug = True
#app.static_folder = '/home/project/WifiStalker/static'
app.config.update(SEND_FILE_MAX_AGE_DEFAULT=0)

# Place holder set later when model is initialized
db = None

from static import static
from knowledge import api as api_knowledge
from graphs import api as api_graph
#from map import api as api_map

app.register_blueprint(static) # url_prefix=/
app.register_blueprint(api_knowledge, url_prefix='/api')
#app.register_blueprint(api_map, url_prefix='/api')
app.register_blueprint(api_graph, url_prefix='/api/graph')

@app.before_request
def before_request():
    # Inject DB object into request function
    g.db = wifistalker.db

