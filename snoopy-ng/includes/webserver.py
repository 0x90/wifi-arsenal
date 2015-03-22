#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import json
from flask import Flask, request, Response, abort
from functools import wraps
from sqlalchemy import create_engine, MetaData, Table, Column, String,\
                   select, and_, Integer
from collections import deque
from sqlalchemy.exc import *
import time
from datetime import datetime
from auth_handler import auth
from includes.jsonify import json_to_objs, objs_to_json
from includes.common import get_tables, create_tables
from includes.fonts import *

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

path="/"

app = Flask(__name__)
#auth_ = auth()
server_data = deque(maxlen=100000)

auth_ = None

def write_local_db(rawdata):
    """Write server db"""
    for entry in rawdata:
        tbl = entry['table']
        data = entry['data']
        if tbl not in metadata.tables.keys():
            logging.error("Error: Drone attempting to insert data into invalid table '%s'"%tbl)
            return False
        tbl=metadata.tables[tbl]
        try:
            tbl.insert().execute(data)
        except Exception,e:
             logging.exception(e)
             return False
    return True

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not verify_admin(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth_.verify_account(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def unpack_data(request):
    if request.headers['Content-Type'] == 'application/json':
       try:
           return json.loads(request.data)
       except Exception,e:
           logging.error(e)

@app.route("/pull/", methods=['GET'])
@requires_auth
def pull():
    global tables
    global metadata
    metadata.reflect()
    all_data = []
    for table in tables:
        if "sunc" in table.c:
            table.metadata = metadata
            query = table.select()
            ex = query.execute()
            results = ex.fetchall()
            if results:
                result_as_dict = [dict(e) for e in results]
                data_to_return = {"table": table.name,
                                               "data": result_as_dict}
                data_to_return = json.loads(objs_to_json(data_to_return)) # A bit backward, ne
                all_data.append(data_to_return)
   
    #return type(json.dumps(str(all_data)) 
    return json.dumps(all_data)


# For the collection of data
@app.route(path, methods=['POST'])
@requires_auth
def catch_data():
    if request.headers['Content-Type'] == 'application/json':
        try:
            jsdata = json_to_objs(request.data)
        except Exception,e:
            logging.error("Unable to parse JSON from '%s'" % request)
            return '{"result":"failure", "reason":"Check server logs"}'
        else:
            server_data.append((jsdata['table'], jsdata['data']  )) 
    else:
        logging.error("Unable to parse JSON from '%s'" % request)
        return '{"result":"failure", "reason":"Check server logs"}'

    return '{"result":"success", "reason":"Check server logs"}'

def poll_data():
        rtnData=[]
        while server_data:
            rtnData.append(server_data.popleft())
        if rtnData:
            return rtnData
        else:
            return []

def prep(dbms="sqlite:///snoopy.db"):
    global db
    global tables
    global metadata
    db=create_engine(dbms)
    db.debug=True
    create_tables(db)
    tables = get_tables()
    metadata = MetaData(db)
    metadata.reflect() 

def run_webserver(port=9001,ip="0.0.0.0",_db=None):
    #create_db_tables()
    global db
    global tables
    global metadata
    global auth_

    auth_ = auth(rawdb=_db)

    db = _db
    if not _db:
        dbms="sqlite:///snoopy.db"
        db=create_engine(dbms)
    tables = get_tables()
    metadata = MetaData(db)
    app.run(host=ip, port=port)

if __name__ == "__main__":
    run_webserver()
