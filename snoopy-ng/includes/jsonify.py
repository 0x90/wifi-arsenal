from datetime import datetime
from sqlalchemy import DateTime
import time
import json
from includes.common import get_tables
import logging

def date_to_epoch(_dt):
	return time.mktime(_dt.utctimetuple())

def epoch_to_date(_et):
	return datetime.fromtimestamp(_et)

obj_to_json = { 
		datetime : date_to_epoch 
	       }

json_to_obj = { 
		DateTime : epoch_to_date 
	       }


col_type_mapper = {}
def load_col_type_mapper():
	global col_type_mapper
	tbls = get_tables()
	for tbl in tbls:
		for col in tbl.columns:
			typ = type(col.type)
			if json_to_obj.get(typ):
				col_type_mapper[(tbl.name,col.name)] = json_to_obj.get(typ)
			
	
def objs_to_json(_data):
    for r in range(len(_data['data'])):
        row = _data['data'][r]
        for name, value in row.iteritems():
            if obj_to_json.get( type(value) ):
                f = obj_to_json[ type(value) ]
                _data['data'][r][name] = f(value)

    try:
       return json.dumps(_data)
    except:
       print _data

def json_to_objs(_json):
    if not col_type_mapper:
        logging.debug("Preloading table mappings...")
        load_col_type_mapper()

    _data = json.loads(_json)		
    table = _data['table']
    for r in range(len(_data['data'])):
        row = _data['data'][r]
        for name, value in row.iteritems():
            if col_type_mapper.get( (table, name) ):
                f = col_type_mapper[ (table, name) ]
                _data['data'][r][name] = f(value)

    return _data


def json_list_to_objs(_json):
    """Take a list of table data, and convert to a list of dicts"""
    if not col_type_mapper:
        logging.debug("Preloading table mappings...")
        load_col_type_mapper()

    _data_list = json.loads(_json)
    _data_to_return = []
    for _data in _data_list:
        table = _data['table']
        for r in range(len(_data['data'])):
            row = _data['data'][r]
            for name, value in row.iteritems():
                if col_type_mapper.get( (table, name) ):
                    f = col_type_mapper[ (table, name) ]
                    _data['data'][r][name] = f(value)
        _data_to_return.append(_data)
    return _data_to_return



