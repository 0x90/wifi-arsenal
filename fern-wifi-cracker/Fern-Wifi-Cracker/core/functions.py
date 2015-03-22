import os
import re
import sqlite3
import commands
import subprocess

################### DATABASE INSERTION FUNCTIONS ##############
#
# Create database if it does not exist
#
def database_create():
    temp = sqlite3.connect(os.getcwd() + '/key-database/Database.db')                 # Database File and Tables are created Here
    temp_query = temp.cursor()
    temp_query.execute('''create table if not exists keys \
                            (access_point text,mac_address text,encryption text,key text,channel int)''')
    temp.commit()
    temp.close()


#
# Add keys to Database with this function
#

def upgrade_database():
    connection = sqlite3.connect('key-database/Database.db')
    query = connection.cursor()
    query.execute("select * from keys")

    if(len(query.description) < 5):
        temp_backup = query.fetchall()
        query.execute("drop table keys")
        query.execute('''create table keys (access_point text,mac_address text,encryption text,key text,channel int)''')
        for values in temp_backup:
            query.execute("insert into keys values ('%s','%s','%s','%s','%s')"%(values[0],str(),values[1],values[2],values[3]))
    connection.commit()
    connection.close()



def set_key_entries(arg,arg1,arg2,arg3,arg4):
    upgrade_database()
    connection = sqlite3.connect('key-database/Database.db')
    query = connection.cursor()
    sql_code = "select key from keys where mac_address ='%s' and encryption = '%s'"
    query.execute(sql_code % (str(arg1),str(arg2)))
    result = query.fetchall()
    if(result):
        sql_code_2 = "update keys set access_point = '%s',encryption = '%s',key = '%s',channel = '%s' where mac_address = '%s'"
        query.execute(sql_code_2 % (str(arg),str(arg2),str(arg3),str(arg4),str(arg1)))
    else:
        query.execute("insert into keys values ('%s','%s','%s','%s','%s')"%(str(arg),str(arg1),str(arg2),str(arg3),str(arg4)))
    connection.commit()
    connection.close()



def get_key_from_database(mac_address,encryption):
    cracked_key = str()
    upgrade_database()
    sql_code = "select key from keys where mac_address ='%s' and encryption = '%s'"
    connection = sqlite3.connect('key-database/Database.db')
    query = connection.cursor()
    query.execute(sql_code % (mac_address,encryption))
    result = query.fetchall()
    if(result):
        cracked_key = str(result[0][0])
    return(cracked_key)


def is_already_Cracked(mac_address,encryption):
    sql_code = "select key from keys where mac_address ='%s' and encryption = '%s'"
    connection = sqlite3.connect('key-database/Database.db')
    query = connection.cursor()
    query.execute(sql_code % (mac_address,encryption))
    result = query.fetchall()
    if(result):
        return(True)
    return(False)



def fern_database_query(sql_query):
    connection = sqlite3.connect('key-database/Database.db')
    query = connection.cursor()
    query.execute(sql_query)
    output = query.fetchall()
    connection.commit()
    connection.close()
    return(output)

########## GENERIC GLOBAL READ/WRITE FUNCTIONS ###############
#
# Some globally defined functions for write,copy and read tasks
#
def reader(arg):
    read_file = str()
    try:
        open_ = open(arg,'r+')
        read_file = open_.read()
    finally:
        return read_file

def write(arg,arg2):
    open_ = open(arg,'a+')
    open_.write(arg2)
    open_.close()

def remove(arg,arg2):
    commands.getstatusoutput('rm -r %s/%s'%(arg,arg2))  #'rm - r /tmp/fern-log/file.log



########## GENERAL SETTINGS FUNCTION #########################


################# MAC Address Validator ######################

def Check_MAC(mac_address):
    hex_digits = re.compile('([0-9a-f]{2}:){5}[0-9a-f]{2}',re.IGNORECASE)
    if re.match(hex_digits,mac_address):
        return(True)
    return(False)


#################   FILE LINE COUNTER ########################

def blocks(files, size=65536):
    '''yields file stream in block sections'''
    while True:
        b = files.read(size)
        if not b: break
        yield b

def line_count(filename):
    '''Returns estimated value of line'''
    with open(filename, "r") as f:
        count =  sum(bl.count("\n") for bl in blocks(f))
        return(count + 1)


######################## Font settings #######################
def font_size():
	font_settings = open('%s/.font_settings.dat'%(os.getcwd()),'r+')
	font_init = font_settings.read()
	return int(font_init.split()[2])


###################### Process Terminate ######################






