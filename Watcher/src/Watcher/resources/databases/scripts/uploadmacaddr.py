#!/usr/bin/env python

# MAC Address download and upload to sqlite database

import sqlite3 as lite
import sys

mac_list = []
db_loc = sys.argv[2]
f_loc = sys.argv[1]
con = lite.connect(db_loc)

def upload_mac():
	f = open(f_loc, 'r').readlines()
	for line in f:
		m_addr = line[:6]
		vend = line[7:].strip('\n')
		rec = m_addr, vend
		if rec not in mac_list:
			with con:
				cur = con.cursor()
				cur.execute('INSERT INTO macaddr VALUES(?, ?)', rec)
				mac_list.append(rec)
		else:
			pass

upload_mac()