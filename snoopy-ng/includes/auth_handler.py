#!/usr/bin/env python
# -*- coding: utf-8 -*-
from sqlalchemy import create_engine, MetaData, Table, Column, String,\
                   select, and_, Integer, ForeignKey, delete
from sqlalchemy.exc import *
import os
import sys
import logging
import random
import string
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.expression import Insert

path=os.path.dirname(os.path.realpath(__file__))

@compiles(Insert)
def replace_string(insert, compiler, **kw):
    s = compiler.visit_insert(insert, **kw)
    s = s.replace("INSERT INTO", "REPLACE INTO")
    return s

class auth:
    """Handle authentication"""
    def __init__(self,dbms="sqlite:///%s/snoopy_creds.db" % path, rawdb=None):
        if not rawdb:
            self.db = create_engine(dbms)
        else:
            self.db = rawdb
        self.metadata = MetaData(self.db)
        self.metadata.reflect()

        drone_tbl_def = Table('drones', MetaData(),
                            Column('drone', String(40), primary_key=True),
                            Column('key', String(40)))

        user_tbl_def = Table('users', MetaData(),
                            Column('user', String(40), primary_key=True),
                            #Column('drone', String(40), ForeignKey('drones.drone')))
                            Column('drone', String(40), primary_key=True, autoincrement=False))

        mt_tbl_def = Table('mtk', MetaData(),
                            Column('user', String(40), primary_key=True),
                            Column('mtkey', String(40), primary_key=True, autoincrement=False))
        
        if 'drones' not in self.metadata.tables.keys():
            self.db.create(drone_tbl_def)
        if 'users' not in self.metadata.tables.keys():
            self.db.create(user_tbl_def)
        if 'mtk' not in self.metadata.tables.keys():
            self.db.create(mt_tbl_def)

        self.metadata.reflect()
        self.drone_table = self.metadata.tables['drones']
        self.user_table = self.metadata.tables['users']
        self.mtk_table = self.metadata.tables['mtk']

    def associate_drone(self, drone, user):
        assert drone
        assert user

        #Check if a Maltego key exists
        s = select([self.mtk_table]).where(self.mtk_table.c.user == user)
        r = self.db.execute(s)
        results = r.fetchall()
        if len(results) <= 0:
            mtkey = ''.join(random.choice(string.ascii_uppercase + string.digits)
                            for x in range(15))
            self.mtk_table.insert().execute(user=user,mtkey=mtkey)

        self.user_table.insert().execute(user=user,drone=drone)

    def disassociate_drone(self, drone, user):
        assert drone
        assert user
        d = delete(self.user_table,  and_(self.user_table.c.drone == drone, self.user_table.c.user == user))
        r = self.db.execute(d)
        return r.rowcount

    def list_mtk(self,user):
        filter = []
        if user:
            filter.append(self.mtk_table.c.user == user) 
        results = list(self.mtk_table.select(and_(*filter)).execute().fetchall())
        toReturn = []
        for row in results:
            usr,mtk = row[0],row[1]
            toReturn.append({"user":usr,"mtk":mtk})
        return toReturn   
        
    def list_associations(self, user=None):
        filter = []
        if user:
            filter.append(self.user_table.c.user == user )
        results =  list(self.user_table.select(and_(*filter)).execute().fetchall())
        toReturn = []
        for row in results:
            usr,snsr = row[0], row[1]
            toReturn.append({"user":usr, "sensor":snsr }) 
        return toReturn

    def manage_drone_account(self, drone, operation):
    
        if operation == "create":
            try:
                key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                              for x in range(15))
                self.drone_table.insert().execute(drone=drone, key=key)
                logging.info("Created new drone '%s'" % drone)
            except IntegrityError:
                logging.error("Drone '%s' already exists!" %drone) #REPLACE INTO will actually just replace it
            except Exception:
                logging.exception("Exception whilst attempting to add drone")
            else:
                return key
        elif operation == "delete":
            result = self.db.execute("DELETE FROM drones WHERE drone='{0}'".format(drone))
            if result.rowcount == 0:
                logging.warning("No such account. Ignoring")
            #self.drone_table.delete().execute(drone=drone)
            return True
        elif operation == "list":
            return(self.drone_table.select().execute().fetchall())
        else:
            logging.error("Bad operation '%s' passed to manage_drone_account" %
                          operation)
            return False
    
    def verify_account(self,_drone, _key):
        try:
            self.drone_table=self.metadata.tables['drones']
            s = select([self.drone_table],
                       and_(self.drone_table.c.drone==_drone, self.drone_table.c.key==_key))
            result = self.db.execute(s).fetchone()
    
            if result:
                #logging.debug("Auth granted for %s" % _drone)
                return True
            else:
                logging.debug("Access denied for %s" % _drone)
                return False
        except Exception, e:
            logging.error('Unable to query access control database. Have you run snoopy_auth to create an account?')
            return False
    
    def verify_admin(self,user, pwd):
        if user == "serval" and pwd == "tanzaniaMountainClimbing13":
            return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-c","--create", help="Create a new drone account")
    parser.add_argument("-d","--delete", help="Delete an existing drone account")
    parser.add_argument("-l","--list", help="List all drones and keys", action="store_true")
    parser.add_argument("-a", "--assoc", help="Associate user to drone (supply <user>,<drone>)")
    parser.add_argument("-r", "--disassoc", help="Dis-associate user and drone (supply <user>,<drone>)")
    parser.add_argument("-u","--users", help="List user/drone associations.", nargs='?', const="*")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        print "[!] No options supplied. Try --help."
    else:

        auth_ = auth('sqlite:////root/snoopy-ng/snoopy.db')
        if args.assoc:
            usr,drn = args.assoc.split(",")
            print "[+] Associating user '%s' to drone '%s'" %(usr,drn)
            auth_.associate_drone(user=usr,drone=drn)

        if args.disassoc:
            usr,drn = args.disassoc.split(",")
            print "[+] Dis-associating user '%s' and drone '%s'" % (usr,drn)
            n = auth_.disassociate_drone(user=usr,drone=drn)
            print "    %d associations removed" % n
        if args.users:
            print "[+] User/drone associations:"
            if args.users == "*":
                args.users = None
            for pair in auth_.list_associations(user=args.users):
                print "\t%s:%s" %(pair[0],pair[1])

        if args.create:
            print "[+] Creating new Snoopy server sync account"
            key = auth_.manage_drone_account(args.create, "create")
            if key:
                print "[+] Key for '%s' is '%s'" % (args.create, key)
                print "[+] Use this value in client mode to sync data to a remote server."
        elif args.delete:
            if auth_.manage_drone_account(args.delete, "delete"):
                print "[+] Deleting '%s'" % args.delete
        elif args.list:
            print "[+] Available drone accounts:"
            drones = auth_.manage_drone_account("foo", "list")
            for d in drones:
                print "\t%s:%s" % (d[0], d[1])

