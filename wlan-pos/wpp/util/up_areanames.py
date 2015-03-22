#!/usr/bin/env python
# Update areaname(en,cn) into wpp_cellarea with key area code from wpp_area_std.
import psycopg2 as pg
from wpp.config import dsn_local_pg, dsn_moto_pg

dsn = dsn_moto_pg
#dsn = dsn_local_pg
con = pg.connect(dsn)
cur = con.cursor()
cur.execute('select areacode,areaname_en from wpp_cellarea')
data = cur.fetchall()

print len(data)

checked_areas = []

for line in data:
    acode_full, aname_en = line
    if acode_full in checked_areas: continue
    aname_en = "\\'".join(aname_en.split("'"))
    aname_en = ">".join(aname_en.split("+"))
    acode_prov = acode_full[:2].ljust(6,'0')
    acode_city = acode_full[:4].ljust(6,'0')
    print acode_prov,acode_city, acode_full
    sql_prov = "select name_cn from wpp_area_std where code='%s'" % acode_prov
    cur.execute(sql_prov)
    aname_prov = cur.fetchone()[0]
    sql_city = "select name_cn from wpp_area_std where code='%s'" % acode_city
    cur.execute(sql_city)
    aname_city = cur.fetchone()[0]
    sql_district = "select name_cn from wpp_area_std where code='%s'" % acode_full
    cur.execute(sql_district)
    aname_district = cur.fetchone()[0]
    # acode_full: acode_province + acode_city + acode_district/county.
    aname_cn = ">".join([aname_prov, aname_city, aname_district])
    # Update |wpp_area|.
    #sql = "update wpp_area set name_cn='%s' where code='%s'" % (aname_cn,acode_full)
    #print sql
    #cur.execute(sql)
    # Update |wpp_cellarea|.
    areanames = "'%s', '%s'" % (aname_en, aname_cn)
    sql = "update wpp_cellarea set (areaname_en,areaname_cn)=(%s) where areacode='%s'" % (areanames,acode_full)
    print sql
    cur.execute(sql)
    con.commit()
    checked_areas.append(acode_full)
    #break
