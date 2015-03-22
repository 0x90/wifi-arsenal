import sys
sys.path.insert(0, '/home/glenn/snoopy_ng/')
from includes.webserver import create_db_tables, app as application

create_db_tables()
