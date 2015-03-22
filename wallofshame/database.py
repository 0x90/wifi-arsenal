from multiprocessing import Process, Queue
import MySQLdb
import logger

class database:

        _stop = 'stop'

        def __init__(self, options):
                self.options = options
                self.queue = Queue()
                self.proc = Process(target=self.loop)
                self.conn = None
                self.logger = logger.logger(self)

        def start(self):
                self.connect()
                self.proc.start()

        def stop(self):
                self.push(self._stop)
                self.proc.join()

        def push(self, command):
                self.queue.put(command, block=False)

        def connect(self):
                try:
                        self.conn = MySQLdb.connect(host = self.options.db_host, user = self.options.db_user, passwd = self.options.db_password, db = self.options.db_database)
                except MySQLdb.Error, e:
                        self.logger.error("Could not connect to database: %s" % (e[1]))
                        exit(1)
        
        def loop(self):
                while True:
                        command = self.queue.get()
                        if command == self._stop:
                                break
                        self.process(command)

        def process(self, statement):
                try:
                        self.conn.cursor().execute(statement)
                except (AttributeError, MySQLdb.OperationalError):
                        self.connect()
                        self.conn.cursor().execute(statement)
                except MySQLdb.ProgrammingError, e:
                        self.logger.warn("Fail to process SQL statement: %s : %s" % (statement, e[1]))

        def escape(self, string):
                return self.conn.escape_string(string)

