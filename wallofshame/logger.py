import sys
import logging             

class logger:
         
        def __init__(self, instance):
                self.module = instance.__class__.__module__
                self.init()

        def init(self):
                self.logger = logging.getLogger(self.module)
                self.logger.setLevel(logging.DEBUG)

                ch = logging.StreamHandler()
                ch.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
                self.logger.addHandler(ch)

        
        def info(self, message):
                self.logger.info(message)

        def debug(self, message):
                self.logger.debug(message)

        def error(self, message):
                self.logger.error(message)

        def warn(self, message):
                self.logger.warn(message)
