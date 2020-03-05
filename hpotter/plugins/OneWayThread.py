import socket
import threading
import re

from hpotter import tables
from hpotter.logger import logger
from hpotter.db import db

class OneWayThread(threading.Thread):
    def __init__(self, source, dest, connection, config, direction):
        super().__init__()
        self.source = source
        self.dest = dest
        self.config = config
        self.connection = connection
        self.config = config
        self.direction = direction

        self.total = self.data = b''
        self.shutdown_requested = False

    def read(self):
        try:
            self.data = self.source.recv(4096)
        except Exception as exception:
            logger.info(exception)
            return False

        logger.debug('Reading from: ' + str(self.source) + ', read: ' + str(self.data))

        if self.data == b'' or not self.data:
            logger.debug('No data read, stopping')
            return False

        self.total += self.data

        return True

    def write(self):
        logger.debug('Sending to: ' + str(self.dest) + ', sent: ' + str(self.data))
        try:
            self.dest.sendall(self.data)
        except Exception as exception:
            logger.info(exception)
            return False

        return True

    def run(self):
        if self.direction + '_length' in self.config:
            length = self.config[self.direction + '_length']
        else:
            length = 0

        while True:
            if not self.read():
                break

            if not self.write():
                break

            if self.shutdown_requested:
                break

            if length > 0 and len(self.total) >= length:
                logger.debug('Limit exceeded, stopping')
                break

        logger.debug(length)
        logger.debug(len(self.total))
        logger.debug(self.direction)
        if length > 0 and len(self.total) > 0:
            db.write(tables.Data(direction=self.direction, data=str(self.total), connection=self.connection))

            printChars = r'[ -\[\]-~]+' # excludes \
            exp = r'"' + printChars + r'\\r' + printChars + r'\\r'
            m = re.search(exp, str(self.total))
            if m:
                userAndPw = m.group()[1:].split('\\r')
                db.write(tables.Credentials(username=userAndPw[0], password=userAndPw[1], connection=self.connection))

    def shutdown(self):
        self.shutdown_requested = True
