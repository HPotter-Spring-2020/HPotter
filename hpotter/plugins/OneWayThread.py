import socket
import threading

from hpotter import tables
from hpotter.env import logger, write_db

# read and write between two sockets with a possible upper limit. write to
# db if table passed in.
class OneWayThread(threading.Thread):
    def __init__(self, source, dest, table=None, limit=0):
        super().__init__()
        logger.info("Starting a one-way thread")
        self.source = source
        self.dest = dest
        self.table = table
        self.limit = limit

        if self.table:
            self.connection = tables.Connections(
                sourceIP=self.source.getsockname()[0],
                sourcePort=self.source.getsockname()[1],
                destIP=self.dest.getsockname()[0],
                destPort=self.dest.getsockname()[1],
                proto=tables.TCP)
            write_db(self.connection)

    def run(self):
        total = b''
        while 1:
            logger.debug('Reading from: ' + str(self.source))
            try:
                data = self.source.recv(4096)
            except Exception as exception:
                logger.info(exception)
                break
            logger.debug('Read: ' + str(data))

            if data == b'' or not data:
                break

            if self.table or self.limit > 0:
                total += data

            logger.debug('Sending to: ' + str(self.dest))
            try:
                self.dest.sendall(data)
            except Exception as exception:
                logger.info(exception)
                break
            logger.debug('Sent')

            if self.limit > 0 and len(total) >= self.limit:
                break

        if self.table and len(total) > 0:
            write_db(self.table(request=str(total), connection=self.connection))
