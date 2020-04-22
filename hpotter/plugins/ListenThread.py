import socket
import threading
import ssl
import tempfile
import os

from OpenSSL import crypto
from time import gmtime, mktime

from hpotter.logger import logger
from hpotter import tables
from hpotter.db import db
from hpotter.plugins.ContainerThread import ContainerThread

class ListenThread(threading.Thread):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.shutdown_requested = False
        self.TLS = 'TLS' in self.config and self.config['TLS']
        self.context = None
        self.container_list = []

    # https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python
    def gen_cert(self):
        if 'key_file' in self.config:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(self.config['cert_file'], self.config['key_file'])
        else:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 4096)
            cert = crypto.X509()
            cert.get_subject().C = "UK"
            cert.get_subject().ST = "London"
            cert.get_subject().L = "Diagon Alley"
            cert.get_subject().OU = "The Leaky Caldron"
            cert.get_subject().O = "J.K. Incorporated"
            cert.get_subject().CN = socket.gethostname()
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10*365*24*60*60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(key, 'sha1')

            # can't use an iobyte file for this as load_cert_chain only take a
            # filesystem path :/
            cert_file = tempfile.NamedTemporaryFile(delete=False)
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            cert_file.close()

            key_file = tempfile.NamedTemporaryFile(delete=False)
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            key_file.close()

            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

            os.remove(cert_file.name)
            os.remove(key_file.name)

    def save_connection(self, address):
        if 'add_dest' in self.config:
            self.connection = tables.Connections(
                sourceIP=self.config['listen_IP'],
                sourcePort=self.config['listen_port'],
                destIP=address[0],
                destPort=address[1],
                proto=tables.TCP)
            db.write(self.connection)
        else:
            self.connection = tables.Connections(
                destIP=address[0],
                destPort=address[1],
                proto=tables.TCP)
            db.write(self.connection)

    def run(self):
        if self.TLS:
            self.gen_cert()

        listen_address = (self.config['listen_IP'], int(self.config['listen_port']))
        logger.info('Listening to ' + str(listen_address))
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # check for shutdown request every five seconds
        listen_socket.settimeout(5)
        listen_socket.bind(listen_address)
        listen_socket.listen()

        while True:
            source = None
            try:
                source, address = listen_socket.accept()
                if self.TLS:
                    source = self.context.wrap_socket(source, server_side=True)
            except socket.timeout:
                if self.shutdown_requested:
                    logger.info('ListenThread shutting down')
                    break
                else:
                    continue
            except Exception as exc:
                logger.info(exc)

            self.save_connection(address)
            container = ContainerThread(source, self.connection, self.config)
            self.container_list.append(container)
            container.start()

        if listen_socket:
            listen_socket.close()
            logger.info('Socket closed')

    def shutdown(self):
        self.shutdown_requested = True
        for c in self.container_list:
            if c.is_alive():
                c.shutdown()
