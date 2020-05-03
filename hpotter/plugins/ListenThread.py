import socket
import threading
import ssl
import tempfile
import os

from OpenSSL import crypto
from time import gmtime, mktime
from multiprocessing.pool import ThreadPool
from threading import Semaphore

from hpotter.logger import logger
from hpotter import tables
from hpotter.db import db
from hpotter.plugins.ContainerThread import ContainerThread
from hpotter.plugins.ssh import get_clear_text

class ListenThread(threading.Thread):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.shutdown_requested = False
        self.TLS = 'TLS' in self.config and self.config['TLS']
        self.SSH = 'SSH' in self.config and self.config['SSH']
        self.context = None
        self.container_list = []
        self.thread_pool = ThreadPool(processes=self.config['max_threads'])
        self.workers = Semaphore(self.config['max_threads'])

    # https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python
    def gen_cert(self):
        if 'key_file' in self.config:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(self.config['cert_file'], self.config['key_file'])
        else:

            info = self.create_cert_key()
            cert = info['cert']
            key = info['key']

            files = self.create_cert_related_files(cert, key)
            cert_file = files['cert_file']
            key_file = files['key_file']



            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

            self.remove_cert_related_files(cert_file, key_file)

    def create_cert_key(self):
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
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        return {'cert': cert, 'key': key}

    def create_cert_related_files(self, cert, key):
        # can't use an iobyte file for this as load_cert_chain only take a
        # filesystem path :/
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        cert_file.close()

        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        key_file.close()

        return {'cert_file': cert_file, 'key_file': key_file}

    def remove_cert_related_files(self, cert_file, key_file):
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

    # https://stackoverflow.com/questions/37167501/multiprocessing-python-is-it-possible-to-send-to-the-pool-a-job-sequentially
    def start_container(self, source):
        container = ContainerThread(source, self.connection, self.config)
        self.container_list.append(container)
        container.start()
        logger.info('Waiting for container death')
        while True:
            if not container.is_alive():
                logger.info('Container: %s dead releasing worker', container)
                self.release_worker()
                break

    def spawn_container(self, source):
        self.workers.acquire()
        self.thread_pool.apply_async(self.start_container, (source,))

    def release_worker(self):
        self.workers.release()
        logger.info('Worker released')



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
                
                if self.SSH:        
                    source = get_clear_text(source, address, listen_socket.getsockname()[0] , listen_socket.getsockname()[1]  )

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
            self.spawn_container(source)

        if listen_socket:
            listen_socket.close()
            logger.info('Socket closed')

    def shutdown(self):
        self.shutdown_requested = True
        for c in self.container_list:
            if c.is_alive():
                c.shutdown()
                self.release_worker()
