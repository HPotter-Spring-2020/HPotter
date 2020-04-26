import unittest
import tempfile
import os
from OpenSSL import crypto
from unittest import mock
from hpotter.plugins.ListenThread import ListenThread

class TestListenThread(unittest.TestCase):

    def test_cert_key_info(self):
        info = ListenThread.create_cert_key(self)
        cert = info['cert']
        key = info['key']

        print(cert.get_subject().C)
        self.assertEqual(cert.get_subject().C, "UK")
        self.assertEqual(cert.get_subject().ST, "London")
        self.assertEqual(cert.get_subject().L, "Diagon Alley")
        self.assertEqual(cert.get_subject().OU, "The Leaky Caldron")
        self.assertEqual(cert.get_subject().O, "J.K. Incorporated")
        # self.assertEqual(cert.get_subject().CN, "?") Don't know how to mock() the socket.getHostName() call
        self.assertEqual(cert.get_serial_number(), 1000)
        self.assertEqual(cert.get_issuer(), cert.get_subject())


    def test_cert_creation_and_removal(self):   # Check if the method creates and removes cert files properly
        cert = crypto.X509()
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        files = ListenThread.create_cert_related_files(self, cert, key)
        cert_file = files['cert_file']
        key_file = files['key_file']

        self.assertEqual(os.path.exists(cert_file.name), True)
        self.assertEqual(os.path.exists(key_file.name), True)

        ListenThread.remove_cert_related_files(self, cert_file, key_file)

        self.assertEqual(os.path.exists(cert_file.name), False)
        self.assertEqual(os.path.exists(key_file.name), False)
