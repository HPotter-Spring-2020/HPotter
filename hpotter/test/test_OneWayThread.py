import unittest
from unittest.mock import call, patch
from hpotter.plugins.OneWayThread import OneWayThread

class TestOneWayThread(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    # pylint: disable=R0201
    def test_SendSingle(self):
        request = unittest.mock.Mock()
        request.recv.side_effect = [bytes(i, 'utf-8') for i in 'a']
        response = unittest.mock.Mock()

        db = unittest.mock.Mock()
        owt = OneWayThread(db, request, response, {}, 'request', None)
        owt.run()

        response.sendall.assert_has_calls([call(b'a')])

    def test_TestLimit(self):
        tosend = 'aa'
        request = unittest.mock.Mock()
        request.recv.side_effect = [bytes(i, 'utf-8') for i in 'aa']
        response = unittest.mock.Mock()

        db = unittest.mock.Mock()
        owt = OneWayThread(db, request, response, {'request_length': 2}, 'request', None)
        owt.run()

        response.sendall.assert_has_calls([call(b'a')])

