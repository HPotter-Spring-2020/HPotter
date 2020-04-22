import unittest
from unittest.mock import call, patch
from hpotter.plugins.OneWayThread import OneWayThread
from hpotter.db import DB

class TestOneWayThread(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    # pylint: disable=R0201
    def test_single(self):
        request = unittest.mock.Mock()
        request.recv.side_effect = [bytes(i, 'utf-8') for i in 'a']
        response = unittest.mock.Mock()

        connection = unittest.mock.Mock()
        OneWayThread(request, response, connection, {}, 'request').run()

        response.sendall.assert_has_calls([call(b'a')])
        response.sendall.assert_called_once()

    def test_limit(self):
        request = unittest.mock.Mock()
        request.recv.side_effect = [bytes(i, 'utf-8') for i in 'aaaa']
        response = unittest.mock.Mock()

        with patch.object(DB, "write") as dbwrite:
            connection = unittest.mock.Mock()
            OneWayThread(request, response, connection, {'request_length': 2}, 'request').run()
            assert dbwrite.call_args[0][0].data == "b'aa'"

        response.sendall.assert_has_calls([call(b'a')], [call(b'a')])
        assert response.sendall.call_count == 2

