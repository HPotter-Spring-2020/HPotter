import unittest
import socket
from unittest.mock import PropertyMock

from hpotter.plugins.ContainerThread import ContainerThread

class TestContainerThread(unittest.TestCase):

    def test_TestDynamicFirewallRule1(self):
        source_ip = "192.168.1.1"
        netmask = "255.255.255.255"  # When the subnet mask is not specified by the user, it defaults to this
        source_port = "8080"
        destination_ip = "172.161.1.1"
        destination_port = "8081"
        protocol = "tcp"

        source = socket.socket()
        connection = unittest.mock.Mock()
        config = unittest.mock.Mock()

        with unittest.mock.patch('socket.socket.getpeername', new_callable=PropertyMock()) as mock_source:
            mock_source.return_value = [source_ip, source_port]
            result = ContainerThread(source, connection, config)
            result.container_protocol = "tcp"
            result.container_ip = destination_ip
            result.container_port = destination_port
            result.create_rules()

            toRule = result.to_rule



        self.assertEqual(toRule['src'], source_ip)
        self.assertEqual(toRule['dst'], destination_ip)
        self.assertEqual(toRule[protocol]['sport'], source_port)
        self.assertEqual(toRule[protocol]['dport'], destination_port)
        self.assertEqual(toRule['protocol'], protocol)
        self.assertEqual(toRule['target'], "ACCEPT")
        result.remove_rules()


    def test_TestDynamicFirewallRule2(self):
        source_ip = "192.168.1.1"
        netmask = "255.255.255.255"  # When the subnet mask is not specified by the user, it defaults to this
        source_port = "8080"
        destination_ip = "172.161.1.1"
        destination_port = "8081"
        protocol = "tcp"

        source = socket.socket()
        connection = unittest.mock.Mock()
        config = unittest.mock.Mock()

        with unittest.mock.patch('socket.socket.getpeername', new_callable=PropertyMock()) as mock_source:
            mock_source.return_value = [source_ip, source_port]
            result = ContainerThread(source, connection, config)
            result.container_protocol = "tcp"
            result.container_ip = destination_ip
            result.container_port = destination_port
            result.create_rules()

            fromRule = result.from_rule

        self.assertEqual(fromRule['src'], destination_ip)
        self.assertEqual(fromRule['dst'], source_ip)
        self.assertEqual(fromRule[protocol]['sport'], destination_port)
        self.assertEqual(fromRule[protocol]['dport'], source_port)
        self.assertEqual(fromRule['protocol'], protocol)
        self.assertEqual(fromRule['target'], "ACCEPT")
        result.remove_rules()


    def test_TestDynamicFirewallRule3(self):
        source_ip = "192.168.1.1"
        netmask = "255.255.255.255"  # When the subnet mask is not specified by the user, it defaults to this
        source_port = "8080"
        destination_ip = "172.161.1.1"
        destination_port = "8081"
        protocol = "tcp"

        source = socket.socket()
        connection = unittest.mock.Mock()
        config = unittest.mock.Mock()
        with unittest.mock.patch('socket.socket.getpeername', new_callable=PropertyMock()) as mock_source:
            mock_source.return_value = [source_ip, source_port]
            result = ContainerThread(source, connection, config)
            result.container_protocol = "tcp"
            result.container_ip = destination_ip
            result.container_port = destination_port
            result.create_rules()

            dropRule = result.drop_rule

        self.assertEqual(dropRule['src'], destination_ip)
        self.assertEqual(dropRule['dst'], "!" + source_ip)
        self.assertEqual(dropRule['target'], "DROP")
        result.remove_rules()