#!/usr/bin/python3

import firewall
import scapy.all as scapy
import unittest

class TestMatchIp(unittest.TestCase):
    def test_ip_src_addr_true(self):
        match = firewall.Match("IP", "src", "10.0.0.1")
        pkt = scapy.IP(src="10.0.0.1")
        self.assertTrue(match.matches(pkt))

    def test_ip_src_net_true(self):
        match = firewall.Match("IP", "src", "10.0.0.0/8")
        pkt = scapy.IP(src="10.0.0.1")
        self.assertTrue(match.matches(pkt))

    def test_ip_src_addr_false(self):
        match = firewall.Match("IP", "src", "10.0.0.1")
        pkt = scapy.IP(src="20.0.0.2")
        self.assertFalse(match.matches(pkt))

    def test_ip_src_net_false(self):
        match = firewall.Match("IP", "src", "10.0.0.0/8")
        pkt = scapy.IP(src="20.0.0.2")
        self.assertFalse(match.matches(pkt))


if __name__ == '__main__':
    unittest.main()

