#!/usr/bin/python3

import firewall
import scapy.all as scapy
import unittest

class TestMatchTransport(unittest.TestCase):
    def test_tcp_src_true(self):
        match = firewall.Match("TCP", "src", 80)
        pkt = scapy.IP()/scapy.TCP(sport=80)
        self.assertTrue(match.matches(pkt))
    
    def test_tcp_src_false(self):
        match = firewall.Match("TCP", "src", 80)
        pkt = scapy.IP()/scapy.TCP(sport=443)
        self.assertFalse(match.matches(pkt))

    def test_tcp_missing(self):
        match = firewall.Match("TCP", "src", 80)
        pkt = scapy.IP()
        self.assertFalse(match.matches(pkt))

    def test_udp_dst_true(self):
        match = firewall.Match("UDP", "dst", 53)
        pkt = scapy.IP()/scapy.UDP(dport=53)
        self.assertTrue(match.matches(pkt))
    
if __name__ == '__main__':
    unittest.main()

