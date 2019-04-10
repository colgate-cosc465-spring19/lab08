#!/usr/bin/python3

import firewall
import scapy.all as scapy
import unittest

class TestMatchRule(unittest.TestCase):
    def test_ip_src_true(self):
        rule = firewall.Rule([firewall.Match("IP", "src", "10.0.0.1")])
        pkt = scapy.IP(src="10.0.0.1")
        self.assertTrue(rule.matches(pkt))

    def test_ip_src_false(self):
        rule = firewall.Rule([firewall.Match("IP", "src", "10.0.0.1")])
        pkt = scapy.IP(src="20.0.0.2")
        self.assertFalse(rule.matches(pkt))
    
    def test_ip_src_and_dst_true(self):
        rule = firewall.Rule([firewall.Match("IP", "src", "10.0.0.1"),
                firewall.Match("IP", "dst", "20.0.0.2")])
        pkt = scapy.IP(src="10.0.0.1", dst="20.0.0.2")
        self.assertTrue(rule.matches(pkt))

    def test_ip_src_and_dst_partial(self):
        rule = firewall.Rule([firewall.Match("IP", "src", "10.0.0.1"),
                firewall.Match("IP", "dst", "20.0.0.2")])
        pkt = scapy.IP(src="10.0.0.1", dst="30.0.0.3")
        self.assertFalse(rule.matches(pkt))
    
if __name__ == '__main__':
    unittest.main()

