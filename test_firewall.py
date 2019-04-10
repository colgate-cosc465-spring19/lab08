#!/usr/bin/python3

import firewall
import scapy.all as scapy
import unittest

class TestMatchRule(unittest.TestCase):
    def test_permit_first(self):
        fw = firewall.Firewall(
                [firewall.Rule([firewall.Match("IP","src","10.0.0.1")], True)])
        pkt = scapy.IP(src="10.0.0.1")
        self.assertTrue(fw.permitted(pkt))

    def test_deny_first(self):
        fw = firewall.Firewall(
                [firewall.Rule([firewall.Match("IP","src","10.0.0.1")])], 
                True)
        pkt = scapy.IP(src="10.0.0.1")
        self.assertFalse(fw.permitted(pkt))
 
    def test_deny_default(self):
        fw = firewall.Firewall(
                [firewall.Rule([firewall.Match("IP","src","10.0.0.1")], False)])
        pkt = scapy.IP(src="20.0.0.2")
        self.assertFalse(fw.permitted(pkt))
    
if __name__ == '__main__':
    unittest.main()

