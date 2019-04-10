#!/usr/bin/python3

import firewall
import scapy.all as scapy
import unittest

class TestMatchDns(unittest.TestCase):
    def test_dns_query_true(self):
        match = firewall.Match("DNS", "query", "www.example.com")
        pkt = scapy.IP()/scapy.UDP(dport=53)/scapy.DNS(qr=0, 
                qd=scapy.DNSQR(qname="www.example.com"))
        self.assertTrue(match.matches(pkt))
    
    def test_dns_query_false(self):
        match = firewall.Match("DNS", "query", "www.example.com")
        pkt = scapy.IP()/scapy.UDP(dport=53)/scapy.DNS(qr=0, 
                qd=scapy.DNSQR(qname="www.colgate.edu"))
        self.assertFalse(match.matches(pkt))

    def test_dns_query_missing(self):
        match = firewall.Match("DNS", "query", "www.example.com")
        pkt = scapy.IP()/scapy.UDP(dport=53)/scapy.DNS(qr=0)
        self.assertFalse(match.matches(pkt))

    def test_dns_missing(self):
        match = firewall.Match("DNS", "query", "www.example.com")
        pkt = scapy.IP()/scapy.UDP(dport=53)
        self.assertFalse(match.matches(pkt))
    
if __name__ == '__main__':
    unittest.main()

