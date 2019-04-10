#!/usr/bin/env python3

import ipaddress
import scapy.all as scapy

"""A single match criteria for a firewall rule"""
class Match:
    """Protcol name, field name, and value to match"""
    def __init__(self, protocol, field, value):
        # Verify match criteria is valid
        assert(protocol in ["IP", "TCP", "UDP", "DNS"])
        if (protocol != "DNS"):
            assert(field in ["src", "dst"])
        else:
            assert (field == "query")
        # Store match criteria
        self._protocol = protocol
        self._field = field
        self._value = value

    """Check if a packet satisfies the match criteria"""
    def matches(self, pkt):
        # TODO

        return False

    """Create string representation of match criteria"""
    def __str__(self):
        return ("%s.%s=%s" % (self._protocol, self._field, str(self._value)))

# IP src specific IPv4 address or IPv4 network address
# IP dst specific IPv4 address or IPv4 network address
# TCP src specific port number
# TCP dst specific port number
# UDP src specific port number
# UDP dst specific port number
# DNS query specific hostname

"""A single firewall rule"""
class Rule:
    """Initialize with criteria and whether to permit matching packets"""
    def __init__(self, criteria=[], permit=False):
        self._criteria = criteria
        self._permit = permit

    """Check if packet matches all criteria"""
    def matches(self, pkt):
        # TODO

        return False

    """ Create string representation of rule"""
    def __str__(self):
        return ("%s\t%s" % 
                (("permit" if self._permit else "deny"),
                " & ".join([str(c) for c in self._criteria])))

"""A firewall"""
class Firewall:
    """Initialize with rules"""
    def __init__(self, rules, permit=False):
        self._rules = rules
        self._default = permit

    """Check if a packet is permitted"""
    def permitted(self, pkt):
        # TODO

        return False

    """Create string representation of firewall"""
    def __str__(self):
        return "\n".join([str(r) for r in self._rules])


