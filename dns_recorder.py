#!/usr/bin/env python3
"""dns_recorder.py"""

import socket
import dpkt
from utility import resolve_name
from host_info import Ipv4Address
from flow import DnsRequest


class DnsRecorder:
    """Class for recording and retrieving dns request records."""
    def __init__(self, localhost):
        self._cnames = {}
        self._domain_names = {}
        self._dns = {}
        self._localhost = localhost

    def dns_requests(self):
        """Return dict of id -> DnsRequest"""
        return self._dns

    def record(self, timestamp, packet):
        """Records the packet. Packet should be dpkt.ip.IP packet."""
        dns = dpkt.dns.DNS(packet.data.data)
        if dns.id not in self._dns:
            new_dns = DnsRequest(timestamp, packet)
            self._dns[new_dns.dns_id()] = new_dns
        else:
            self._dns[dns.id].add_packet(timestamp, packet)
        for ans in dns.an:
            if ans.type == dpkt.dns.DNS_CNAME:
                self._record_cname(ans)
            if ans.type == dpkt.dns.DNS_A:
                self._record_a(ans)

    def _get_cname(self, name_set):
        """Return the set of cnames for the given names"""
        result = set()
        for name in name_set:
            if name in self._cnames:
                result.update(self._cnames[name])
                result.update(self._get_cname(self._cnames[name]))
        return result

    def get_domain_name(self, ip_addr, port, localhost=False):
        """Return the domain name of the host."""
        hostnames = set()
        if ip_addr in self._domain_names:
            current = self._domain_names[ip_addr]
            hostnames.add(current)
            hostnames.update(self._get_cname(set([current])))
        hostnames.add(resolve_name(str(ip_addr), port))
        if localhost:
            hostnames.add('localhost')
        return hostnames

    def _record_cname(self, ans):
        if ans.cname in self._cnames:
            self._cnames[ans.cname].add(ans.name)
        else:
            self._cnames[ans.cname] = set()
            self._cnames[ans.cname].add(ans.name)

    def _record_a(self, ans):
        addr = Ipv4Address(socket.inet_ntoa(ans.rdata))
        self._domain_names[addr] = ans.name
