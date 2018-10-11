#!/usr/bin/env python3
"""HostInfo class."""

from utility import resolve_name
from ipv4_address import Ipv4Address


class HostInfo:
    """
    Class representing information about a single host.
    """

    def __init__(self, dns_recorder=None, packet=None,
                 src=True, localhost=None, **info):
        """
        packet:
            dpkt.ip.IP packet to scrape info from.
            If this value is None, then ip_addr, port, hostname
            are used instead.
        src:
            True if info should be drawn from src host, else dst host.
            Only used if packet is not None.
        original_names:
            set of dns names for the host
        localhost:
            str of the localhost address.
        info: dict containing info if packet is None
            "ip_addr": ip address of host (str or bytes representation)
            "port": port of host (int)
            "hostname": hostname of host (str)
        """
        if packet is not None:
            self._ip_addr = Ipv4Address(packet.src if src else packet.dst)
            self._port = packet.data.sport if src else packet.data.dport
            self._hostname = resolve_name(str(self._ip_addr), self._port)
        else:
            self._ip_addr = Ipv4Address(info["ip_addr"])
            self._port = info["port"]
            self._hostname = info["hostname"]
        self._localhost = False
        if localhost is not None:
            self._localhost = str(self._ip_addr) == localhost
        if dns_recorder is not None:
            self._original_names = dns_recorder.get_domain_name(
                ip_addr=self._ip_addr, port=self._port, localhost=self._localhost)
        else:
            self._original_names = set()

    def __str__(self):
        return "{}:{} ({}/{})".format(self._ip_addr, self._port,
                                      self._hostname, self._original_names)

    def __eq__(self, other):
        return self._ip_addr == other.ip_addr() and self._port == other.port()

    def is_localhost(self):
        """Return whether or not this host is the localhost"""
        return self._localhost

    def ip_addr(self):
        """Return the ip address of the host."""
        return self._ip_addr

    def port(self):
        """Returns the port of the host."""
        return self._port

    def hostname(self):
        """Returns the hostname of the host."""
        return self._hostname

    def original_names(self):
        """Return the original dns names of the host."""
        return self._original_names

    def description(self):
        """
        Return an identifying string for the host.
        Consists of ip address followed by port.
        """
        return str(self._ip_addr) + str(self._port)
