#!/usr/bin/env python3
"""flow_sorter.py"""

import dpkt
from flow import Flow, FlowId
from host_info import HostInfo
from dns_recorder import DnsRecorder


class FlowSorter:
    """Class for sorting packets into flows."""

    def __init__(self, localhost=None):
        self._flows = {}
        self._dns_recorder = DnsRecorder(localhost=localhost)
        self._localhost = localhost

    def __iter__(self):
        return iter(self._flows.items())

    def sort(self, reader):
        """Read in the packets from the Reader and sort them info flows."""
        for timestamp, pkt in reader:
            success, ip_packet = FlowSorter._get_ip_packet(pkt)
            if not success:
                print("Failed to parse packet")
                continue
            if not FlowSorter._is_tcp(ip_packet) and not\
                    FlowSorter._is_udp(ip_packet):
                print("IP Packet is not tcp or udp. Skipping...")
                continue
            if FlowSorter._is_dns(ip_packet):
                self._dns_recorder.record(timestamp, ip_packet)
            else:
                if not FlowSorter._is_tcp(ip_packet):
                    print("Non DNS Packet is not TCP. Skipping...")
                    continue
                self._sort_tcp_packet(timestamp, ip_packet)

    def flows(self):
        """Return a dict of FlowId -> Flow objects."""
        return self._flows

    def dns_requests(self):
        """Return dict of id -> DnsRequest"""
        return self._dns_recorder.dns_requests()

    def _sort_tcp_packet(self, timestamp, packet):
        """Puts the dpkt.ip.IP tcp packet into the correct flow."""
        src_host = HostInfo(packet=packet, dns_recorder=self._dns_recorder,
                            src=True, localhost=self._localhost)
        dst_host = HostInfo(packet=packet, dns_recorder=self._dns_recorder,
                            src=False, localhost=self._localhost)
        flow_id = FlowId(src_host=src_host, dst_host=dst_host)
        if flow_id in self._flows:
            self._flows[flow_id].add_packet(timestamp, packet)
        else:
            self._flows[flow_id] = Flow(flow_id=flow_id)
            self._flows[flow_id].add_packet(timestamp, packet)

    @staticmethod
    def _is_tcp(packet):
        """Returns whether the dpkt.ip.IP packet contains a TCP frame."""
        return isinstance(packet.data, dpkt.tcp.TCP)

    @staticmethod
    def _is_udp(packet):
        """Returns whether the dpkt.ip.IP packet contains a UDP frame."""
        return isinstance(packet.data, dpkt.udp.UDP)

    @staticmethod
    def _is_dns(packet):
        """Return if the IP packet is a dns packet."""
        return packet.data.sport == 53 or packet.data.dport == 53

    @staticmethod
    def _get_ip_packet(packet):
        """Return a dpkt.ip.IP object from raw packet."""
        try:
            ethernet = dpkt.ethernet.Ethernet(packet)
        except dpkt.dpkt.UnpackError as err:
            print("ERROR PARSING ETHERNET PACKET: {}".format(err))
            return False, None
        if isinstance(ethernet.data, dpkt.ip.IP):
            return True, ethernet.data
        else:
            try:
                return True, dpkt.ip.IP(packet)
            except dpkt.dpkt.UnpackError as err:
                print("ERROR PARSING IP PACKET: {}".format(err))
                return False, None
