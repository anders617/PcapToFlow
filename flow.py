#!/usr/bin/env python3
"""Flow class."""

import numpy as np
import dpkt
from host_info import HostInfo


class PacketContainer:
    """Class representing a collection of packets, ordered by timestamp."""

    def __init__(self):
        self._packets = []
        self._timestamps = []
        self._total_message_bytes = 0
        self._total_bytes = 0
        self._inter_arrival_times = []

    def __iter__(self):
        return zip(self._timestamps, self._packets)

    def __len__(self):
        return len(self._timestamps)

    def add_packet(self, timestamp, packet):
        """Add a packet to the Flow object."""
        self._total_message_bytes += len(packet.data.data)
        self._total_bytes += len(packet)
        if self._packets:
            self._inter_arrival_times.append(timestamp - self._timestamps[-1])
        self._timestamps.append(timestamp)
        self._packets.append(packet)

    def packets(self):
        """Return a numpy.array containing packets."""
        return np.array(self._packets)

    def first_timestamp(self):
        """Return the first timestamp in the container."""
        return self._timestamps[0]

    def timestamps(self):
        """Return a numpy.array containing timestamps."""
        return np.array(self._timestamps)

    def inter_arrival_times(self):
        """Return a numpy.array containing inter arrival times."""
        return np.array(self._inter_arrival_times)

    def total_message_bytes(self):
        """Return the total number of bytes excluding headers."""
        return self._total_message_bytes

    def total_bytes(self):
        """Return the total number of bytes including headers."""
        return self._total_bytes


class FlowId:
    """Class identifying a TCP/UDP flow."""
    def __init__(self, src_host, dst_host):
        super().__init__()
        self._src_host = src_host
        self._dst_host = dst_host

    def __str__(self):
        return "({}) -> ({})".format(self._src_host, self._dst_host)

    def __eq__(self, other):
        return self._src_host == other.src_host() and\
            self._dst_host == other.dst_host()

    def __hash__(self):
        return hash(self.description())

    def src_host(self):
        """Return src HostInfo object."""
        return self._src_host

    def dst_host(self):
        """Return dst HostInfo object."""
        return self._dst_host

    def non_localhost(self):
        """Return the remote host."""
        if self._src_host.is_localhost():
            return self._dst_host
        return self._src_host

    def reversed(self):
        """Return the FlowId going in the opposite direction."""
        return FlowId(src_host=self._dst_host, dst_host=self._src_host)

    def description(self):
        """Return a str description of the Flow."""
        return self._src_host.description() + self._dst_host.description()


class Flow(PacketContainer):
    """Class representing a TCP/UDP flow."""

    def __init__(self, flow_id):
        super().__init__()
        self._flow_id = flow_id

    def __str__(self):
        return str(self._flow_id)

    def __eq__(self, other):
        return self._flow_id == other.flow_id()

    def __hash__(self):
        return hash(self._flow_id)

    def flow_id(self):
        """Return the FlowId that identifies this flow."""
        return self._flow_id

    def is_localhost_src(self):
        """Return whether the src is the localhost"""
        return self._flow_id.src_host().is_localhost()

    def is_localhost_dst(self):
        """Return whether the destination is the localhost"""
        return self._flow_id.dst_host().is_localhost()

    def src_host(self):
        """Return src HostInfo object."""
        return self._flow_id.src_host()

    def dst_host(self):
        """Return dst HostInfo object."""
        return self._flow_id.dst_host()


class DnsRequest(PacketContainer):
    """Represents a DNS Request"""

    def __init__(self, timestamp, request_packet):
        super().__init__()
        dns = dpkt.dns.DNS(request_packet.data.data)
        self._remote_host = HostInfo(packet=request_packet, src=False)
        self._dns_questions = dns.qd
        self._dns_answers = []
        self._id = dns.id
        self.add_packet(timestamp, request_packet)

    def answers(self):
        """Return the answers to the dns query."""
        return self._dns_answers

    def questions(self):
        """Return the questions of the dns query."""
        return self._dns_questions

    def remote_host(self):
        """Returns HostInfo about the remote host."""
        return self._remote_host

    def dns_id(self):
        """Return the id of the dns request."""
        return self._id

    def matches(self, answer_packet):
        """Return whether the answer packet matches the question packet."""
        dns = dpkt.dns.DNS(answer_packet.data.data)
        return self._id == dns.id

    def add_packet(self, timestamp, packet):
        """Add packet to the DnsRequest object."""
        if not self.matches(packet):
            raise RuntimeError('answer id does not match question id')
        dns = dpkt.dns.DNS(packet.data.data)
        self._dns_answers = dns.an
        super().add_packet(timestamp, packet)
