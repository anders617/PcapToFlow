#!/usr/bin/env python3
"""Utility functions for PcapToFlows."""

import socket


def resolve_name(ip_address, port):
    """Returns the hostname of the ip address and port combo."""
    return ip_address
    # return socket.getnameinfo((ip_address, port), 0)
