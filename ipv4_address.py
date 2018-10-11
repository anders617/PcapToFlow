#!/usr/bin/env python3
"""ipv4_address.py"""


class Ipv4Address:
    """Class representing an ipv4 address."""

    def __init__(self, address):
        """Create Ipv4Address using either string or bytes object."""
        if isinstance(address, str):
            self._bytes = Ipv4Address.string_to_bytes(address)
            # Convert back to string to ensure correct format
            self._string = Ipv4Address.bytes_to_string(self._bytes)
        else:
            self._bytes = address
            self._string = Ipv4Address.bytes_to_string(address)

    def __str__(self):
        return self._string

    def __eq__(self, other):
        return self._bytes == other.bytes()

    def __hash__(self):
        return hash(self._string)

    @staticmethod
    def bytes_to_string(byte_address):
        """Converts bytes object to human readable ipv4 address."""
        return ".".join([format(c, "01d") for c in byte_address])

    @staticmethod
    def string_to_bytes(string_address):
        """Converts string to bytes object."""
        return bytes([int(c) for c in string_address.split(".")])

    def bytes(self):
        """Returns the ipv4 address as a bytes object."""
        return self._bytes
