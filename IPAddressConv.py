#!/usr/bin/env python
"""Routines to convert IP addresses to/from various formats

Describe what's in this module and put that info here...
"""

import socket
import struct

ANY_IPV6_ADDR = "::"
PRESENT_ANY_IPV6_ADDR = "::0"

def ipv6_hexdelimited_to_presentation(hexdelim):
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, hexdelim))

class IPAddressConv:
    """Utlities for converting IP address to/from various formats."""

    def __init__(self):
        self.__DelimIPV6 = ":"

    def ipv6_hexstring_to_presentation(self, hexip):
        __delim = ""
        __sep = ""

        for __off in range( 0, 4):
            __delim = __delim + __sep
            __sep = self.__DelimIPV6

            __chunk = hexip[ __off * 8: (__off + 1) * 8 ]
            __net_hex = '{0:08x}'.format(struct.unpack("!L", struct.pack("=L", int(__chunk, 16)))[0])
            __delim = __delim + __net_hex[0:4] + self.__DelimIPV6 + __net_hex[4:8]

        __pres = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, __delim))
        if __pres == ANY_IPV6_ADDR:
            __pres = PRESENT_ANY_IPV6_ADDR
        return __pres

    def ipv6_hexstring_to_hexdelimited(self, hexip):
        __delim = ""
        __sep = ""

        for __off in range( 0, 4):
            __delim = __delim + __sep
            __sep = self.__DelimIPV6

            __chunk = hexip[ __off * 8: (__off + 1) * 8 ]
            __net_hex = '{0:08x}'.format(struct.unpack("!L", struct.pack("=L", int(__chunk, 16)))[0])
            __delim = __delim + __net_hex[0:4] + self.__DelimIPV6 + __net_hex[4:8]

        return __delim
