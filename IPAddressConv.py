#!/usr/bin/env python
"""Routines to convert IP addresses to/from various formats"""

import socket
import struct

ANY_IPV6_ADDR = "::"
PRESENT_ANY_IPV6_ADDR = "::0"

def ipv6_hexdelimited_to_presentation(hexdelim):
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, hexdelim))

def ipv6_hexstring_to_presentation( hexip):
    __delim = ipv6_hexstring_to_hexdelimited( hexip)
    __pres = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, __delim))
    if __pres == ANY_IPV6_ADDR:
        __pres = PRESENT_ANY_IPV6_ADDR
    return __pres

def ipv6_hexstring_to_hexdelimited( hexip):
    __delimIPV6 = ":"
    __delim = ""
    __sep = ""

    for __off in range( 0, 4):
        __delim = "{partial}{separator}".format(partial=__delim, separator=__sep)
        __sep = __delimIPV6

        __chunk = hexip[ __off * 8: (__off + 1) * 8 ]
        __net_hex = '{0:08x}'.format(struct.unpack("!L", struct.pack("=L", int(__chunk, 16)))[0])
        __delim = "{partial}{chunk1}{separator}{chunk2}".format(partial=__delim, chunk1=__net_hex[0:4], separator=__delimIPV6, chunk2=__net_hex[4:8])

    return __delim



if __name__ == "__main__":

    print "This is collection of routines to convert IP addresses to/from various formats"
