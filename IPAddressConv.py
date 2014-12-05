#!/usr/bin/env python
"""Routines to convert IP addresses to/from various formats"""

import socket
import struct

ANY_IPV6_ADDR = "::"
PRESENT_ANY_IPV6_ADDR = "::0"

def ipv6_hexdelim_to_pres(hexdelim):
    """
    Convert a text IPv6 address in hex delimited chunks to
    standard presentation format.
    """

    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6,
               hexdelim))

def ipv6_hexstring_to_presentation(hexip):
    """
    Convert an IPv6 address, expressed as a string of hex digits, into
    the standard text presentation format.  See file /proc/net/if_net6
    for an example of where that format is used.
    """

    __delim = ipv6_hexstring_to_hexdelimited(hexip)
    __pres = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(
            socket.AF_INET6, __delim))
    if __pres == ANY_IPV6_ADDR:
        __pres = PRESENT_ANY_IPV6_ADDR
    return __pres

def ipv6_hexstring_to_hexdelimited(hexip):
    """
    Take a string of hex digits and reformat with standard IPv6
    delimiters between the chunks, which is the format routines
    that interpret text versions of IPv6 addresses will accept.
    """

    __delim_ipv6 = ":"
    __delim = ""
    __sep = ""

    for __off in range(0, 4):
        __delim = "{partial}{sep}".format(partial=__delim, sep=__sep)
        __sep = __delim_ipv6

        __chunk = int(hexip[__off*8: (__off+1) * 8], 16)
        __unpacked = struct.unpack("!L", struct.pack("=L", __chunk))[0]
        __net_hex = '{0:08x}'.format(__unpacked)
        __delim = "{partial}{chunk1}{separator}{chunk2}".format(
                      partial=__delim, chunk1=__net_hex[0:4],
                      separator=__delim_ipv6, chunk2=__net_hex[4:8])

    return __delim



if __name__ == "__main__":

    print "Collection of routines to convert IP addr's to/from various formats"
