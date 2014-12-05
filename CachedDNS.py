#!/usr/bin/env python
"""DNS lookup with cache"""

import socket

class LookupIP(object):
    """
    Map IP's to hostnames using local cache where possible, using DNS lookups
    otherwise
    """

    def __init__(self):

        self.__def_hostname = "-unknown-"
        self.__hostname_cache = dict()
        self.__hostname_cache["0.0.0.0"] = self.__def_hostname


    def get_cached_hostname(self, ip_addr):
        """Return the hostname associated with the given IP address."""

        if ip_addr in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip_addr]
        else:
            try:
                (__ip2host, __ip2alias, __ip2iplist) = socket.gethostbyaddr(
                                                           ip_addr)
            except (socket.error, socket.herror, socket.timeout):
                __ip2host = ""

            if __ip2host == "":
                __ip2host = self.__def_hostname
            self.__hostname_cache[ip_addr] = __ip2host

        return __ip2host

    def get_cache_entry(self, ip_addr):
        """Return the cache entry for the given IP address."""

        if ip_addr in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip_addr]
        else:
            __ip2host = self.__def_hostname

        return __ip2host

    def flush_cache(self):
        """Discard the current cache of names/IP's"""

        self.__hostname_cache = dict()
        self.__hostname_cache["0.0.0.0"] = self.__def_hostname

    def get_cache_list(self):
        """Return a copy of the cached names/IP's"""

        return self.__hostname_cache



if __name__ == "__main__":
    print "This is a collection of routines to perform DNS lookups"
