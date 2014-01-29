#!/usr/bin/env python
"""DNS lookup with cache"""

import socket

class CachedDNS:
    """Map IP's to hostnames using local cache where possible, using lookups otherwise"""

    def __init__(self):

        self.__DEF_HOSTNAME = "-unknown-"
        self.__hostname_cache = dict()
        self.__hostname_cache["0.0.0.0"] = self.__DEF_HOSTNAME


    def get_cached_hostname(self, ip):

        if ip in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip]
        else:
            try:
                (__ip2host, __ip2alias, __ip2iplist) = socket.gethostbyaddr( ip)
            except (socket.error, socket.herror, socket.timeout):
                __ip2host = ""

            if __ip2host == "":
                __ip2host = self.__DEF_HOSTNAME
            self.__hostname_cache[ip] = __ip2host

        return __ip2host

    def get_cache_entry(self, ip):

        if ip in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip]
        else:
            __ip2host = self.__DEF_HOSTNAME

        return __ip2host

    def flush_cache(self):

        self.__hostname_cache = dict()
        self.__hostname_cache["0.0.0.0"] = self.__DEF_HOSTNAME

    def get_cache_list(self):

        return( self.__hostname_cache)



if __name__ == "__main__":
    print "This is a collection of routines to perform DNS lookups"