#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

# ---

RECREATOR = dict()

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

__all__ = ["net_tcp", "net_udp", "net_tcp6", "net_udp6", "net_unix",
    "net_connector", "net_netlink", "net_protocols", "net_dev",
    "net_softnet_stat", "net_ptype", "net_dev_mcast", "net_psched", "net_arp",
    "net_route", "net_rt_cache", "net_igmp", "net_sockstat"]
