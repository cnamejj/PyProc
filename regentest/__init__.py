#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

# ---

RECREATOR = dict()

__all__ = ["net_tcp", "net_udp", "net_tcp6", "net_udp6", "net_unix", "net_connector"]
