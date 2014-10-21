#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

import ProcHandlers as PH
import sys

# ---

HANDLER = PH.GET_HANDLER

RECREATOR = dict()

__all__ = ["net_tcp", "net_udp", "net_tcp6", "net_udp6"]
