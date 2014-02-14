#!/usr/bin/env python
"""
Constants used as 'no value' or other placeholders in several modules, also
network state mapping array.  There's no code here.
"""

try:
    import numpy
    NAN = numpy.nan
    INF = numpy.inf
except ImportError:
    import pickle
    NAN = pickle.loads('Fnan\n.')
    INF = pickle.loads('Finf\n.')

UNKNOWN_STATE = "UNRECOGNIZED"

ANY_HW_ADDR = "00:00:00:00:00:00"
ANY_INTERFACE = "any"
ANY_IPV6_ADDR = "::"
ANY_IP_ADDR = "0.0.0.0"
ANY_IP_ADDR_HEX = "00000000"
ANY_IPV6_ADDR_HEX = "00000000000000000000000000000000"
ANY_MASK_HEX = "FFFFFFFF"
NULL_MASK_HEX = "00000000"
PRESENT_ANY_IPV6_ADDR = "::0"
PRESENT_ANY_IP_ADDR = "0.0.0.0"
ANY_DEVICE = "any"
NO_DEVICE = "none"

STATE_LIST = dict()
STATE_LIST["01"] = "ESTABLISHED"
STATE_LIST["02"] = "SYN_SENT"
STATE_LIST["03"] = "SYN_RECV"
STATE_LIST["04"] = "FIN_WAIT1"
STATE_LIST["05"] = "FIN_WAIT2"
STATE_LIST["06"] = "TIME_WAIT"
STATE_LIST["07"] = "CLOSE"
STATE_LIST["08"] = "CLOSE_WAIT"
STATE_LIST["09"] = "LACK_ACK"
STATE_LIST["0A"] = "LISTEN"
STATE_LIST["0B"] = "CLOSING"
