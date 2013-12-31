#!/usr/bin/env python
"""Constants used as 'no value' or other placeholders in several modules, also network state mapping array, no code here"""

unknown_state = "UNRECOGNIZED"

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

state_list = dict()
state_list["01"] = "ESTABLISHED"
state_list["02"] = "SYN_SENT"
state_list["03"] = "SYN_RECV"
state_list["04"] = "FIN_WAIT1"
state_list["05"] = "FIN_WAIT2"
state_list["06"] = "TIME_WAIT"
state_list["07"] = "CLOSE"
state_list["08"] = "CLOSE_WAIT"
state_list["09"] = "LACK_ACK"
state_list["0A"] = "LISTEN"
state_list["0B"] = "CLOSING"
