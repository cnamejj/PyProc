#!/usr/bin/env python

"""Handle records from /proc/net/l2cap data files"""

import regentest as RG
import ProcHandlers as PH

# ---

def re_net_l2cap(inprecs):

    """Iterate through parsed records and re-generate data file"""

    RG.bluetooth_data_format(inprecs)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/l2cap")] = re_net_l2cap
