#!/usr/bin/env python

"""Handle records from /proc/net/ip_tables_targets data files"""

import regentest as RG
import ProcHandlers as PH

# ---

def re_net_ip_tables_targets(inprecs):

    """Iterate through parsed records and re-generate data file"""

    RG.list_of_terms(inprecs)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/ip_tables_targets")] = \
        re_net_ip_tables_targets
