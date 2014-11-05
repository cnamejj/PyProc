#!/usr/bin/env python

"""Handle records from /proc/net/dev_snmp6/* data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_dev_snmp6(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{name:<32s}\t{val:s}"

    for __hilit in inprecs:
        __ff = inprecs.field
        __hits = __ff[PFC.F_HITS]

        for __seq in range(0, len(__hits)):
            __key = __hits[__seq]
            print __template.format(name=__key, val=__ff[__key])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/dev_snmp6")] = re_net_dev_snmp6


