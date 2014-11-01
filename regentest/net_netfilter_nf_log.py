#!/usr/bin/env python

"""Handle records from /proc/net/netfilter/nf_log data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_netfilter_nf_log(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __no_name = "NONE"

    __template = "{idx:2d} {name:s} ({loglist:s})"

    for __hilit in inprecs:
        __ff = inprecs.field

        __name = __ff[PFC.F_NAME]
        if __name == "":
            __name = __no_name

        print __template.format(idx=__ff[PFC.F_INDEX], name=__name,
                loglist=__ff[PFC.F_LOGGER_LIST])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/netfilter/nf_log")] = \
        re_net_netfilter_nf_log
