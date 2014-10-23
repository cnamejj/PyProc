#!/usr/bin/env python

"""Handler records from /proc/net/igmp6 data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_igmp6(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{idx:<4d} {dev:<15s} {mcax:6s} {mcus:5d} {flags:08X} {tex:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(idx=__ff[PFC.F_INT_INDEX], 
                dev=__ff[PFC.F_DEVICE], mcax=__ff[PFC.F_MCAST_ADDR_HEX], 
                mcus=__ff[PFC.F_MCAST_USERS], flags=__ff[PFC.F_MCAST_FLAGS], 
                tex=__ff[PFC.F_TIMER_EXPIRE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/igmp6")] = re_net_igmp6
