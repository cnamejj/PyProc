#!/usr/bin/env python

"""Handle records from /proc/buddyinfo data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_buddyinfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __frl = ( PFC.F_FRBL_AREA_1, PFC.F_FRBL_AREA_2, PFC.F_FRBL_AREA_3,
            PFC.F_FRBL_AREA_4, PFC.F_FRBL_AREA_5, PFC.F_FRBL_AREA_6,
            PFC.F_FRBL_AREA_7, PFC.F_FRBL_AREA_8, PFC.F_FRBL_AREA_9,
            PFC.F_FRBL_AREA_10, PFC.F_FRBL_AREA_11 )

    __leadtemp = "Node {node:d}, zone {zone:>8s} "

    __entrytemp = "{agg:s}{frbl:>6s} "

    __template = "{line:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __out = __leadtemp.format(node=__ff[PFC.F_NODE], zone=__ff[PFC.F_ZONE])

        for __key in __frl:
            __out = __entrytemp.format(agg=__out, frbl=__ff[__key])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __out


RG.RECREATOR[PH.GET_HANDLER("/proc/buddyinfo")] = re_root_buddyinfo
