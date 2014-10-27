#!/usr/bin/env python

"""Handle records from /proc/swaps data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_swaps(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __is_file = "file"

    __head = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority"

    __typetemp = "{typ:s}\t"
    __template = "{name:<40s}{typ:s}\t{size:d}\t{used:d}\t{prior:d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        __st = __ff[PFC.F_TYPE]
        if __st == __is_file:
            __st = __typetemp.format(typ=__st)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(name=__ff[PFC.F_FILENAME], typ=__st,
                size=__ff[PFC.F_SIZE], used=__ff[PFC.F_USED], 
                prior=__ff[PFC.F_PRIORITY]
                )
    
RG.RECREATOR[PH.GET_HANDLER("/proc/swaps")] = re_root_swaps
