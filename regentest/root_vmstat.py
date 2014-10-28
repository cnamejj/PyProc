#!/usr/bin/env python

"""Handle records from /proc/vmstat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_vmstat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{cat:s} {count:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(cat=__ff[PFC.F_CATEGORY],
                count=__ff[PFC.F_COUNT])
    
RG.RECREATOR[PH.GET_HANDLER("/proc/vmstat")] = re_root_vmstat
