#!/usr/bin/env python

"""Handle records from /proc/self/cpuset data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_cpuset(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{cpuset:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(cpuset=__ff[PFC.F_CPU_SET])
    
RG.RECREATOR[PH.GET_HANDLER("/proc/self/cpuset")] = re_self_cpuset
