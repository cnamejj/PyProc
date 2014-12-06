#!/usr/bin/env python

"""Handle records from /proc/self/comm data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_comm(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{comm:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(comm=__ff[PFC.F_COMM])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/comm")] = re_self_comm
