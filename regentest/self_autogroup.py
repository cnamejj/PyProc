#!/usr/bin/env python

"""Handle records from /proc/self/autogroup data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_autogroup(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "/autogroup-{id:d} nice {nice:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(id=__ff[PFC.F_ID], nice=__ff[PFC.F_NICE])
    
RG.RECREATOR[PH.GET_HANDLER("/proc/self/autogroup")] = re_self_autogroup
