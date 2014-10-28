#!/usr/bin/env python

"""Handle records from /proc/self/schedstat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_schedstat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{rtime:d} {rqueue:d} {rslice:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(rtime=__ff[PFC.F_RUN_TIME],
                rqueue=__ff[PFC.F_RUNQUEUE_TIME],
                rslice=__ff[PFC.F_RUN_TIMESLICES]
                )
    
RG.RECREATOR[PH.GET_HANDLER("/proc/self/schedstat")] = re_self_schedstat

