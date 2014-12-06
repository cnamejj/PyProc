#!/usr/bin/env python

"""Handle records from /proc/net/psched data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_psched(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{usec:08x} {ticks:08x} {unk:08x} {hrtime:08x}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(usec=__ff[PFC.F_NSEC_PER_USEC],
                ticks=__ff[PFC.F_PSCHED_TICKS],
                unk=__ff[PFC.F_UNKNOWN_FIELD],
                hrtime=__ff[PFC.F_NSEC_PER_HRTIME]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/psched")] = re_net_psched
