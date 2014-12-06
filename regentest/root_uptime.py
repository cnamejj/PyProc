#!/usr/bin/env python

"""Handle records from /proc/uptime data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_uptime(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{upt:.2f} {idle:.2f}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(upt=__ff[PFC.F_UPTIME], idle=__ff[PFC.F_IDLE])

RG.RECREATOR[PH.GET_HANDLER("/proc/uptime")] = re_root_uptime
