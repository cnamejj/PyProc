#!/usr/bin/env python

"""Handle records from /proc/execdomains data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_execdomains(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{low:d}-{hi:d}\t{name:<16s}\t{mod:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(low=__ff[PFC.F_PERSONALITY_LOW],
                hi=__ff[PFC.F_PERSONALITY_HIGH], name=__ff[PFC.F_EXDOM_NAME],
                mod=__ff[PFC.F_EXDOM_MODULE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/execdomains")] = re_root_execdomains
