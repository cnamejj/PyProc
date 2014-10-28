#!/usr/bin/env python

"""Handle records from /proc/self/personality data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_personality(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{pers:08x}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(pers=__ff[PFC.F_PERSONALITY])
    
RG.RECREATOR[PH.GET_HANDLER("/proc/self/personality")] = re_self_personality

