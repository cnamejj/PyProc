#!/usr/bin/env python

"""Handle records from /proc/self/oom_score data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_oom_score(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{oom:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(oom=__ff[PFC.F_OOM_SCORE])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/oom_score")] = re_self_oom_score

