#!/usr/bin/env python

"""Handle records from /proc/self/oom_score_adj data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_oom_score_adj(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{oom:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(oom=__ff[PFC.F_OOM_SCORE_ADJ])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/oom_score_adj")] = re_self_oom_score_adj

