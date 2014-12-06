#!/usr/bin/env python

"""Handle records from /proc/self/coredump_filter data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_core_filter(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{cdf:08x}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(cdf=__ff[PFC.F_COREDUMP_FILTER])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/coredump_filter")] = re_self_core_filter
