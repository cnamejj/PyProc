#!/usr/bin/env python

"""Handle records from /proc/self/statm data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_statm(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{size:d} {resident:d} {shared:d} {text:d} 0 {data:d} 0"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(size=__ff[PFC.F_SIZE],
                resident=__ff[PFC.F_RESIDENT_SIZE],
                shared=__ff[PFC.F_SHARED_SIZE], text=__ff[PFC.F_TEXT_SIZE],
                data=__ff[PFC.F_DATA_SIZE])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/statm")] = re_self_statm

