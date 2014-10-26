#!/usr/bin/env python

"""Handle records from /proc/meminfo data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_meminfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __spec = "HardwareCorrupted:"

    __template = "{cat:<15s} {size:8d} {unit:s}"
    __spectemp = "{cat:<18s} {size:5d} {unit:s}"
    __alttemp = "{cat:<18s} {size:5d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        if __ff[PFC.F_CATEGORY] == __spec:
            print __spectemp.format(cat=__ff[PFC.F_CATEGORY],
                   size=__ff[PFC.F_SIZE], unit=__ff[PFC.F_UNITS])
        elif __ff[PFC.F_UNITS] != "":
            print __template.format(cat=__ff[PFC.F_CATEGORY],
                   size=__ff[PFC.F_SIZE], unit=__ff[PFC.F_UNITS])
        else:                   
            print __alttemp.format(cat=__ff[PFC.F_CATEGORY],
                   size=__ff[PFC.F_SIZE])

RG.RECREATOR[PH.GET_HANDLER("/proc/meminfo")] = re_root_meminfo
