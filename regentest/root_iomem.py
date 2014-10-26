#!/usr/bin/env python

"""Handle records from /proc/iomem data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_iomem(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{pref:s}{st:08x}-{en:08x} : {mdesc:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __lev = __ff[PFC.F_LEVEL]
        if __lev > 0:
            __pref = "  " * __lev
        else:
            __pref = ""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(pref=__pref, st=__ff[PFC.F_START],
               en=__ff[PFC.F_END], mdesc=__ff[PFC.F_MEM_DESC])

RG.RECREATOR[PH.GET_HANDLER("/proc/iomem")] = re_root_iomem
