#!/usr/bin/env python

"""Handle records from /proc/ioports data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_ioports(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{pref:s}{st:04x}-{en:04x} : {pname:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __lev = __ff[PFC.F_LEVEL]
        if __lev > 0:
            __pref = "  " * __lev
        else:
            __pref = ""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(pref=__pref, st=__ff[PFC.F_START],
               en=__ff[PFC.F_END], pname=__ff[PFC.F_PORT_NAME])

RG.RECREATOR[PH.GET_HANDLER("/proc/ioports")] = re_root_ioports
