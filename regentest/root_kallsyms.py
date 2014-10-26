#!/usr/bin/env python

"""Handle records from /proc/kallsyms data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_kallsyms(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __modtemp = "\t[{mod:s}]"

    __template = "{addr:016x} {typ:s} {sym:s}{mod:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __mod = __ff[PFC.F_MODULE]
        if __mod != "":
            __mod = __modtemp.format(mod=__mod)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(mod=__mod, addr=__ff[PFC.F_ADDRESS],
               typ=__ff[PFC.F_TYPE], sym=__ff[PFC.F_SYMBOL]
               )

RG.RECREATOR[PH.GET_HANDLER("/proc/kallsyms")] = re_root_kallsyms
