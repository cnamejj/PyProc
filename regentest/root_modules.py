#!/usr/bin/env python

"""Handle records from /proc/modules data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_modules(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __taintstemp = " {taints:s}"

    __template = "{mod:s} {sz:d} {refc:d} {src:s} {stat:s} \
0x{mcore:016x}{taints:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __taints = __ff[PFC.F_TAINTS]
        if __taints != "":
            __taints = __taintstemp.format(taints=__taints)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(mod=__ff[PFC.F_MODULE], sz=__ff[PFC.F_SIZE],
                refc=__ff[PFC.F_REFCOUNT], src=__ff[PFC.F_SOURCE_LIST],
                stat=__ff[PFC.F_STATUS], mcore=__ff[PFC.F_MODULE_CORE],
                taints=__taints
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/modules")] = re_root_modules
