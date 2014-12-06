#!/usr/bin/env python

"""Handle records from /proc/self/numa_maps data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_self_numa_maps(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{addr:08x} {buff:s}{path:s}{huge:s}{nvplist:s}{nodelist:s}"

    __pathtemp = " file={path:s}"
    __heap = " heap"
    __stack = " stack"
    __huge = " huge"

    __label = { PFC.F_ANON: 'anon', PFC.F_DIRTY: 'dirty',
            PFC.F_MAPPED: 'mapped', PFC.F_MAPMAX: 'mapmax',
            PFC.F_SWAPCACHE: 'swapcache', PFC.F_ACTIVE_PAGES: 'active',
            PFC.F_WRITEBACK: 'writeback' }

    __floattemp = "{acc:s} {name:s}={val:d}"
    __nodestemp = "{acc:s} N{nodenum:s}={nodeval:s}"

    for __hilit in inprecs:
        __ff = inprecs.field
        __path = ""
        __is_huge = ""

        if __ff[PFC.F_FILEPATH] != "":
            __path = __pathtemp.format(path=__ff[PFC.F_FILEPATH])

        elif __ff[PFC.F_HEAP] == 1:
            __path = __heap

        elif __ff[PFC.F_STACK] == 1:
            __path = __stack

        if __ff[PFC.F_HUGE] == 1:
            __is_huge = __huge

        __float = ""
        for __seq in range(0, len(inprecs.floating_hits)):
            __key = inprecs.floating_hits[__seq]
            if __key != PFC.F_FILEPATH:
                __float = __floattemp.format(acc=__float, name=__label[__key],
                        val=__ff[__key])

        __nodes = ""
        for __seq in __ff[PFC.F_NODE_ORDER]:
            __nodenum = __ff[PFC.F_NODE_ORDER][__seq]
            __nodes = __nodestemp.format(acc=__nodes, nodenum=__nodenum,
                    nodeval=__ff[PFC.F_NODE_LIST][__nodenum])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(addr=__ff[PFC.F_START], \
            buff=__ff[PFC.F_BUFFNAME], path=__path, huge=__is_huge,
            nvplist=__float, nodelist=__nodes)

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/self/numa_maps")] = re_self_numa_maps

