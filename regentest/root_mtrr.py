#!/usr/bin/env python

"""Handle records from /proc/mtrr data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_mtrr(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __kb = 1024
    __mb = 1024 * 1024

    __template = "reg{idx:02d}: base=0x{base:09x} ({basemb:5d}MB), \
size={sz:5d}{sc:s}B, count={count:d}: {typ:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __base = __ff[PFC.F_BASE_MEMORY]
        __basemb = __base / 1024 / 1024

        __size = __ff[PFC.F_SIZE]
        if __size >= __mb:
            __size /= __mb
            __scale = "M"
        else:
            __size /= __kb
            __scale = "K"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(idx=__ff[PFC.F_INDEX], base=__base,
                basemb=__basemb, sz=__size, sc=__scale,
                count=__ff[PFC.F_COUNT], typ=__ff[PFC.F_TYPE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/mtrr")] = re_root_mtrr
