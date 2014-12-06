#!/usr/bin/env python

"""Handle records from /proc/self/maps data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_maps(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __leadtemp = "{st:08x}-{en:08x} {fl:4s} {offset:08x} \
{major:02x}:{minor:02x} {inode:d} "

    __ptr_size = 8
    __preflen = (__ptr_size * 6) + 25
    __preftemp = "{{pref:<{plen:d}s}}".format(plen=__preflen)

    __template = "{pref:s}{path:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        __lead = __leadtemp.format(st=__ff[PFC.F_START], en=__ff[PFC.F_END],
                fl=__ff[PFC.F_FLAGS], offset=__ff[PFC.F_PAGE_OFFSET],
                major=__ff[PFC.F_MAJOR_DEV], minor=__ff[PFC.F_MINOR_DEV],
                inode=__ff[PFC.F_INODE]
                )

        __path = __ff[PFC.F_PATH]
        if __path == "":
            print __lead
        else:
            __pref = __preftemp.format(pref=__lead)
            print __template.format(pref=__pref, path=__ff[PFC.F_PATH])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/maps")] = re_self_maps
