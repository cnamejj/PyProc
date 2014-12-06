#!/usr/bin/env python

"""Handle records from /proc/vmallocinfo data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_root_vmallocinfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "0x{st:016x}-0x{en:016x} {size:7d}{caller:s}{pages:s}\
{phys:s}{ioremap:s}{vmalloc:s}{vmmap:s}{usermap:s}{vpages:s}{numa:s}"

    __callertemp = " {caller:s}"
    __pagestemp = " pages={pages:x}"
    __phystemp = " phys={phys:x}"
    __ioremaptemp = " ioremap"
    __vmalloctemp = " vmalloc"
    __vmmaptemp = " vmap"
    __usermaptemp = " user"
    __vpagestemp = " vpages"
    __numatemp = " {numa:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        if __ff[PFC.F_CALLER] == "":
            __caller = ""
        else:
            __caller = __callertemp.format(caller=__ff[PFC.F_CALLER])

        if __ff[PFC.F_PAGES] == 0:
            __pages = ""
        else:
            __pages = __pagestemp.format(pages=__ff[PFC.F_PAGES])

        if __ff[PFC.F_PHYS_ADDR] == 0:
            __phys = ""
        else:
            __phys = __phystemp.format(phys=__ff[PFC.F_PHYS_ADDR])

        if __ff[PFC.F_IOREMAP] == 0:
            __ioremap = ""
        else:
            __ioremap = __ioremaptemp

        if __ff[PFC.F_VM_ALLOC] == 0:
            __vmalloc = ""
        else:
            __vmalloc = __vmalloctemp

        if __ff[PFC.F_VM_MAP] == 0:
            __vmmap = ""
        else:
            __vmmap = __vmmaptemp

        if __ff[PFC.F_USER_MAP] == 0:
            __usermap = ""
        else:
            __usermap = __usermaptemp

        if __ff[PFC.F_VM_PAGES] == 0:
            __vpages = ""
        else:
            __vpages = __vpagestemp

        if __ff[PFC.F_NUMA_INFO] == "":
            __numa = ""
        else:
            __numa = __numatemp.format(numa=__ff[PFC.F_NUMA_INFO])

        print __template.format(st=__ff[PFC.F_START], en=__ff[PFC.F_END],
                size=__ff[PFC.F_SIZE], caller=__caller, pages=__pages,
                phys=__phys, ioremap=__ioremap, vmalloc=__vmalloc,
                vmmap=__vmmap, usermap=__usermap, vpages=__vpages, numa=__numa)

# pylint: enable=R0914

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/vmallocinfo")] = re_root_vmallocinfo
