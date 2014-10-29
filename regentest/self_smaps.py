#!/usr/bin/env python

"""Handle records from /proc/self/smaps data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_smaps(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __lab = dict()
    __lab[PFC.F_SIZE] = "Size:"
    __lab[PFC.F_RSS] = "Rss:"
    __lab[PFC.F_PSS] = "Pss:"
    __lab[PFC.F_SH_CLEAN] = "Shared_Clean:"
    __lab[PFC.F_SH_DIRTY] = "Shared_Dirty:"
    __lab[PFC.F_PR_CLEAN] = "Private_Clean:"
    __lab[PFC.F_PR_DIRTY] = "Private_Dirty:"
    __lab[PFC.F_REFERENCED] = "Referenced:"
    __lab[PFC.F_ANONYMOUS] = "Anonymous:"
    __lab[PFC.F_ANON_HUGE_PAGES] = "AnonHugePages:"
    __lab[PFC.F_SWAP] = "Swap:"
    __lab[PFC.F_KERNEL_PGSZ] = "KernelPageSize:"
    __lab[PFC.F_MMU_PGSZ] = "MMUPageSize:"
    __lab[PFC.F_LOCKED] = "Locked:"

    __detailorder = [ PFC.F_SIZE, PFC.F_RSS, PFC.F_PSS, PFC.F_SH_CLEAN,
            PFC.F_SH_DIRTY, PFC.F_PR_CLEAN, PFC.F_PR_DIRTY,
            PFC.F_REFERENCED, PFC.F_ANONYMOUS, PFC.F_ANON_HUGE_PAGES,
            PFC.F_SWAP, PFC.F_KERNEL_PGSZ, PFC.F_MMU_PGSZ, PFC.F_LOCKED]

    __leadtemp = "{st:08x}-{en:08x} {fl:4s} {poff:08x} {major:02x}:{minor:02x} \
{inode:d}"
    __summtemp = "{lead:<72s} {path:s}"
    __nopathtemp = "{lead:s} "

    __detailtemp = "{label:<15s} {val:8d} kB"

    for __hilit in inprecs:
        __ff = inprecs.field

        __lead = __leadtemp.format(st=__ff[PFC.F_START], en=__ff[PFC.F_END],
                fl=__ff[PFC.F_FLAGS], poff=__ff[PFC.F_PAGE_OFFSET],
                major=__ff[PFC.F_MAJOR_DEV], minor=__ff[PFC.F_MINOR_DEV],
                inode=__ff[PFC.F_INODE]
                )

        if __ff[PFC.F_PATH] == "":
            print __nopathtemp.format(lead=__lead)
        else:
            print __summtemp.format(lead=__lead, path=__ff[PFC.F_PATH])

        for __key in __detailorder:
            print __detailtemp.format(label=__lab[__key], val=__ff[__key])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    
RG.RECREATOR[PH.GET_HANDLER("/proc/self/smaps")] = re_self_smaps

