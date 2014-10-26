#!/usr/bin/env python

"""Handle records from /proc/locks data files"""

import regentest as RG
import ProcHandlers as PH
import ProcDataConstants as PDC

PFC = PH.ProcFieldConstants

# ---

def re_root_locks(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __endtemp = "{en:d}"

    __template = "{idx:d}: {ltype:<6s} {lsubt:<9s} {iot:<5s} {pid:d} {inode:s} \
{st:d} {en:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __end = __ff[PFC.F_END]
        if __end == PDC.INF:
            __end_st = __ff[PFC.F_END_STRING]
        else:
            __end_st = __endtemp.format(en=__end)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(en=__end_st, idx=__ff[PFC.F_INDEX], 
               ltype=__ff[PFC.F_LOCK_TYPE], lsubt=__ff[PFC.F_LOCK_SUBTYPE],
               iot=__ff[PFC.F_LOCK_IO], pid=__ff[PFC.F_PID],
               inode=__ff[PFC.F_LOCK_INODE], st=__ff[PFC.F_START]
               )

RG.RECREATOR[PH.GET_HANDLER("/proc/locks")] = re_root_locks
