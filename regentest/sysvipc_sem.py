#!/usr/bin/env python

"""Handle records from /proc/sysvipc/sem data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_sysvipc_sem(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "       key      semid perms      nsems   uid   gid  cuid  \
cgid      otime      ctime"

    __template = "{key:10d} {id:10d}  {mode:4o} {sems:10d} {ow_uid:5d} \
{ow_gid:5d} {cr_uid:5d} {cr_gid:5d} {otime:10d} {ctime:10d}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __headtemp

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(key=__ff[PFC.F_KEY], id=__ff[PFC.F_ID],
                mode=__ff[PFC.F_MODE], sems=__ff[PFC.F_SEMS],
                ow_uid=__ff[PFC.F_OW_UID], ow_gid=__ff[PFC.F_OW_GID],
                cr_uid=__ff[PFC.F_CR_UID], cr_gid=__ff[PFC.F_CR_GID],
                otime=__ff[PFC.F_UPD_TIME], ctime=__ff[PFC.F_CHAN_TIME])

RG.RECREATOR[PH.GET_HANDLER("/proc/sysvipc/sem")] = re_sysvipc_sem
