#!/usr/bin/env python

"""Handle records from /proc/sysvipc/msg data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_sysvipc_msg(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "       key      msqid perms      cbytes       qnum lspid \
lrpid   uid   gid  cuid  cgid      stime      rtime      ctime"

    __template = "{key:10d} {id:10d}  {mode:4o}  {bytes:10d} {qnum:10d} \
{spid:5d} {rpid:5d} {ow_uid:5d} {ow_gid:5d} {cr_uid:5d} {cr_gid:5d} \
{stime:10d} {rtime:10d} {ctime:10d}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __headtemp

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(key=__ff[PFC.F_KEY], id=__ff[PFC.F_ID],
                mode=__ff[PFC.F_MODE], bytes=__ff[PFC.F_BYTES],
                qnum=__ff[PFC.F_QUEUES], spid=__ff[PFC.F_SEND_PID],
                rpid=__ff[PFC.F_RECV_PID], ow_uid=__ff[PFC.F_OW_UID],
                ow_gid=__ff[PFC.F_OW_GID], cr_uid=__ff[PFC.F_CR_UID],
                cr_gid=__ff[PFC.F_CR_GID], stime=__ff[PFC.F_SEND_TIME],
                rtime=__ff[PFC.F_RECV_TIME], ctime=__ff[PFC.F_CHAN_TIME])

RG.RECREATOR[PH.GET_HANDLER("/proc/sysvipc/msg")] = re_sysvipc_msg
