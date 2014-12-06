#!/usr/bin/env python

"""Handle records from /proc/sysvipc/shm data files"""

import regentest as RG
import ProcHandlers as PH
import platform

PFC = PH.ProcFieldConstants

# ---

def re_sysvipc_shm(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __arch_size, __arch_link = platform.architecture()

    if __arch_size == "64bit":
        __numtemp = "{num:21d}"
        __coltemp = "{label:>21s}"
    else:
        __numtemp = "{num:10d}"
        __coltemp = "{label:>10s}"

    __headtemp = "       key      shmid perms \
{size:s}  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime \
{rss:s} {swap:s}"

    __template = "{key:10d} {id:10d}  {mode:4o} {size:s} {cpid:5d} {lpid:5d}  \
{attach:5d} {ow_uid:5d} {ow_gid:5d} {cr_uid:5d} {cr_gid:5d} {atime:10d} \
{dtime:10d} {ctime:10d} {rss:s} {swap:s}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    __size = __coltemp.format(label="size")
    __rss = __coltemp.format(label="rss")
    __swap = __coltemp.format(label="swap")

    print __headtemp.format(size=__size, rss=__rss, swap=__swap)

    for __hilit in inprecs:
        __ff = inprecs.field

        __size = __numtemp.format(num=__ff[PFC.F_SIZE])
        __rss = __numtemp.format(num=__ff[PFC.F_RSS])
        __swap = __numtemp.format(num=__ff[PFC.F_SWAP])

        print __template.format(key=__ff[PFC.F_KEY], id=__ff[PFC.F_ID],
                mode=__ff[PFC.F_MODE], size=__size, cpid=__ff[PFC.F_CPID],
                lpid=__ff[PFC.F_LPID], attach=__ff[PFC.F_ATTACH],
                ow_uid=__ff[PFC.F_OW_UID], ow_gid=__ff[PFC.F_OW_GID],
                cr_uid=__ff[PFC.F_CR_UID], cr_gid=__ff[PFC.F_CR_GID],
                atime=__ff[PFC.F_ACC_TIME], dtime=__ff[PFC.F_DEST_TIME],
                ctime=__ff[PFC.F_CHAN_TIME], rss=__rss, swap=__swap)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/sysvipc/shm")] = re_sysvipc_shm
