#!/usr/bin/env python

"""Handle records from /proc/key-users data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_key_users(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{uid:5d}: {usage:5d} {nk:d}/{nik:d} {qnk:d}/{maxk:d} \
{qnb:d}/{maxb:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(uid=__ff[PFC.F_UID], usage=__ff[PFC.F_USAGE],
               nk=__ff[PFC.F_NKEYS], nik=__ff[PFC.F_NIKEYS],
               qnk=__ff[PFC.F_QNKEYS], maxk=__ff[PFC.F_MAXKEYS],
               qnb=__ff[PFC.F_QNBYTES], maxb=__ff[PFC.F_MAXBYTES]
               )

RG.RECREATOR[PH.GET_HANDLER("/proc/key-users")] = re_root_key_users
