#!/usr/bin/env python

"""Handle records from /proc/keys files"""

import regentest as RG
import ProcHandlers as PH
import ProcFieldConstants as PFC

# ---

def re_root_keys(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{serial:08x} {flags:s} {usage:5d} {expire:4s} {perms:08x} \
{uid:5d} {gid:5d} {name:<9s} {desc:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(serial=__ff[PFC.F_SERIAL],
                flags=__ff[PFC.F_FLAGS], usage=__ff[PFC.F_USAGE],
                expire=__ff[PFC.F_EXPIRES], perms=__ff[PFC.F_PERMS],
                uid=__ff[PFC.F_UID], gid=__ff[PFC.F_GID],
                name=__ff[PFC.F_KEY_NAME], desc=__ff[PFC.F_DESCRIPTION])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/keys")] = re_root_keys
