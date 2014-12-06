#!/usr/bin/env python

"""Handle records from /proc/net/unix data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_unix(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "Num       RefCount Protocol Flags    Type St Inode Path"

    __template = "{num:016x}: {refct:08X} {prot:08X} {flags:08x} {typ:04X} \
{state:02X} {inode:5d}{path}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        path = __ff[PFC.F_PATH]
        if path != "":
            path = " {path}".format(path=path)

        print __template.format(num=__ff[PFC.F_NUM], refct=__ff[PFC.F_REFCOUNT],
                prot=__ff[PFC.F_PROTOCOL], flags=__ff[PFC.F_FLAGS],
                typ=__ff[PFC.F_TYPE], state=__ff[PFC.F_STATE],
                inode=__ff[PFC.F_INODE], path=path
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/unix")] = re_net_unix

