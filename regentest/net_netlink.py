#!/usr/bin/env python

"""Handle records from /proc/net/netlink data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_netlink(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "sk       Eth Pid    Groups   Rmem     Wmem     Dump     \
Locks     Drops     Inode"

    __template = "{sk:016x} {prot:<3d} {pid:<6d} {gr:08x} {rmem:<8d} \
{wmem:<8d} {dump:s} {lock:<8d} {drop:<8d} {inode:<8d}"

    __dumphextemp = "{dump:016x}"
    __dumpdectemp = "{dump:d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        __dump = __dumpdectemp.format(dump=__ff[PFC.F_DUMP])
        if __dump != __ff[PFC.F_DUMP_STR]:
            __dump = __dumphextemp.format(dump=__ff[PFC.F_DUMP])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(sk=__ff[PFC.F_SOCKET_POINTER],
                prot=__ff[PFC.F_PROTOCOL], pid=__ff[PFC.F_PID],
                gr=__ff[PFC.F_GROUPS], rmem=__ff[PFC.F_RMEM_ALLOC],
                wmem=__ff[PFC.F_WMEM_ALLOC], dump=__dump,
                lock=__ff[PFC.F_LOCKS], drop=__ff[PFC.F_DROPS],
                inode=__ff[PFC.F_INODE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/netlink")] = re_net_netlink

