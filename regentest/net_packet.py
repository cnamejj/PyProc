#!/usr/bin/env python

"""Handle records from /proc/net/packet data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_packet(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "sk       RefCnt Type Proto  Iface R Rmem   User   Inode"

    __template = "{sp:016x} {refc:<6d} {typ:<4d} {prot:04x}   {iidx:<5d} \
{run:1d} {rmem:<6d} {uid:<6d} {inode:<6d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(sp=__ff[PFC.F_SOCKET_POINTER],
                refc=__ff[PFC.F_REFCOUNT], typ=__ff[PFC.F_TYPE],
                prot=__ff[PFC.F_PROTOCOL], iidx=__ff[PFC.F_INT_INDEX],
                run=__ff[PFC.F_RUNNING], rmem=__ff[PFC.F_RMEM_ALLOC],
                uid=__ff[PFC.F_UID], inode=__ff[PFC.F_INODE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/packet")] = re_net_packet
