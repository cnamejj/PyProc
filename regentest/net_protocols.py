#!/usr/bin/env python

"""Handle records from /proc/net/protocols data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_protocols(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "protocol  size sockets  memory press maxhdr  slab module     \
cl co di ac io in de sh ss gs se re sp bi br ha uh gp em"

    __template = "{prot:9s} {size:4d} {socks:6d}  {mem:6d}   {press:3s} \
{mhead:6d}   {slab:3s}  {mod:10s} {cl:>2s} {conn:>2s} {disc:>2s} {acc:>2s} \
{ioctl:>2s} {init:>2s} {dest:>2s} {shut:>2s} {ssopt:>2s} {gsopt:>2s} \
{smsg:>2s} {rmsg:>2s} {spag:>2s} {bind:>2s} {brec:>2s} {hash:>2s} {unh:>2s} \
{gport:>2s} {entpr:>2s}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(prot=__ff[PFC.F_PROTOCOL],
                size=__ff[PFC.F_SIZE], socks=__ff[PFC.F_SOCKETS],
                mem=__ff[PFC.F_MEMORY], press=__ff[PFC.F_PRESSURE],
                mhead=__ff[PFC.F_MAX_HEADER], slab=__ff[PFC.F_SLAB],
                mod=__ff[PFC.F_MODULE], cl=__ff[PFC.F_CLOSE],
                conn=__ff[PFC.F_CONNECT], disc=__ff[PFC.F_DISCONNECT],
                acc=__ff[PFC.F_ACCEPT], ioctl=__ff[PFC.F_IOCTL],
                init=__ff[PFC.F_INIT], dest=__ff[PFC.F_DESTROY],
                shut=__ff[PFC.F_SHUTDOWN], ssopt=__ff[PFC.F_SETSOCKOPT],
                gsopt=__ff[PFC.F_GETSOCKOPT], smsg=__ff[PFC.F_SENDMSG],
                rmsg=__ff[PFC.F_RECVMSG], spag=__ff[PFC.F_SENDPAGE],
                bind=__ff[PFC.F_BIND], brec=__ff[PFC.F_BACKLOG_RCV],
                hash=__ff[PFC.F_HASH], unh=__ff[PFC.F_UNHASH],
                gport=__ff[PFC.F_GET_PORT], entpr=__ff[PFC.F_ENTER_PRESSURE]
                )


RG.RECREATOR[PH.GET_HANDLER("/proc/net/protocols")] = re_net_protocols

