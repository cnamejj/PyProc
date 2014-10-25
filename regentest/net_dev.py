#!/usr/bin/env python

"""Handle records from /proc/net/dev data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_dev(inprecs):

    """Iterate through parsed records and re-generate data file"""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    __head = "Inter-|   Receive                                                \
|  Transmit\n\
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    \
packets errs drop fifo colls carrier compressed"

    __template = "{dev:>6s}: {rbyte:7d} {rpack:7d} {rerr:4d} {rdrop:4d} \
{rfifo:4d} {rframe:5d} {rcomp:10d} {rmcas:9d} {tbyte:8d} {tpack:7d} {terr:4d} \
{tdrop:4d} {tfifo:4d} {tcoll:5d} {tcarr:7d} {tcomp:10d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(dev=__ff[PFC.F_DEVICE],
                rbyte=__ff[PFC.F_RX_BYTES], rpack=__ff[PFC.F_RX_PACKETS],
                rerr=__ff[PFC.F_RX_ERRORS], rdrop=__ff[PFC.F_RX_DROP],
                rfifo=__ff[PFC.F_RX_FIFO], rframe=__ff[PFC.F_RX_FRAME],
                rcomp=__ff[PFC.F_RX_COMPRESSED],
                rmcas=__ff[PFC.F_RX_MULTICAST], tbyte=__ff[PFC.F_TX_BYTES],
                tpack=__ff[PFC.F_TX_PACKETS], terr=__ff[PFC.F_TX_ERRORS],
                tdrop=__ff[PFC.F_TX_DROP], tfifo=__ff[PFC.F_TX_FIFO],
                tcoll=__ff[PFC.F_TX_COLLISION], tcarr=__ff[PFC.F_TX_CARRIER],
                tcomp=__ff[PFC.F_TX_COMPRESSED]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/dev")] = re_net_dev

