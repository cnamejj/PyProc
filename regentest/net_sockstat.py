#!/usr/bin/env python

"""Handle records from /proc/net/sockstat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

USED = 'used'
INUSE = 'inuse'
ORPH = 'orphan'
TW = 'tw'
ALLOC = 'alloc'
MEM = 'mem'
MEMORY = 'memory'

# ---

# pylint: disable=R0914

def re_net_sockstat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "sockets: used {used}\n\
TCP: inuse {tcpuse} orphan {tcporph} tw {tcptw} alloc {tcpall} mem {tcpmem}\n\
UDP: inuse {udpuse} mem {udpmem}\n\
UDPLITE: inuse {ultuse}\n\
RAW: inuse {rawuse}\n\
FRAG: inuse {fruse} memory {frmem}"


    for __hilit in inprecs:
        __ff = inprecs.field

        __spd = __ff[PFC.F_SOCK_SOCKETS]
        __socks = __spd[USED]

        __spd = __ff[PFC.F_SOCK_TCP]
        __tcpuse = __spd[INUSE]
        __tcporph = __spd[ORPH]
        __tcptw = __spd[TW]
        __tcpall = __spd[ALLOC]
        __tcpmem = __spd[MEM]

        __spd = __ff[PFC.F_SOCK_UDP]
        __udpuse = __spd[INUSE]
        __udpmem = __spd[MEM]

        __spd = __ff[PFC.F_SOCK_UDPLITE]
        __ultuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_RAW]
        __rawuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_FRAG]
        __fruse = __spd[INUSE]
        __frmem = __spd[MEMORY]

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(used=__socks, tcpuse=__tcpuse,
                tcporph=__tcporph, tcptw=__tcptw, tcpall=__tcpall,
                tcpmem=__tcpmem, udpuse=__udpuse, udpmem=__udpmem,
                ultuse=__ultuse, rawuse=__rawuse, fruse=__fruse, frmem=__frmem)

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/net/sockstat")] = re_net_sockstat
