#!/usr/bin/env python

"""Handle records from /proc/net/sockstat6 data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

INUSE = 'inuse'
MEMORY = 'memory'

# ---

def re_net_sockstat6(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "TCP6: inuse {tcpuse:s}\n\
UDP6: inuse {udpuse:s}\n\
UDPLITE6: inuse {ultuse:s}\n\
RAW6: inuse {rawuse:s}\n\
FRAG6: inuse {fruse:s} memory {frmem:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __spd = __ff[PFC.F_SOCK_TCP6]
        __tcpuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_UDP6]
        __udpuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_UDPLITE6]
        __ultuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_RAW6]
        __rawuse = __spd[INUSE]

        __spd = __ff[PFC.F_SOCK_FRAG6]
        __fruse = __spd[INUSE]
        __frmem = __spd[MEMORY]

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(tcpuse=__tcpuse, udpuse=__udpuse,
                ultuse=__ultuse, rawuse=__rawuse, fruse=__fruse, frmem=__frmem
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/sockstat6")] = re_net_sockstat6
