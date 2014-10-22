#!/usr/bin/env python

"""Handler records from /proc/net/route data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_route(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __fixedline = "{line:127}"

    __head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\
\t\tMTU\tWindow\tIRTT"

    __template = "{iface:s}\t{dhex:8s}\t{ghex:8s}\t{flags:04X}\t{refc:d}\t\
{use:d}\t{metric:d}\t{mhex:8s}\t{mtu:d}\t{win:d}\t{irtt:d}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __fixedline.format(line=__head)

    for __hilit in inprecs:
        __ff = inprecs.field

        __out = __template.format(iface=__ff[PFC.F_INTERFACE], 
                dhex=__ff[PFC.F_DEST_HEXIP], ghex=__ff[PFC.F_GATE_HEXIP], 
                flags=__ff[PFC.F_FLAGS], refc=__ff[PFC.F_REFCOUNT], 
                use=__ff[PFC.F_USECOUNT], metric=__ff[PFC.F_METRIC], 
                mhex=__ff[PFC.F_MASK_HEXIP], mtu=__ff[PFC.F_MTU], 
                win=__ff[PFC.F_WINDOW], irtt=__ff[PFC.F_IRTT]
                )

        print __fixedline.format(line=__out)

RG.RECREATOR[PH.GET_HANDLER("/proc/net/route")] = re_net_route
