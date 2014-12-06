#!/usr/bin/env python

"""Handle records from /proc/net/ipv6_route data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_ipv6_route(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{dad:32s} {dpl:02x} {sad:32s} {spl:02x} {pkey:32s} \
{metric:08x} {refc:08x} {use:08x} {flags:8s} {dev:>8s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(dad=__ff[PFC.F_DEST_HEXIP],
                dpl=__ff[PFC.F_DEST_PREFIX_LEN], sad=__ff[PFC.F_SRCE_HEXIP],
                spl=__ff[PFC.F_SRCE_PREFIX_LEN], pkey=__ff[PFC.F_PRIMARY_KEY],
                metric=__ff[PFC.F_RT6I_METRIC], refc=__ff[PFC.F_DEST_REFCOUNT],
                use=__ff[PFC.F_DEST_USE], flags=__ff[PFC.F_RT6I_FLAGS],
                dev=__ff[PFC.F_DEVICE])

RG.RECREATOR[PH.GET_HANDLER("/proc/net/ipv6_route")] = re_net_ipv6_route
