#!/usr/bin/env python

"""Handle records from /proc/net/rt6_stats data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_rt6_stats(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{nodes:04x} {rnodes:04x} {ralloc:04x} {rentry:04x} \
{rcache:04x} {destop:04x} {droute:04x}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(nodes=__ff[PFC.F_FIB_NODES],
                rnodes=__ff[PFC.F_FIB_ROUTE_NODES],
                ralloc=__ff[PFC.F_FIB_ROUTE_ALLOC],
                rentry=__ff[PFC.F_FIB_ROUTE_ENTRIES],
                rcache=__ff[PFC.F_FIB_ROUTE_CACHE],
                destop=__ff[PFC.F_FIB_DEST_OPS],
                droute=__ff[PFC.F_FIB_DISC_ROUTES])

RG.RECREATOR[PH.GET_HANDLER("/proc/net/rt6_stats")] = re_net_rt6_stats
