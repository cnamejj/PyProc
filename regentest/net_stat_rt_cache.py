#!/usr/bin/env python

"""Handle records from /proc/net/stat/rt_cache data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_stat_rt_cache(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd \
in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total \
gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search"

    __template = "{ents:08x}  {ihit:08x} {istot:08x} {ismc:08x} {inor:08x} \
{ibrd:08x} {imdst:08x} {imsrc:08x}  {ohit:08x} {ostot:08x} {osmc:08x} \
{gctot:08x} {gcig:08x} {gcgm:08x} {gcdo:08x} {ihls:08x} {ohls:08x} "

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(ents=__ff[PFC.F_ENTRIES],
                ihit=__ff[PFC.F_IN_HIT], istot=__ff[PFC.F_IN_SLOW_TOT],
                ismc=__ff[PFC.F_IN_SLOW_MC], ibrd=__ff[PFC.F_IN_BRD],
                imdst=__ff[PFC.F_IN_MARTIAN_DST],
                imsrc=__ff[PFC.F_IN_MARTIAN_SRC], inor=__ff[PFC.F_IN_NO_ROUTE],
                ohit=__ff[PFC.F_OUT_HIT], ostot=__ff[PFC.F_OUT_SLOW_TOT],
                osmc=__ff[PFC.F_OUT_SLOW_MC], gctot=__ff[PFC.F_GC_TOTAL],
                gcig=__ff[PFC.F_GC_IGNORED], gcgm=__ff[PFC.F_GC_GOAL_MISS],
                gcdo=__ff[PFC.F_GC_DST_OVERFLOW], ihls=__ff[PFC.F_IN_HL_SEARCH],
                ohls=__ff[PFC.F_OUT_HL_SEARCH])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/stat/rt_cache")] = re_net_stat_rt_cache
