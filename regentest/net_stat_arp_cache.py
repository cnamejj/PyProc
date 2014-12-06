#!/usr/bin/env python

"""Handle records from /proc/net/stat/arp_cache data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_stat_arp_cache(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "entries  allocs destroys hash_grows  lookups hits  res_failed  \
rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs \
unresolved_discards"

    __template = "{arps:08x}  {alloc:08x} {destroy:08x} {hgrow:08x}  \
{look:08x} {hit:08x}  {rfail:08x}  {rmcast:08x} {rucast:08x}  {gcper:08x} \
{gcfor:08x} {udisc:08x}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(arps=__ff[PFC.F_ARP_ENTRIES],
                alloc=__ff[PFC.F_ALLOC], destroy=__ff[PFC.F_DESTROY],
                hgrow=__ff[PFC.F_HASH_GROW], look=__ff[PFC.F_LOOKUP],
                hit=__ff[PFC.F_HIT], rfail=__ff[PFC.F_RES_FAIL],
                rmcast=__ff[PFC.F_RCV_MCAST_PROBE],
                rucast=__ff[PFC.F_RCV_UCAST_PROBE],
                gcper=__ff[PFC.F_GC_PERIODIC], gcfor=__ff[PFC.F_GC_FORCED],
                udisc=__ff[PFC.F_UNRES_DISCARD])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/stat/arp_cache")] = re_net_stat_arp_cache

