#!/usr/bin/env python

"""Handle records from /proc/net/stat/ip_conntrack data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_stat_ip_conntrack(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "entries  searched found new invalid ignore delete delete_list \
insert insert_failed drop early_drop icmp_error  expect_new expect_create \
expect_delete search_restart"

    __template = "{ents:08x}  {search:08x} {found:08x} {new:08x} {inv:08x} \
{ign:08x} {delete:08x} {dlist:08x} {ins:08x} {ifail:08x} {drop:08x} \
{dearly:08x} {icmp:08x}  {exnew:08x} {excr:08x} {exdel:08x} {srest:08x}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(ents=__ff[PFC.F_ENTRIES], 
                search=__ff[PFC.F_SEARCHED], found=__ff[PFC.F_FOUND],
                new=__ff[PFC.F_NEW], inv=__ff[PFC.F_INVALID],
                ign=__ff[PFC.F_IGNORE], delete=__ff[PFC.F_DELETE],
                dlist=__ff[PFC.F_DELETE_LIST], ins=__ff[PFC.F_INSERT],
                ifail=__ff[PFC.F_INSERT_FAILED], drop=__ff[PFC.F_DROP],
                dearly=__ff[PFC.F_DROP_EARLY], icmp=__ff[PFC.F_ICMP_ERROR],
                exnew=__ff[PFC.F_EXP_NEW], excr=__ff[PFC.F_EXP_CREATE],
                exdel=__ff[PFC.F_EXP_DELETE], srest=__ff[PFC.F_SEARCH_RESTART])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/stat/ip_conntrack")] = \
        re_net_stat_ip_conntrack

    

