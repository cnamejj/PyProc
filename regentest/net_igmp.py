#!/usr/bin/env python

"""Handle records from /proc/net/igmp data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_igmp(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter"

    __template = "{idx:d}\t{dev:<10s}: {count:5d} {query:>7s}\n\
\t\t\t\t{group:08X} {users:5d} {timer:d}:{zero:08x}\t\t{rep:d}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(idx=__ff[PFC.F_INDEX], dev=__ff[PFC.F_DEVICE], 
                count=__ff[PFC.F_COUNT], query=__ff[PFC.F_QUERIER], 
                group=__ff[PFC.F_GROUP], users=__ff[PFC.F_USERS], 
                timer=__ff[PFC.F_TIMER], zero=__ff[PFC.F_ZERO1], 
                rep=__ff[PFC.F_REPORTER]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/igmp")] = re_net_igmp
