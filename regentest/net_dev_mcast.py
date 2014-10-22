#!/usr/bin/env python

"""Handler records from /proc/net/dev_mcast data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_dev_mcast(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{ifind:<4d} {name:<15s} {refc:<5d} {glob:<5d} {addr:s}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(ifind=__ff[PFC.F_INT_INDEX], 
                name=__ff[PFC.F_DEVICE],
                refc=__ff[PFC.F_REFCOUNT],
                glob=__ff[PFC.F_GLOBAL_USE],
                addr=__ff[PFC.F_DEV_ADDR]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/dev_mcast")] = re_net_dev_mcast

