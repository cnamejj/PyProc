#!/usr/bin/env python

"""Handle records from /proc/self/cgroup files"""

import regentest as RG
import ProcHandlers as PH
import ProcFieldConstants as PFC

# ---

def re_self_cgroup(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{ssid:d}:{nlist:s}:{path}"

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(ssid=__ff[PFC.F_SUBSYS_ID],
                nlist=",".join(__ff[PFC.F_NAME_LIST]),
                path=__ff[PFC.F_PATH])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/cgroup")] = re_self_cgroup
