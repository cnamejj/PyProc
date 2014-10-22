#!/usr/bin/env python

"""Handler records from /proc/net/ptype data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_ptype(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "Type Device      Function"

    __template = "{dev_type:<4s} {dev_name:<8s} {dev_func:s}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(dev_type=__ff[PFC.F_DEVICE_TYPE], 
                dev_name=__ff[PFC.F_DEVICE_NAME],
                dev_func=__ff[PFC.F_DEVICE_FUNC]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/ptype")] = re_net_ptype

