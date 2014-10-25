#!/usr/bin/env python

"""Handle records from /proc/devices data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_devices(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __dtype = "unknown"
    __break = ""

    __type_pref = dict()
    __type_pref["unknown"] = "Unknown"
    __type_pref["character"] = "Character"
    __type_pref["block"] = "Block"

    __head = "{lb:s}{dt:s} devices:"

    __template = "{major:3d} {name:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        if __dtype != __ff[PFC.F_DEVICE_TYPE]:
            __dtype = __ff[PFC.F_DEVICE_TYPE]
            print __head.format(dt=__type_pref[__dtype], lb=__break)
            __break = "\n"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(major=__ff[PFC.F_MAJOR_DEV],
                name=__ff[PFC.F_DEVICE_NAME]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/devices")] = re_root_devices
