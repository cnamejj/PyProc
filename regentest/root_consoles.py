#!/usr/bin/env python

"""Handle records from /proc/consoles data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_consoles(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{devname:21}{iot:3s} ({flags:s}) {major:>4s}:{minor:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __sp = __ff[PFC.F_DEVICE_NUMBER].partition(":")
        
#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(devname=__ff[PFC.F_DEVICE_NAME],
                iot=__ff[PFC.F_IO_TYPE], flags=__ff[PFC.F_FLAGS],
                major=__sp[0], minor=__sp[2],
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/consoles")] = re_root_consoles
