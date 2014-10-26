#!/usr/bin/env python

"""Handle records from /proc/misc data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_misc(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{minor:3d} {devname:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(minor=__ff[PFC.F_MINOR_DEV],
                devname=__ff[PFC.F_DEVICE])

RG.RECREATOR[PH.GET_HANDLER("/proc/misc")] = re_root_misc
