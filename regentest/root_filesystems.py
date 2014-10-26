#!/usr/bin/env python

"""Handle records from /proc/filesystems data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_filesystems(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{nodev:s}\t{name:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(nodev=__ff[PFC.F_DEV_FLAG],
               name=__ff[PFC.F_FILESYSTEM])

RG.RECREATOR[PH.GET_HANDLER("/proc/filesystems")] = re_root_filesystems
