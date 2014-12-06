#!/usr/bin/env python

"""Handle records from /proc/mounts data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_mounts(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{msrc:s} {mfs:s} {fst:s} {mopts:s} 0 0"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(msrc=__ff[PFC.F_MOUNT_SRC],
                mfs=__ff[PFC.F_MOUNT_FS], fst=__ff[PFC.F_FS_TYPE],
                mopts=__ff[PFC.F_MOUNT_OPTS]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/mounts")] = re_root_mounts
