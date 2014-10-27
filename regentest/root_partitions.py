#!/usr/bin/env python

"""Handle records from /proc/partitions data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_partitions(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "major minor  #blocks  name\n"
    __template = "{major:4d}  {minor:7d} {blocks:10d} {part:s}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(major=__ff[PFC.F_MAJOR_DEV],
                minor=__ff[PFC.F_MINOR_DEV], blocks=__ff[PFC.F_BLOCKS],
                part=__ff[PFC.F_PARTITION_NAME]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/partitions")] = re_root_partitions
