#!/usr/bin/env python

"""Handle records from /proc/diskstats data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_diskstats(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{major:4d} {minor:7d} {dname:s} {rios:d} {rmerg:d} {rsect:d} \
{rmsec:d} {wios:d} {wmerg:d} {wsect:d} {wmsec:d} {pif:d} {ioms:d} {wtms:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(major=__ff[PFC.F_MAJOR_DEV],
                minor=__ff[PFC.F_MINOR_DEV], dname=__ff[PFC.F_DISK_NAME],
                rios=__ff[PFC.F_READ_IOS], rmerg=__ff[PFC.F_READ_MERGES],
                rsect=__ff[PFC.F_READ_SECTORS], rmsec=__ff[PFC.F_READ_MSECS],
                wios=__ff[PFC.F_WRITE_IOS], wmerg=__ff[PFC.F_WRITE_MERGES],
                wsect=__ff[PFC.F_WRITE_SECTORS], wmsec=__ff[PFC.F_WRITE_MSECS],
                pif=__ff[PFC.F_PART_IN_FLIGHT], ioms=__ff[PFC.F_IO_MSECS],
                wtms=__ff[PFC.F_QUEUE_TIME_MSECS]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/diskstats")] = re_root_diskstats
