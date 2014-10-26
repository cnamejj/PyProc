#!/usr/bin/env python

"""Handle records from /proc/loadavg data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_loadavg(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{la0:.2f} {la1:.2f} {la2:.2f} {tasks:d}/{thrs:d} {lpid:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(la0=__ff[PFC.F_LOAD_AV0],
               la1=__ff[PFC.F_LOAD_AV1], la2=__ff[PFC.F_LOAD_AV2],
               tasks=__ff[PFC.F_NUM_TASKS], thrs=__ff[PFC.F_NUM_THREADS],
               lpid=__ff[PFC.F_LAST_PID]
               )

RG.RECREATOR[PH.GET_HANDLER("/proc/loadavg")] = re_root_loadavg
