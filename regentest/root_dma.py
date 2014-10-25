#!/usr/bin/env python

"""Handle records from /proc/dma data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_dma(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{chan:2d}: {devname:s}"

    __norectemp = "No DMA"

    __nrecs = 0

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(chan=__ff[PFC.F_CHANNEL],
                devname=__ff[PFC.F_DEVICE_NAME]
                )

    if __nrecs == 0:
        print __norectemp

RG.RECREATOR[PH.GET_HANDLER("/proc/dma")] = re_root_dma
