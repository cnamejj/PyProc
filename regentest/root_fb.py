#!/usr/bin/env python

"""Handle records from /proc/fb data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_fb(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{node:d} {id:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(node=__ff[PFC.F_NODE], id=__ff[PFC.F_ID_LIST])

RG.RECREATOR[PH.GET_HANDLER("/proc/fb")] = re_root_fb
