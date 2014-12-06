#!/usr/bin/env python

"""Handle records from /proc/self/stack data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_stack(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "[<{addr:016x}>] {entry:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(addr=__ff[PFC.F_ADDRESS],
                entry=__ff[PFC.F_STACK_ENTRY])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/stack")] = re_self_stack

