#!/usr/bin/env python

"""Handle records from /proc/self/syscall data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_syscall(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{line:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(line=__ff[PFC.F_SYSCALL])

RG.RECREATOR[PH.GET_HANDLER("/proc/self/syscall")] = re_self_syscall

    

