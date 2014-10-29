#!/usr/bin/env python

"""Handle records from /proc/self/cmdline data files"""

from __future__ import print_function
import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_cmdline(inprecs):

    """Iterate through parsed records and re-generate data file"""

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print("\0".join(__ff[PFC.F_COMM_ARGS]), end="")

RG.RECREATOR[PH.GET_HANDLER("/proc/self/cmdline")] = re_self_cmdline

    

