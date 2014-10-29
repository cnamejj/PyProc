#!/usr/bin/env python

"""Handle records from /proc/self/wchan data files"""

from __future__ import print_function
import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_wchan(inprecs):

    """Iterate through parsed records and re-generate data file"""

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print(__ff[PFC.F_WCHAN], end="")

RG.RECREATOR[PH.GET_HANDLER("/proc/self/wchan")] = re_self_wchan

    

