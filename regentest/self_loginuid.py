#!/usr/bin/env python

"""Handle records from /proc/self/loginuid data files"""

from __future__ import print_function
import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_loginuid(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{uid:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print(__template.format(uid=__ff[PFC.F_LOGINUID]), end="")

RG.RECREATOR[PH.GET_HANDLER("/proc/self/loginuid")] = re_self_loginuid

    

