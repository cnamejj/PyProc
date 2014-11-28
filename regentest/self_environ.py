#!/usr/bin/env python

"""Handle records from /proc/self/environ files"""

from __future__ import print_function
import regentest as RG
import ProcHandlers as PH

# ---

def re_self_environ(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{name:s}={val:s}\0"

    for __hilit in inprecs:
        __ff = inprecs.field
        __hitlist = inprecs.hit_order

        for __seq in range(0, len(__hitlist)):
            __name = __hitlist[__seq]
            print(__template.format(name=__name, val=__ff[__name]), end="")

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/environ")] = re_self_environ
