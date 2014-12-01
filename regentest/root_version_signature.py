#!/usr/bin/env python

"""Handle records from /proc/version_signature files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC 

# ---

def re_root_version_signature(inprecs):

    """Iterate through parsed records and re-generate data file"""

    for __hilit in inprecs:
        print inprecs.field[PFC.F_VERSION_STRING]

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/version_signature")] = \
        re_root_version_signature
