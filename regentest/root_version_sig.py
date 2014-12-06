#!/usr/bin/env python

"""Handle records from /proc/version_signature data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_version_sig(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{line:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(line=__ff[PFC.F_VERSION_STRING])

RG.RECREATOR[PH.GET_HANDLER("/proc/version_signature")] = re_root_version_sig
