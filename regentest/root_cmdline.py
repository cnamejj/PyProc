#!/usr/bin/env python

"""Handle records from /proc/cmdline data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_cmdline(inprecs):

    """Iterate through parsed records and re-generate data file"""

    for __hilit in inprecs:
        print inprecs.field[PFC.F_CMDLINE]

RG.RECREATOR[PH.GET_HANDLER("/proc/cmdline")] = re_root_cmdline
