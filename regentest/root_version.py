#!/usr/bin/env python

"""Handle records from /proc/version files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC 

# ---

def re_root_version(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{sys:s} version {rel:s} ({comp_by:s}@{comp_host:s}) \
({compiler:s}) {vers:s}"

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(sys=__ff[PFC.F_SYSNAME], 
                rel=__ff[PFC.F_RELEASE], comp_by=__ff[PFC.F_COMP_BY],
                comp_host=__ff[PFC.F_COMP_HOST], compiler=__ff[PFC.F_COMPILER],
                vers=__ff[PFC.F_VERSION])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/version")] = re_root_version
