#!/usr/bin/env python

"""Handler records from /proc/cgroups data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_cgroups(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "#subsys_name	hierarchy	num_cgroups	enabled"

    __template = "{subsys:s}\t{hier:d}\t{ncgr:d}\t{enab:d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(subsys=__ff[PFC.F_SUBSYSTEM], 
                hier=__ff[PFC.F_HIERARCHY], ncgr=__ff[PFC.F_NUM_CGROUPS], 
                enab=__ff[PFC.F_ENABLED]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/cgroups")] = re_root_cgroups
