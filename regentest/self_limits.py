#!/usr/bin/env python

"""Handle records from /proc/self/limits data files"""

import regentest as RG
import ProcHandlers as PH
import ProcDataConstants as PDC

PFC = PH.ProcFieldConstants

# ---

def re_self_limits(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __unlimited = "unlimited"

    __numtemp = "{num:d}"
    __unitstemp = "{units:<10s}"

    __template = "{name:<25s} {soft:<20s} {hard:<20s} {units:s}"

    print __template.format(name="Limit", soft="Soft Limit", hard="Hard Limit",
            units="Units     ")

    for __hilit in inprecs:
        __ff = inprecs.field

        __name = __ff[PFC.F_LIMIT]
        __soft = __ff[PFC.F_SOFT_LIMIT]
        if __soft == PDC.INF:
            __soft = __unlimited
        else:
            __soft = __numtemp.format(num=__soft)

        __hard = __ff[PFC.F_HARD_LIMIT]
        if __hard == PDC.INF:
            __hard = __unlimited
        else:
            __hard = __numtemp.format(num=__hard)

        __units = __ff[PFC.F_UNITS]
        if __units != "":
            __units = __unitstemp.format(units=__units)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(name=__name, soft=__soft, hard=__hard,
                units=__units)

RG.RECREATOR[PH.GET_HANDLER("/proc/self/limits")] = re_self_limits
