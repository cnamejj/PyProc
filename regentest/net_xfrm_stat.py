#!/usr/bin/env python

"""Handle records from /proc/net/xfrm_stat files"""

import regentest as RG
import ProcHandlers as PH
import ProcBaseRoutines as PBR

PREFIX = PBR.PREFIX_VAL
NAME = PBR.FIELD_NAME
CONV = PBR.CONVERSION

# ---

def re_net_xfrm_stat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{parm:<24s}\t{val:d}"

    for __hilit in inprecs:
        __ff = inprecs.field
        __rulelist = inprecs.parse_rule
        __hitlist = inprecs.hit_order

        __prefix = dict()

        for __seq in range(0, len(__rulelist)):
            __rule = __rulelist[__seq][0]

            try:
                __prefix[__rule[NAME]] = __rule[PREFIX]
            except KeyError:
                pass

        for __seq in range(0, len(__hitlist)):
            __name = __hitlist[__seq]

            print __template.format(parm=__prefix[__name],
                    val=__ff[__name])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/xfrm_stat")] = re_net_xfrm_stat
