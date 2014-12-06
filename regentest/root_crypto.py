#!/usr/bin/env python

"""Handle records from /proc/crypto files"""

import regentest as RG
import ProcHandlers as PH
import ProcBaseRoutines as PBR

PREFIX = PBR.PREFIX_VAL
NAME = PBR.FIELD_NAME
CONV = PBR.CONVERSION

# ---

def re_root_crypto(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __strtemp = "{parm:<12s} : {val:s}"
    __longtemp = "{parm:<12s} : {val:d}"

    __template = { str: __strtemp, long: __longtemp }

    for __hilit in inprecs:
        __ff = inprecs.field
        __rulelist = inprecs.parse_rule
        __hitlist = inprecs.hit_order

        __prefix = dict()
        __conv = dict()

        for __seq in range(0, len(__rulelist)):
            __rule = __rulelist[__seq][0]

            try:
                __prefix[__rule[NAME]] = __rule[PREFIX]
                try:
                    __conv[__rule[NAME]] = __rule[CONV]
                except KeyError:
                    __conv[__rule[NAME]] = str
            except KeyError:
                pass

        for __seq in range(0, len(__hitlist)):
            __name = __hitlist[__seq]
            __vt = __conv[__name]

            print __template[__vt].format(parm=__prefix[__name],
                    val=__ff[__name])

        print ""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/crypto")] = re_root_crypto
