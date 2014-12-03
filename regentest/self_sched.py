#!/usr/bin/env python

"""Handle records from PID specific /proc/PID/sched data files"""

import regentest as RG
import ProcHandlers as PH
import ProcBaseRoutines as PBR

PFC = PH.ProcFieldConstants

# ---

def re_self_sched(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "{prog:s} ({pid:d}, #threads: {threads:d})\n\
{hrule:s}"

    __strtemptemp = "{{desc:<{dlen:d}s}}:{{count:>21s}}"
    __longtemptemp = "{{desc:<{dlen:d}s}}:{{count:21d}}"
    __floattemptemp = "{{desc:<{dlen:d}s}}:{{count:21.6f}}"

    __template = ()

    for __hilit in inprecs:
        __ff = inprecs.field
        __hits = inprecs.hit_order

        if len(__template) == 0:
            __dlen = len(__ff[PFC.F_HRULE]) - 22
            __strtemp = __strtemptemp.format(dlen=__dlen)
            __longtemp = __longtemptemp.format(dlen=__dlen)
            __floattemp = __floattemptemp.format(dlen=__dlen)

            __template = { str: __strtemp, long: __longtemp,
                    float: __floattemp }

        __keydesc = dict()
        __keyconv = dict()

        __rule_list = inprecs.parse_rule
        for __seq in __rule_list:
            __rule = __rule_list[__seq][0]
            try:
                __key = __rule[PBR.FIELD_NAME]
                __keydesc[__key] = __rule[PBR.PREFIX_VAL]
                try:
                    __keyconv[__key] = __rule[PBR.CONVERSION]
                except KeyError:
                    __keyconv[__key] = str
            except KeyError:
                pass

        for __key in inprecs.two_longs:
            try:
                __keyconv[__key] = float
                __ff[__key] /= 1000000.0
            except KeyError:
                pass

        print __headtemp.format(prog=__ff[PFC.F_PROGRAM], pid=__ff[PFC.F_PID],
                threads=__ff[PFC.F_THREADS], hrule=__ff[PFC.F_HRULE])

        for __seq in range(0, len(__hits)):
            __key = __hits[__seq]
            if __keydesc.has_key(__key):
                __val = __ff[__key]

                print __template[__keyconv[__key]].format(desc=__keydesc[__key],
                        count=__ff[__key])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/sched")] = re_self_sched
