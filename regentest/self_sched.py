#!/usr/bin/env python

"""Handle records from PID specific /proc/PID/sched data files"""

import regentest as RG
import ProcHandlers as PH
import ProcBaseRoutines as PBR

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_self_sched(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "{prog:s} ({pid:d}, #threads: {threads:d})\n\
{hrule:s}"

    __strtemptemp = "{{desc:<{dlen:d}s}}:{{count:>21s}}"
    __longtemptemp = "{{desc:<{dlen:d}s}}:{{count:21d}}"
    __floattemptemp = "{{desc:<{dlen:d}s}}:{{count:21.6f}}"

    __hilotemp = "{hi:14d}.{low:06d}"

    __numamigtemp = "{desc:s} {count:d}"
    __numafaulttemp = "{label:s} {idx:d}, {node:d}, {cpu:d}, {home:d}, \
{flt:d}"

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
                __keyconv[__key] = str
                __ff[__key] = __hilotemp.format(hi=__ff[__key] / 1000000,
                        low=__ff[__key] % 1000000)
            except KeyError:
                pass

        print __headtemp.format(prog=__ff[PFC.F_PROGRAM], pid=__ff[PFC.F_PID],
                threads=__ff[PFC.F_THREADS], hrule=__ff[PFC.F_HRULE])

        for __seq in range(0, len(__hits)):
            __key = __hits[__seq]
            if __keydesc.has_key(__key):
                if __key == PFC.F_NUMA_MIGRATE:
                    print __numamigtemp.format(desc=__keydesc[__key],
                        count=__ff[__key])

                else:
                    __val = __ff[__key]

                    print __template[__keyconv[__key]].format(
                            desc=__keydesc[__key], count=__ff[__key])

        if __ff.has_key(PFC.F_NUMA_FAULTS):
            __faultlist = __ff[PFC.F_NUMA_FAULTS]
            for __seq in range(0, len(__faultlist)):
                __fset = __faultlist[__seq]
                print __numafaulttemp.format(idx=__fset[PFC.F_INDEX],
                        node=__fset[PFC.F_NODE], cpu=__fset[PFC.F_CPU],
                        home=__fset[PFC.F_HOME], flt=__fset[PFC.F_FAULT],
                        label=__fset[PFC.F_NUMA_FAULTS_LAB])

# pylint: enable=R0914

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/sched")] = re_self_sched
