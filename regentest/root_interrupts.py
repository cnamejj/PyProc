#!/usr/bin/env python

"""Handle records from /proc/interrupts data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_root_interrupts(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __first = True
    __summ_only = set( ["ERR", "MIS"] )

    __cputemp = "CPU{ncpu:d}"

    __headtemp = "{acc:s}{cpu:<11s}"

    __cpustatstemp = "{acc:s} {count:10d}"

    __templatetemp = "{{intr:>{preflen:d}s}}:{{cpustats:s}}  {{desc:s}}"
    __summonlytemptemp = "{{intr:>{preflen:d}s}}: {{tot:10d}}"

    for __hilit in inprecs:
        __ff = inprecs.field

        if __first:
            __first = False

            __preflen = __ff[PFC.F_COL1_WIDTH]

            __template = __templatetemp.format(preflen=__preflen)
            __summonlytemp = __summonlytemptemp.format(preflen=__preflen)

            __head = " " * (__preflen + 8)
            for __cpu in range(0, len(__ff[PFC.F_COUNT])):
                __showcpu = __cputemp.format(ncpu=__cpu)
                __head = __headtemp.format(acc=__head, cpu=__showcpu)

            print __head

        __intr = __ff[PFC.F_INTERRUPT]

        if __intr in __summ_only:
            print __summonlytemp.format(intr=__intr, tot=__ff[PFC.F_TOT_COUNT])

        else:
            __cpustats = ""
            for __cpu in range(0, len(__ff[PFC.F_COUNT])):
                __showcpu = __cputemp.format(ncpu=__cpu)
                __cpustats = __cpustatstemp.format(acc=__cpustats,
                        count=__ff[PFC.F_COUNT][__showcpu])

            print __template.format(intr=__intr, cpustats=__cpustats,
                desc=__ff[PFC.F_INTERRUPT_DESC])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/interrupts")] = re_root_interrupts
