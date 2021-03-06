#!/usr/bin/env python

"""Handle records from /proc/softirqs data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_root_softirqs(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __first = True

    __headpref = " " * 20
    __colheadtemp = "{out:s}{cpu:<11s}"

    __labeltemp = "{label:>12s}:"
    __irqstemp = "{out:s} {irqs:10d}"

    __cols = dict()
    __irqs = dict()

    __hilit = inprecs.next()

    __cpulist = inprecs.field[PFC.F_CPU_ORDER]
    __irqlist = inprecs.field[PFC.F_IRQ_ORDER]

    for __off in range(0, len(__irqlist)):
        __key = __irqlist[str(__off)]
        __irqs[__off] = __key

    for __off in range(0, len(__cpulist)):
        __val = __cpulist[str(__off)]
        __cols[__off] = __val

    # ---

    __out = __headpref

    for __off in range(0, len(__cols)):
        __out = __colheadtemp.format(out=__out, cpu=__cols[__off])

    print __out

    for __off in range(0, len(__irqs)):
        __key = __irqs[__off]
        __cts = inprecs.field[__key]

        __out = __labeltemp.format(label=__key)

        for __cnum in range(0, len(__cols)):
            __out = __irqstemp.format(out=__out, irqs=__cts[__cols[__cnum]])

        print __out

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/softirqs")] = re_root_softirqs
