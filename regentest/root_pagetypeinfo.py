#!/usr/bin/env python

"""Handle records from /proc/pagetypeinfo data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_pagetypeinfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "Page block order: {order:d}\n\
Pages per block:  {perblock:d}\n"

    __freepref = "{desc:<43s} ".format(desc="Free pages count per migrate type \
at order")
    __freeheadertemp = "{acc:s}{order:6d} "

    __orderpreftemp = "Node {node:4d}, zone {zone:>9s} type {typ:>12s} "
    __ordertemp = "{acc:s}{count:6d} "

    __blockpref = "\n{desc:<23s}".format(desc="Number of blocks type ")
    __blockheadertemp = "{acc:s}{name:>12s} "

    __blsumpreftemp = "Node {node:d}, zone {zone:>8s} "
    __blsumtemp = "{acc:s}{count:12d} "

    first = True
    in_block = False

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    for __hilit in inprecs:
        __ff = inprecs.field
        __brkout = __ff[PFC.F_MIGR_BRKOUT]

        if first:
            first = False
            print __headtemp.format(order=__ff[PFC.F_BLOCK_ORDER],
                    perblock=__ff[PFC.F_PAGES_PER_BLOCK])

            __label = __freepref
            for __seq in range(0, len(__brkout)):
                __label = __freeheadertemp.format(acc=__label, order=__seq)
            print __label

        if len(__brkout) > 0:
            __order = __orderpreftemp.format(node=__ff[PFC.F_NODE],
                    zone=__ff[PFC.F_ZONE], typ=__ff[PFC.F_TYPE])

            __olist = inprecs.order_list
            for __seq in range(0, len(__brkout)):
                __order = __ordertemp.format(acc=__order,
                        count=__brkout[__olist[__seq]])
            print __order

        else:
            __mig = inprecs.migtype_list

            if not in_block:
                in_block = True

                __label = __blockpref
                for __seq in range(0, len(__mig)):
                    __label = __blockheadertemp.format(acc=__label,
                            name=__mig[__seq])

                print __label

            __blsum = __blsumpreftemp.format(node=__ff[PFC.F_NODE],
                    zone=__ff[PFC.F_ZONE])

            __totals = __ff[PFC.F_MIGR_AGG]
            for __seq in range(0, len(__totals)):
                __blsum = __blsumtemp.format(acc=__blsum,
                        count=__totals[__mig[__seq]])

            print __blsum

RG.RECREATOR[PH.GET_HANDLER("/proc/pagetypeinfo")] = re_root_pagetypeinfo
