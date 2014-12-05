#!/usr/bin/env python

"""Handle records from /proc/net/softnet_stat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_softnet_stat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{proc:08x} {drop:08x} {tsq:08x} {zero1:08x} {zero2:08x} \
{zero3:08x} {zero4:08x} {zero5:08x} {ccoll:08x} {rrps:08x}{flc:s}"

    __flctemp = " {count:08x}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    for __hilit in inprecs:
        __ff = inprecs.field
        __hits = inprecs.fixpos_hits

        __flc = ""
        for __seq in __hits:
            if __hits[__seq] == PFC.F_FLOW_LIM_COUNT:
                __flc = __flctemp.format(count=__ff[PFC.F_FLOW_LIM_COUNT])
                break

        print __template.format(proc=__ff[PFC.F_PROCESSED], 
                drop=__ff[PFC.F_DROPPED], tsq=__ff[PFC.F_TIME_SQUEEZE],
                zero1=__ff[PFC.F_ZERO1], zero2=__ff[PFC.F_ZERO2],
                zero3=__ff[PFC.F_ZERO3], zero4=__ff[PFC.F_ZERO4],
                zero5=__ff[PFC.F_ZERO5], ccoll=__ff[PFC.F_CPU_COLL],
                rrps=__ff[PFC.F_RECEIVED_RPS], flc=__flc)

RG.RECREATOR[PH.GET_HANDLER("/proc/net/softnet_stat")] = re_net_softnet_stat

