#!/usr/bin/env python

"""Handle records from /proc/latency_stats files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC

# ---

def re_root_latency_stats(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __header = "Latency Top version : v0.1"

    __template = "{hits:d} {lacc:d} {lmax:d} {btrace:s}"

    print __header

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(hits=__ff[PFC.F_HITS],
                lacc=__ff[PFC.F_ACCUM_LATENCY], lmax=__ff[PFC.F_MAX_LATENCY],
                btrace=" ".join(__ff[PFC.F_BACKTRACE]))

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/latency_stats")] = re_root_latency_stats
