#!/usr/bin/env python

"""Handle records from /proc/stat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def string_from_list_of_longs(lset):

    """Convert a list of longs to a space delimited string"""

    __total_key = "total"
    __res = ""

    __nent = 0
    for __off in lset:
        if type(__off) == type(__nent):
            __nent += 1
        elif __off == __total_key:
            __res = " {tot:d}".format(tot=lset[__off])

    for __off in range(0, __nent):
        __res = "{acc:s} {next:d}".format(acc=__res, next=lset[__off])

    return __res

# ---

def parse_cpu_stats(cpu_stats, stats_order):

    """Construct a space delimitted string of metrics using a list of stats
       to control the order"""

    __res = ""

    for __off in range(0, len(stats_order)):
        __key = stats_order[__off]
        __res = "{acc:s} {next:d}".format(acc=__res, next=cpu_stats[__key])

    return __res

# ---

def re_root_stat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __cpu_pref = "cpu"
    __appstattemp = "{acc:s} {stat:d}"
    __cpukeytemp = "cpu{cpu:d}"

    __cputemp = "cpu{cn:s}{stlist:s}"
    __intrtemp = "intr{intrlist:s}"
    __onestattemp = "{name:s} {stat:d}"
    __irqtemp = "softirq{irqlist:s}"

    __stat_name = dict()
    __stat_name[0] = "user"
    __stat_name[1] = "nice"
    __stat_name[2] = "sys"
    __stat_name[3] = "idle"
    __stat_name[4] = "iowait"
    __stat_name[5] = "irq"
    __stat_name[6] = "softirq"
    __stat_name[7] = "steal"
    __stat_name[8] = "guest"
    __stat_name[9] = "guest-nice"

    __lab = { 0: (PFC.F_SS_CTXT, "ctxt"),
            1: (PFC.F_SS_BTIME, "btime"),
            2: (PFC.F_SS_PROCS_TOT, "processes"),
            3: (PFC.F_SS_PROCS_RUN, "procs_running"),
            4: (PFC.F_SS_PROCS_BLOCK, "procs_blocked") }

    for __hilit in inprecs:
        __ff = inprecs.field
        __ncpu = 0

        __out = parse_cpu_stats(__ff[PFC.F_SS_CPU], __stat_name)
        print __cputemp.format(cn=" ", stlist=__out)

        for __key in __ff:
            if __key.startswith(__cpu_pref) and __key != PFC.F_SS_CPU:
                __ncpu += 1

        for __off in range(0, __ncpu):
            __key = __cpukeytemp.format(cpu=__off)
            __out = parse_cpu_stats(__ff[__key], __stat_name)
            print __cputemp.format(cn=str(__off), stlist=__out)

        __out = string_from_list_of_longs(__ff[PFC.F_SS_INTR])
        print __intrtemp.format(intrlist=__out)

        for __off in range(0, len(__lab)):
            __key, __name = __lab[__off]
            print __onestattemp.format(name=__name, stat=__ff[__key])

        __out = string_from_list_of_longs(__ff[PFC.F_SS_SOFTIRQ])
        print __irqtemp.format(irqlist=__out)

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/stat")] = re_root_stat
