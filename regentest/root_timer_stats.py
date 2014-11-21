#!/usr/bin/env python

"""Handle records from /proc/timer_stats data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_timer_stats(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "Timer Stats Version: {vers:s}\n\
Sample period: {samper:.3f} s"

    __overflowtemp = "Overflow: {over:d} entries"
    __fulltotaltemp = "{tot:d} total events, {evrate:.3f} events/sec"
    __shorttotaltemp = "{tot:d} total events"

    __defertemp = "{count:4d}D,"
    __normtemp = " {count:4d},"

    __template = "{count:s} {pid:5d} {comm:<16s} {stfunc:s} ({exfunc:s})"

    __first = True

    for __hilit in inprecs:
        __ff = inprecs.field

        if __first:
            print __headtemp.format(vers=__ff[PFC.F_VERSION],
                    samper=__ff[PFC.F_SAMPLE_PERIOD])

            # -- This is false if the value is "NaN"
            if __ff[PFC.F_OVERFLOW] == __ff[PFC.F_OVERFLOW]:
                print __overflowtemp.format(over=__ff[PFC.F_OVERFLOW])
            __first = False

        if __ff[PFC.F_EVENT_TOTAL] > 0:

            # -- Another "NAN check"
            if __ff[PFC.F_EVENT_RATE] == __ff[PFC.F_EVENT_RATE]:
                print __fulltotaltemp.format(tot=__ff[PFC.F_EVENT_TOTAL],
                        evrate=__ff[PFC.F_EVENT_RATE])
            else:
                print __shorttotaltemp.format(tot=__ff[PFC.F_EVENT_TOTAL])

        else:
            if __ff[PFC.F_DEFERRABLE] == "":
                __count = __normtemp.format(count=__ff[PFC.F_COUNT])
            else:
                __count = __defertemp.format(count=__ff[PFC.F_COUNT])

            print __template.format(count=__count, pid=__ff[PFC.F_PID],
                    comm=__ff[PFC.F_PROC_NAME], stfunc=__ff[PFC.F_INIT_ROUT],
                    exfunc=__ff[PFC.F_CBACK_ROUT])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    
RG.RECREATOR[PH.GET_HANDLER("/proc/timer_stats")] = re_root_timer_stats
