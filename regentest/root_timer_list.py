#!/usr/bin/env python

"""Handle records from /proc/timer_list data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def recreate_tickdev_info(recs):
    """Generate a tick-device multi-line record"""

    __devtypetemp = "Per CPU device: {cpu:d}"
    __bcastmasktemp = "tick_broadcast_mask: {mask:s}"
    __oneshotmasktemp = "tick_broadcast_oneshot_mask: {mask:s}\n"
    __nulldev = "<NULL>"

    __template = "Tick Device: mode:     {tdm:d}\n\
{devtype:s}\n\
Clock Event Device: {devname:s}"

    __detailtemp = " max_delta_ns:   {maxdn:d}\n\
 min_delta_ns:   {mindn:d}\n\
 mult:           {mult:d}\n\
 shift:          {shift:d}\n\
 mode:           {modenum:d}\n\
 next_event:     {nextsecs:d} nsecs\n\
 set_next_event: {nextevent:s}\n\
 set_mode:       {modename:s}\n\
 event_handler:  {handler:s}\n\
 retries:        {retries:d}"

    if recs[PFC.F_CLOCK_EV_DEV] != "":
        if recs[PFC.F_BCAST_DEVICE]:
            __devtype = "Broadcast device"
        else:
            __devtype = __devtypetemp.format(cpu=recs[PFC.F_PER_CPU_DEV])

        print __template.format(tdm=recs[PFC.F_TICK_DEV], devtype=__devtype,
                devname=recs[PFC.F_CLOCK_EV_DEV])

        if recs[PFC.F_CLOCK_EV_DEV] != __nulldev:
            print __detailtemp.format(maxdn=recs[PFC.F_MAX_DELTA],
                    mindn=recs[PFC.F_MIN_DELTA], mult=recs[PFC.F_MULT],
                    shift=recs[PFC.F_SHIFT], modenum=recs[PFC.F_MODE],
                    nextsecs=recs[PFC.F_NEXT_EVENT],
                    nextevent=recs[PFC.F_SET_NEXT_EVENT],
                    modename=recs[PFC.F_SET_MODE],
                    handler=recs[PFC.F_EVENT_HANDLER],
                    retries=recs[PFC.F_RETRIES])

    if len(recs[PFC.F_TICK_BCAST_MASK]) > 0:
        print __bcastmasktemp.format(mask=recs[PFC.F_TICK_BCAST_MASK])

    if len(recs[PFC.F_TICK_BCAST_ONESHOT]) > 0:
        print __oneshotmasktemp.format(mask=recs[PFC.F_TICK_BCAST_ONESHOT])
    elif len(recs[PFC.F_TICK_BCAST_MASK]) > 0:
        print ""

    if recs[PFC.F_CLOCK_EV_DEV] != "":
        print ""

# ---

def show_timer_details(active):
    """Generate detailed info about one timer"""

    __tstattemp = " {stsite:s}, {comm:s}/{pid:d}"

    __taddrtemp = "<{addr:016x}>"

    __template = " #{idx:d}: {addr:s}, {name:s}, S:{state:2s}{tstat:s}\n\
 # expires at {exp1:d}-{exp2:d} nsecs [in {left1:d} to {left2:d} nsecs]"

    if active[PFC.F_START_COMM] == "":
        __tstat = ""
    else:
        __tstat = __tstattemp.format(stsite=active[PFC.F_START_SITE],
                comm=active[PFC.F_START_COMM], pid=active[PFC.F_START_PID])

    try:
        __taddr = __taddrtemp.format(addr=active[PFC.F_TIMER_ADDR])
    except KeyError:
        __taddr = active[PFC.F_TIMER_ADDR_TEXT]

    print __template.format(idx=active[PFC.F_TIMER_NUM],
            addr=__taddr, name=active[PFC.F_TIMER_FUNC],
            state=active[PFC.F_TIMER_STATE], tstat=__tstat,
            exp1=active[PFC.F_SOFT_EXP], exp2=active[PFC.F_EXP],
            left1=active[PFC.F_SOFT_EXP_DIFF], left2=active[PFC.F_EXP_DIFF])

# ---

# pylint: disable=R0914

def recreate_cpu_info(recs, hits):
    """Generate output describing a CPU, it's clocks and timers"""

    __cputemp = "\ncpu: {cpu:d}"

    __clocktemp = " clock {clock:d}:\n\
  .base:       {base:016x}\n\
  .index:      {idx:d}\n\
  .resolution: {secs:d} nsecs\n\
  .get_time:   {name:s}"

    __hrtimetemp = "  .offset:     {hrsecs:d} nsecs"

    __activetemp = "active timers:"

    __strawtemp = "  .{label:<15s}: {val:d}"
    __stnstemp = "  .{label:<15s}: {val:d} nsecs"
    __stjifftemp = "{label:s}: {val:d}"

    # ---

    __hi_res = False

    for __off in range(0, len(hits)):
        if hits[__off] == PFC.F_HRES_ACTIVE:
            __hi_res = True

    __tick_oneshot = False

    for __off in range(0, len(hits)):
        if hits[__off] == PFC.F_NOHZ_MODE:
            __tick_oneshot = True

    __hi_res_list = [ (PFC.F_NEXT_EXPIRE, "expires_next", __stnstemp),
            (PFC.F_HRES_ACTIVE, "hres_active", __strawtemp),
            (PFC.F_NR_EVENTS, "nr_events", __strawtemp),
            (PFC.F_NR_RETRIES, "nr_retries", __strawtemp),
            (PFC.F_NR_HANGS, "nr_hangs", __strawtemp),
            (PFC.F_MAX_HANG_TIME, "max_hang_time", __stnstemp) ]

    __tick_oneshot_list = [ (PFC.F_NOHZ_MODE, "nohz_mode", __strawtemp),
            (PFC.F_LAST_TICK, "last_tick", __stnstemp),
            (PFC.F_IDLE_TICK, "idle_tick", __stnstemp),
            (PFC.F_TICK_STOP, "tick_stopped", __strawtemp),
            (PFC.F_IDLE_JIFFIES, "idle_jiffies", __strawtemp),
            (PFC.F_IDLE_CALLS, "idle_calls", __strawtemp),
            (PFC.F_IDLE_SLEEPS, "idle_sleeps", __strawtemp),
            (PFC.F_IDLE_ENTRY, "idle_entrytime", __stnstemp),
            (PFC.F_IDLE_WAKE, "idle_waketime", __stnstemp),
            (PFC.F_IDLE_EXIT, "idle_exittime", __stnstemp),
            (PFC.F_IDLE_SLEEPTIME, "idle_sleeptime", __stnstemp),
            (PFC.F_IOWAIT_SLEEP, "iowait_sleeptime", __stnstemp),
            (PFC.F_LAST_JIFFIES, "last_jiffies", __strawtemp),
            (PFC.F_NEXT_JIFFIES, "next_jiffies", __strawtemp),
            (PFC.F_IDLE_EXPIRES, "idle_expires", __stnstemp),
            (PFC.F_JIFFIES, "jiffies", __stjifftemp) ]

    # ---

    print __cputemp.format(cpu=recs[PFC.F_CPU])

    for __seq in range(0, len(recs[PFC.F_CLOCK_LIST])):
        __clinfo = recs[PFC.F_CLOCK_LIST][__seq]
        print __clocktemp.format(clock=__clinfo[PFC.F_CLOCK_ID],
                base=__clinfo[PFC.F_CLOCK_BASE],
                idx=__clinfo[PFC.F_CLOCK_INDEX],
                secs=__clinfo[PFC.F_CLOCK_RES],
                name=__clinfo[PFC.F_CLOCK_GETTIME])

        if __hi_res and __clinfo.has_key(PFC.F_CLOCK_OFFSET):
            print __hrtimetemp.format(hrsecs=__clinfo[PFC.F_CLOCK_OFFSET])

        print __activetemp

        __tset = __clinfo[PFC.F_ACTIVE_TIMERS]
        for __tnum in range(0, len(__tset)):
            show_timer_details(__tset[__tnum])

    if __hi_res:
        for __off in range(0, len(__hi_res_list)):
            __key, __pref, __temp = __hi_res_list[__off]
            print __temp.format(label=__pref, val=recs[__key])

    if __tick_oneshot:
        __idle_tick = False
        __last_tick = False

        for __off in range(0, len(hits)):
            if hits[__off] == PFC.F_IDLE_TICK:
                __idle_tick = True
            if hits[__off] == PFC.F_LAST_TICK:
                __last_tick = True

        for __off in range(0, len(__tick_oneshot_list)):
            __key, __pref, __temp = __tick_oneshot_list[__off]

            if __key == PFC.F_IDLE_TICK:
                __show = __idle_tick
            elif __key == PFC.F_LAST_TICK:
                __show = __last_tick
            else:
                __show = True

            if __show:
                print __temp.format(label=__pref, val=recs[__key])

# pylint: enable=R0914

# ---

def re_root_timer_list(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "Timer List Version: {vers:s}\n\
HRTIMER_MAX_CLOCK_BASES: {maxcb:d}\n\
now at {secs:d} nsecs"

    __ticksectionpref = "\n"
    __nulldev = "<NULL>"

    __first = True
    __first_tick = True

    for __hilit in inprecs:
        __ff = inprecs.field

        if __first:
            print __headtemp.format(vers=__ff[PFC.F_VERSION],
                    maxcb=__ff[PFC.F_HRT_MAX_CL_BASES],
                    secs=__ff[PFC.F_TIME_NOW])
            __first = False

        if len(__ff[PFC.F_CLOCK_LIST]) > 0:
            recreate_cpu_info(__ff, inprecs.hit_order)

        else:
            if __first_tick:
                print ""
                __first_tick = False
                if __ff[PFC.F_CLOCK_EV_DEV] == __nulldev:
                    print ""

            recreate_tickdev_info(__ff)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/timer_list")] = re_root_timer_list


