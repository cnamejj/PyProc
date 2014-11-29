#!/usr/bin/env python

"""Handle records from /proc/slabinfo files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC

# ---

def re_root_slabinfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headertemp = "slabinfo - version: 2.1{desc:s}\n\
# name            <active_objs> <num_objs> <objsize> <objperslab> \
<pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata \
<active_slabs> <num_slabs> <sharedavail>{label}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    __statstemp = " : globalstat {lisall:7d} {maxobj:6d} {grow:5d} {reap:4d} \
{err:4d} {maxfree:4d} {nodall:4d} {remfree:4d} {alov:4d} : cpustat {hitall:6d} \
{misall:6d} {hitfree:6d} {misfree:6d}"

    __template = "{name:<17s} {actobj:6d} {nobj:6d} {osize:6d} {opsl:4d} \
{ppsl:4d} : tunables {lim:4d} {bcount:4d} {shfac:4d} : slabdata {nsla:6d} \
{shsla:6d} {actsla:6d}{stats:s}"

    __desc_short = ""
    __desc_stats = " (statistics)"

    __label_short = ""
    __label_stats = " : globalstat <listallocs> <maxobjs> <grown> <reaped> \
<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow> : cpustat \
<allochit> <allocmiss> <freehit> <freemiss>"

    __minimum_fields = 12

    __first = True
    __has_stats = False
    __stats = ""

    for __hilit in inprecs:
        __ff = inprecs.field
        __hitlist = inprecs.fixpos_hits

        if __first:
            __first = False

            __has_stats = len(__hitlist) > __minimum_fields

            if inprecs.curr_sio.raw_lines_read > 1:
                if __has_stats:
                    __desc = __desc_stats
                    __label = __label_stats
                else:
                    __desc = __desc_short
                    __label = __label_short

                print __headertemp.format(desc=__desc, label=__label)

        if __has_stats:
            __stats = __statstemp.format(lisall=__ff[PFC.F_LIST_ALLOCS],
                    maxobj=__ff[PFC.F_MAX_OBJS], grow=__ff[PFC.F_GROWN],
                    reap=__ff[PFC.F_REAPED], err=__ff[PFC.F_ERROR],
                    maxfree=__ff[PFC.F_MAX_FREEABLE], 
                    nodall=__ff[PFC.F_NODE_ALLOCS], 
                    remfree=__ff[PFC.F_REMOTE_FREES],
                    alov=__ff[PFC.F_ALIEN_OVERFLOW], 
                    hitall=__ff[PFC.F_ALLOC_HIT],
                    misall=__ff[PFC.F_ALLOC_MISS],
                    hitfree=__ff[PFC.F_FREE_HIT],
                    misfree=__ff[PFC.F_FREE_MISS])

        print __template.format(name=__ff[PFC.F_SLAB_NAME], 
                actobj=__ff[PFC.F_ACTIVE_OBJS], nobj=__ff[PFC.F_NUM_OBJS],
                osize=__ff[PFC.F_OBJ_SIZE], opsl=__ff[PFC.F_OBJ_PER_SLAB],
                ppsl=__ff[PFC.F_PAGES_PER_SLAB], lim=__ff[PFC.F_LIMIT],
                bcount=__ff[PFC.F_BATCHCOUNT], shfac=__ff[PFC.F_SHARED],
                nsla=__ff[PFC.F_ACTIVE_SLABS], shsla=__ff[PFC.F_NUM_SLABS],
                actsla=__ff[PFC.F_SHARED_AVAIL], stats=__stats)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/slabinfo")] = re_root_slabinfo
