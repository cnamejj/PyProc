#!/usr/bin/env python

"""Handle records from /proc/self/stat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_stat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{pnr:d} ({comm:s}) {state:s} {ppid:d} {pgid:d} {sid:d} \
{tnr:d} {tpgr:d} {fl:d} {minfl:d} {cminfl:d} {majfl:d} {cmajfl:d} {utime:d} \
{stime:d} {cutime:d} {cstime:d} {pri:d} {nice:d} {thr:d} 0 {stt:d} {vsz:d} \
{rss:d} {rssl:d} {stcode:d} {encode:d} {ststack:d} {esp:d} {eip:d} {sigpn:d} \
{sigbl:d} {sigig:d} {sigca:d} {wch:d} 0 0 {exsig:d} {task:d} {rtpri:d} \
{pol:d} {iotic:d} {gtime:d} {cgtime:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(pnr=__ff[PFC.F_PID_NR], comm=__ff[PFC.F_COMM],
                state=__ff[PFC.F_STATE], ppid=__ff[PFC.F_PPID],
                pgid=__ff[PFC.F_PGID], sid=__ff[PFC.F_SID],
                tnr=__ff[PFC.F_TTY_NR], tpgr=__ff[PFC.F_TTY_PGRP],
                fl=__ff[PFC.F_FLAGS], minfl=__ff[PFC.F_MIN_FLT],
                cminfl=__ff[PFC.F_CMIN_FLT], majfl=__ff[PFC.F_MAJ_FLT],
                cmajfl=__ff[PFC.F_CMAJ_FLT], utime=__ff[PFC.F_UTIME],
                stime=__ff[PFC.F_STIME], cutime=__ff[PFC.F_CUTIME],
                cstime=__ff[PFC.F_CSTIME], pri=__ff[PFC.F_PRIORITY],
                nice=__ff[PFC.F_NICE], thr=__ff[PFC.F_THREADS],
                stt=__ff[PFC.F_START_TIME], vsz=__ff[PFC.F_VSIZE],
                rss=__ff[PFC.F_RSS_SIZE], rssl=__ff[PFC.F_RSS_LIM],
                stcode=__ff[PFC.F_START_CODE], encode=__ff[PFC.F_END_CODE],
                ststack=__ff[PFC.F_START_STACK], esp=__ff[PFC.F_ESP],
                eip=__ff[PFC.F_EIP], sigpn=__ff[PFC.F_SIG_PEND],
                sigbl=__ff[PFC.F_SIG_BLOCK], sigig=__ff[PFC.F_SIG_IGNORE],
                sigca=__ff[PFC.F_SIG_CATCH], wch=__ff[PFC.F_WCHAN],
                exsig=__ff[PFC.F_EXIT_SIG], task=__ff[PFC.F_TASK],
                rtpri=__ff[PFC.F_RT_PRIORITY], pol=__ff[PFC.F_POLICY],
                iotic=__ff[PFC.F_IO_TICKS], gtime=__ff[PFC.F_GTIME],
                cgtime=__ff[PFC.F_CGTIME]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/self/stat")] = re_self_stat

    

