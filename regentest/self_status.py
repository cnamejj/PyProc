#!/usr/bin/env python

"""Handle records from /proc/self/status data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_self_status(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __nametemp = "Name:\t{prog:s}"

    __grlisttemp = "{acc:s}{gr:d} "

    __tasktemp = "State:\t{st:s}\n\
Tgid:\t{tgid:d}\n\
Pid:\t{pid:d}\n\
PPid:\t{ppid:d}\n\
TracerPid:\t{trpid:d}\n\
Uid:\t{uid:d}\t{euid:d}\t{suid:d}\t{fsuid:d}\n\
Gid:\t{gid:d}\t{egid:d}\t{sgid:d}\t{fsgid:d}\n\
FDSize:\t{fdsize:d}\n\
Groups:\t{grlist:s}"

    __memtemp = "VmPeak:\t{peak:8d} kB\n\
VmSize:\t{sz:8d} kB\n\
VmLck:\t{lock:8d} kB\n\
VmPin:\t{pin:8d} kB\n\
VmHWM:\t{hwm:8d} kB\n\
VmRSS:\t{rss:8d} kB\n\
VmData:\t{dat:8d} kB\n\
VmStk:\t{stack:8d} kB\n\
VmExe:\t{exe:8d} kB\n\
VmLib:\t{lib:8d} kB\n\
VmPTE:\t{pte:8d} kB\n\
VmSwap:\t{swap:8d} kB"

    __sigtemp = "Threads:\t{thr:d}\n\
SigQ:\t{squeue:s}\n\
SigPnd:\t{pend:s}\n\
ShdPnd:\t{shpend:s}\n\
SigBlk:\t{block:s}\n\
SigIgn:\t{ign:s}\n\
SigCgt:\t{caught:s}"

    __captemp = "CapInh:\t{inh:s}\n\
CapPrm:\t{perm:s}\n\
CapEff:\t{eff:s}\n\
CapBnd:\t{bset:s}"

    __seccomptemp = "Seccomp:\t{sec:d}"

    __cpustemp = "Cpus_allowed:\t{cpus:s}\n\
Cpus_allowed_list:\t{cpus_list:s}\n\
Mems_allowed:\t{mems:s}\n\
Mems_allowed_list:\t{mems_list:s}"

    __cswitchtemp = "voluntary_ctxt_switches:\t{vol:d}\n\
nonvoluntary_ctxt_switches:\t{nonvol:d}"

    __first = True
    __has_seccomp = False

    for __hilit in inprecs:
        __ff = inprecs.field

        if __first:
            __first = False
            __hits = inprecs.hit_order

            for __seq in __hits:
                if __hits[__seq] == PFC.F_SEC_COMP:
                    __has_seccomp = True
                    break

        print __nametemp.format(prog=__ff[PFC.F_PROG_NAME])

        __grlist = ""
        __grs = __ff[PFC.F_GROUPS]
        for __off in range(0, len(__grs)):
            __grlist = __grlisttemp.format(acc=__grlist, gr=__grs[__off])

        print __tasktemp.format(st=__ff[PFC.F_RUNSTATUS], 
                tgid=__ff[PFC.F_THREAD_GID], pid=__ff[PFC.F_PID],
                ppid=__ff[PFC.F_PPID], trpid=__ff[PFC.F_TRACER_PID],
                uid=__ff[PFC.F_UID], euid=__ff[PFC.F_EUID], 
                suid=__ff[PFC.F_SUID], fsuid=__ff[PFC.F_FSUID],
                gid=__ff[PFC.F_GID], egid=__ff[PFC.F_EGID],
                sgid=__ff[PFC.F_SGID], fsgid=__ff[PFC.F_FSGID],
                fdsize=__ff[PFC.F_FDSIZE], grlist=__grlist)

        print __memtemp.format(peak=__ff[PFC.F_VM_PEAK], sz=__ff[PFC.F_VM_SIZE],
                lock=__ff[PFC.F_VM_LOCK], pin=__ff[PFC.F_VM_PIN],
                hwm=__ff[PFC.F_VM_HWM], rss=__ff[PFC.F_VM_RSS],
                dat=__ff[PFC.F_VM_DATA], stack=__ff[PFC.F_VM_STACK],
                exe=__ff[PFC.F_VM_EXE], lib=__ff[PFC.F_VM_LIB],
                pte=__ff[PFC.F_VM_PTE], swap=__ff[PFC.F_VM_SWAP])

        print __sigtemp.format(thr=__ff[PFC.F_THREADS], 
                squeue=__ff[PFC.F_SIG_QUEUE], pend=__ff[PFC.F_SIG_PEND],
                shpend=__ff[PFC.F_SIG_PEND], block=__ff[PFC.F_SIG_BLOCK],
                ign=__ff[PFC.F_SIG_IGN], caught=__ff[PFC.F_SIG_CAUGHT])

        print __captemp.format(inh=__ff[PFC.F_CAP_INHERIT],
                perm=__ff[PFC.F_CAP_PERM], eff=__ff[PFC.F_CAP_EFF],
                bset=__ff[PFC.F_CAP_BSET])

        if __has_seccomp:
            print __seccomptemp.format(sec=__ff[PFC.F_SEC_COMP])

        print __cpustemp.format(cpus=__ff[PFC.F_CPU_ALLOW_MASK],
                cpus_list=__ff[PFC.F_CPU_ALLOW_LIST],
                mems=__ff[PFC.F_MEM_ALLOW_MASK],
                mems_list=__ff[PFC.F_MEM_ALLOW_LIST])

        print __cswitchtemp.format(vol=__ff[PFC.F_CSWITCH_VOL],
                nonvol=__ff[PFC.F_CSWITCH_NONVOL])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/self/status")] = re_self_status

    

