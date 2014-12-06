#!/usr/bin/env python

"""Handle records from /proc/net/rt_cache data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_rt_cache(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __fixedline = "{line:127}"

    __head = "Iface\tDestination\tGateway \tFlags\t\tRefCnt\tUse\tMetric\t\
Source\t\tMTU\tWindow\tIRTT\tTOS\tHHRef\tHHUptod\tSpecDst"

    __template = "{iface:s}\t{dhex:8s}\t{ghex:8s}\t{flags:8X}\t{refc:d}\t\
{usec:d}\t{metric:d}\t{shex:8s}\t{mtu:d}\t{win:d}\t{irtt:d}\t{tos:02X}\t\
{hhref:d}\t{hhup:1d}\t{sphex:8s}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __fixedline.format(line=__head)

    for __hilit in inprecs:
        __ff = inprecs.field

        __out = __template.format(iface=__ff[PFC.F_INTERFACE],
                dhex=__ff[PFC.F_DEST_HEXIP], ghex=__ff[PFC.F_GATE_HEXIP],
                flags=__ff[PFC.F_FLAGS], refc=__ff[PFC.F_REFCOUNT],
                usec=__ff[PFC.F_USECOUNT], metric=__ff[PFC.F_METRIC],
                shex=__ff[PFC.F_SRCE_HEXIP], mtu=__ff[PFC.F_MTU],
                win=__ff[PFC.F_WINDOW], irtt=__ff[PFC.F_IRTT],
                tos=__ff[PFC.F_TOS], hhref=__ff[PFC.F_HHREF],
                hhup=__ff[PFC.F_HHUPTOD], sphex=__ff[PFC.F_SPEC_HEXIP])

        print __fixedline.format(line=__out)

RG.RECREATOR[PH.GET_HANDLER("/proc/net/rt_cache")] = re_net_rt_cache
