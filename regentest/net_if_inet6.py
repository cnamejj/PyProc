#!/usr/bin/env python

"""Handle records from /proc/net/if_inet6 data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_if_inet6(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{ip:32s} {iidx:02x} {pflen:02x} {scope:02x} {flags:02x} \
{dev:>8s}"

    for __hilit in inprecs:
        __ff = inprecs.field

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(ip=__ff[PFC.F_IPV6_HEX], 
                iidx=__ff[PFC.F_INT_INDEX], pflen=__ff[PFC.F_PREFIX_LEN], 
                scope=__ff[PFC.F_SCOPE], flags=__ff[PFC.F_FLAGS], 
                dev=__ff[PFC.F_DEVICE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/if_inet6")] = re_net_if_inet6
