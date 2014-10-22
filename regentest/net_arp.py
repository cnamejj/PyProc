#!/usr/bin/env python

"""Handler records from /proc/net/arp data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_arp(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "IP address       HW type     Flags       HW address            \
Mask     Device"

    __template = "{ip:<16s} 0x{hw_type:<10x}0x{flags:<10x}{hw_addr:s}     \
{mask:s}        {name:s}"

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(ip=__ff[PFC.F_IP_ADDRESS], 
                hw_type=__ff[PFC.F_HW_TYPE],
                flags=__ff[PFC.F_FLAGS],
                hw_addr=__ff[PFC.F_HW_ADDRESS],
                mask=__ff[PFC.F_MASK],
                name=__ff[PFC.F_DEVICE]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/arp")] = re_net_arp
