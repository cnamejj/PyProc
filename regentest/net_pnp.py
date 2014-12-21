#!/usr/bin/env python

"""Handle records from /proc/net/pnp files"""

import regentest as RG
import ProcHandlers as PH
import ProcFieldConstants as PFC

# ---

def re_net_pnp(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __template = "{dt:s} {val:s}"
    __headtemp = "#{tt:s}"

    __key2label = { PFC.F_DOMAIN: "domain", PFC.F_NAMESERVER: "nameserver",
            PFC.F_BOOTSERVER: "bootserver" }

    __first = True

    for __hilit in inprecs:
        __ff = inprecs.field

        if __first:
            __first = False
            print __headtemp.format(tt=__ff[PFC.F_PROTO_USED])

        if __ff[PFC.F_DOMAIN] != "":
            __key = PFC.F_DOMAIN

        elif __ff[PFC.F_NAMESERVER] != "":
            __key = PFC.F_NAMESERVER

        elif __ff[PFC.F_BOOTSERVER] != "":
            __key = PFC.F_BOOTSERVER

        else:
            continue

        print __template.format(dt=__key2label[__key], val=__ff[__key])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/pnp")] = re_net_pnp
