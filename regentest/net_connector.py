#!/usr/bin/env python

"""Handle records from /proc/net/connector data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_connector(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __head = "Name            ID"

    __template = "{name:15} {ind:d}:{val:d}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field

        print __template.format(name=__ff[PFC.F_NAME], ind=__ff[PFC.F_ID_IDX],
                val=__ff[PFC.F_ID_VAL]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/connector")] = re_net_connector

