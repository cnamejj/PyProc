#!/usr/bin/env python

"""Handle records from /proc/net/ip_conntrack data files"""

import regentest as RG
import ProcHandlers as PH
import ProcDataConstants as PDC

PFC = PH.ProcFieldConstants

# ---

def re_net_ip_conntrack(inprecs):

    """Iterate through parsed records and re-generate data file"""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    __template = "{name:<8s} {number:d} {timeout:d} {state:s}{orig:s}{oracct:s}\
{unrep:s}{reply:s}{reacct:s}{assure:s}{mark:s}{secctx:s}{use:s}"

    __statetemp = "{state:s} "
    __tupletemp = "src={sip:s} dst={dip:s} sport={sport:d} dport={dport:d} "
    __accttemp = "packets={packs:d} bytes={bytes:d} "
    __unreptemp = "[UNREPLIED] "
    __assuretemp = "[ASSURED] "
    __marktemp = "mark={mark:d} "
    __secctxtemp = "secctx={sec:s} "
    __usetemp = "use={use:d}"

    for __hilit in inprecs:
        __ff = inprecs.field

        __val = __ff[PFC.F_STATE]
        if __val == PDC.UNKNOWN_STATE:
            __state = ""
        else:
            __state = __statetemp.format(state=__val)

        __val = __ff[PFC.F_OR_SRC_PORT]
        if __val != __val:
            __orig = ""
        else:
            __orig = __tupletemp.format(sip=__ff[PFC.F_OR_SRC_IP],
                    dip=__ff[PFC.F_OR_DST_IP], sport=__ff[PFC.F_OR_SRC_PORT],
                    dport=__ff[PFC.F_OR_DST_PORT])

        __val = __ff[PFC.F_OR_PACKETS]
        if __val != __val:
            __oracct = ""
        else:
            __oracct = __accttemp.format(packets=__val,
                    bytes=__ff[PFC.F_OR_BYTES])

        __val = __ff[PFC.F_UNREPLIED]
        if __val == "":
            __unrep = ""
        else:
            __unrep = __unreptemp

        __val = __ff[PFC.F_RE_SRC_PORT]
        if __val != __val:
            __reply = ""
        else:
            __reply = __tupletemp.format(sip=__ff[PFC.F_RE_SRC_IP],
                    dip=__ff[PFC.F_RE_DST_IP], sport=__ff[PFC.F_RE_SRC_PORT],
                    dport=__ff[PFC.F_RE_DST_PORT])

        __val = __ff[PFC.F_RE_PACKETS]
        if __val != __val:
            __reacct = ""
        else:
            __reacct = __accttemp.format(packets=__val,
                    bytes=__ff[PFC.F_RE_BYTES])

        __val = __ff[PFC.F_ASSURED]
        if __val == "":
            __assure = ""
        else:
            __assure = __assuretemp

        __val = __ff[PFC.F_MARK]
        if __val != __val:
            __reply = ""
        else:
            __mark = __marktemp.format(mark=__val)

        __val = __ff[PFC.F_SECCTX]
        if __val != __val:
            __secctx = ""
        else:
            __secctx = __secctxtemp.format(secctx=__val)

        __val = __ff[PFC.F_USE]
        if __val != __val:
            __use = ""
        else:
            __use = __usetemp.format(use=__val)

        print __template.format(name=__ff[PFC.F_PROTOCOL],
                number=__ff[PFC.F_PROTOCOL_NUM], timeout=__ff[PFC.F_TIMEOUT],
                state=__state, orig=__orig, oracct=__oracct, unrep=__unrep,
                reply=__reply, reacct=__reacct, assure=__assure, mark=__mark,
                secctx=__secctx, use=__use)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    
RG.RECREATOR[PH.GET_HANDLER("/proc/net/ip_conntrack")] = re_net_ip_conntrack
