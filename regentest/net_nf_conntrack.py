#!/usr/bin/env python

"""Handle records from /proc/net/nf_conntrack data files"""

import regentest as RG
import ProcHandlers as PH
import ProcDataConstants as PDC

PFC = PH.ProcFieldConstants

# ---

# pylint: disable=R0914

def re_net_nf_conntrack(inprecs):

    """Iterate through parsed records and re-generate data file"""

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
    __template = "{l3prot:<8s} {l3num:d} {l4prot:<8s} {l4num:d} {timeout:d} \
{state:s}{orig:s}{oracct:s}{unrep:s}{reply:s}{reacct:s}{assure:s}{mark:s}\
{secctx:s}{zone:s}{delta:s}{use:s}"

    __statetemp = "{state:s} "
    __tupletemp = "src={sip:s} dst={dip:s} sport={sport:d} dport={dport:d} "
    __noportstemp = "src={sip:s} dst={dip:s} "
    __accttemp = "packets={packs:d} bytes={bytes:d} "
    __unreptemp = "[UNREPLIED] "
    __assuretemp = "[ASSURED] "
    __marktemp = "mark={mark:d} "
    __secctxtemp = "secctx={sec:s} "
    __zonetemp = "zone={zone:d} "
    __deltatemp = "delta-time={delta:d} "
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
        elif __val == PDC.NO_PORT:
            __orig = __noportstemp.format(sip=__ff[PFC.F_OR_SRC_IP],
                    dip=__ff[PFC.F_OR_DST_IP])
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
        elif __val == PDC.NO_PORT:
            __reply = __noportstemp.format(sip=__ff[PFC.F_RE_SRC_IP],
                    dip=__ff[PFC.F_RE_DST_IP])
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
            __mark = ""
        else:
            __mark = __marktemp.format(mark=__val)

        __val = __ff[PFC.F_SECCTX]
        if __val == "":
            __secctx = ""
        else:
            __secctx = __secctxtemp.format(sec=__val)

        __val = __ff[PFC.F_ZONE]
        if __val != __val:
            __zone = ""
        else:
            __zone = __zonetemp.format(zone=__val)

        __val = __ff[PFC.F_DELTA_TIME]
        if __val != __val:
            __delta = ""
        else:
            __delta = __deltatemp.format(delta=__val)

        __val = __ff[PFC.F_USE]
        if __val != __val:
            __use = ""
        else:
            __use = __usetemp.format(use=__val)

        print __template.format(l3prot=__ff[PFC.F_L3_PROTOCOL],
                l3num=__ff[PFC.F_L3_PROTOCOL_NUM], l4prot=__ff[PFC.F_PROTOCOL],
                l4num=__ff[PFC.F_PROTOCOL_NUM], timeout=__ff[PFC.F_TIMEOUT],
                state=__state, orig=__orig, oracct=__oracct, unrep=__unrep,
                reply=__reply, reacct=__reacct, assure=__assure, mark=__mark,
                secctx=__secctx, zone=__zone, delta=__delta, use=__use)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

# pylint: enable=R0914

RG.RECREATOR[PH.GET_HANDLER("/proc/net/nf_conntrack")] = re_net_nf_conntrack
