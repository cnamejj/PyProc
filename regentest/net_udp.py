#!/usr/bin/env python

"""Handle records from /proc/net/udp data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_udp(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __fixedline = '{line:127}'

    __head = "  sl  local_address rem_address   st tx_queue rx_queue tr \
tm->when retrnsmt   uid  timeout inode ref pointer drops"

    __template = "{seq:5d}: {lip}:{lport:04X} {rip}:{rport:04X} \
{state} {txq:08X}:{rxq:08X} {tr:02X}:{when:08X} {retrans:08X} \
{uid:5d} {tout:8d} {inode:d} {refcount:d} {ptr:016X} {drops:d}"

    print __fixedline.format(line=__head)

    for __hilit in inprecs:
        __ff = inprecs.field
        __out = __template.format(seq=__ff[PFC.F_BUCKET],
                lip=__ff[PFC.F_ORIG_HEXIP], lport=__ff[PFC.F_ORIG_PORT],
                rip=__ff[PFC.F_DEST_HEXIP], rport=__ff[PFC.F_DEST_PORT],
                state=__ff[PFC.F_HEXSTATE],
                txq=__ff[PFC.F_TXQUEUE], rxq=__ff[PFC.F_RXQUEUE],
                tr=__ff[PFC.F_TIMER], when=__ff[PFC.F_TIMER_WHEN],
                retrans=__ff[PFC.F_RETRANS], uid=__ff[PFC.F_UID],
                tout=__ff[PFC.F_TIMEOUT], inode=__ff[PFC.F_INODE],
                refcount=__ff[PFC.F_REFCOUNT], ptr=__ff[PFC.F_POINTER],
                drops=__ff[PFC.F_DROPS]
                )
        print __fixedline.format(line=__out)

RG.RECREATOR[PH.GET_HANDLER("/proc/net/udp")] = re_net_udp

