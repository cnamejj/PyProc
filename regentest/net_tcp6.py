#!/usr/bin/env python

"""Handle records from /proc/net/tcp6 data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_tcp6(inprecs):
    """Handle parsed data from /proc/net/tcp6 file"""

    __head = "  sl  local_address                         \
remote_address                        \
st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

    __template = "{seq:4d}: {lip}:{lport:04X} {rip}:{rport:04X} \
{state} {txq:08X}:{rxq:08X} {tr:02X}:{when:08X} {retrans:08X} \
{uid:5d} {tout:8d} {inode:d} {refcount:d} {ptr:016x} {ret_tout:d} \
{ack_tout:d} {qop:d} {cong:d} {sstart:}"

    print __head

    for __hilit in inprecs:
        __ff = inprecs.field
        print __template.format(seq=__ff[PFC.F_BUCKET],
                lip=__ff[PFC.F_ORIG_HEXIP], lport=__ff[PFC.F_ORIG_PORT],
                rip=__ff[PFC.F_DEST_HEXIP], rport=__ff[PFC.F_DEST_PORT],
                state=__ff[PFC.F_HEXSTATE],
                txq=__ff[PFC.F_TXQUEUE], rxq=__ff[PFC.F_RXQUEUE],
                tr=__ff[PFC.F_TIMER], when=__ff[PFC.F_TIMER_WHEN],
                retrans=__ff[PFC.F_RETRANS], uid=__ff[PFC.F_UID],
                tout=__ff[PFC.F_TIMEOUT], inode=__ff[PFC.F_INODE],
                refcount=__ff[PFC.F_REFCOUNT], ptr=__ff[PFC.F_POINTER],
                ret_tout=__ff[PFC.F_RETRY_TIMEOUT], 
                ack_tout=__ff[PFC.F_ACK_TIMEOUT],
                qop=__ff[PFC.F_QUICK_OR_PPONG],
                cong=__ff[PFC.F_CONGEST_WINDOW],
                sstart=__ff[PFC.F_SSTART_THRESH]
                )

RG.RECREATOR[PH.GET_HANDLER("/proc/net/tcp6")] = re_net_tcp6
