#!/usr/bin/env python

# ---
# (C) 2012-2014 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
Handlers for file in the /proc/net directory (and subdirectories)
"""

# pylint: disable=C0302

import socket
import binascii
import IPAddressConv
import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

REGISTER_FILE = PBR.register_file
REGISTER_PARTIAL_FILE = PBR.register_partial_file

NAME = PBR.FIELD_NAME
POS = PBR.FIELD_NUMBER
CONV = PBR.CONVERSION
ERRVAL = PBR.ERROR_VAL
BASE = PBR.NUM_BASE
PREFIX = PBR.PREFIX_VAL
SUFFIX = PBR.SUFFIX_VAL
BEFORE = PBR.BEFORE_VAL
AFTER = PBR.AFTER_VAL
WORDS = PBR.WORDS_VAL
SUBWORD = PBR.SUBWORD
HAS = PBR.HAS_VAL
BTOOTH_FULL_REC_SIZE = 9
BTOOTH_MIN_REC_SIZE = 7

STATE_LIST = PDC.STATE_LIST




# ---
class ProcNetNETLINK(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/netlink"""
# source: net/netlink/af_netlink.c
#        seq_printf(seq, "%pK %-3d %-6d %08x %-8d %-8d %pK %-8d %-8d %-8lu\n",
#                   s,
#                   s->sk_protocol,
#                   nlk->pid,
#                   nlk->groups ? (u32)nlk->groups[0] : 0,
#                   sk_rmem_alloc_get(s),
#                   sk_wmem_alloc_get(s),
#                   nlk->cb,
#                   atomic_read(&s->sk_refcnt),
#                   atomic_read(&s->sk_drops),
#                   sock_i_ino(s)
#                );

    def extra_init(self, *opts):
        self.minfields = 10
        self.skipped = "sk"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SOCKET_POINTER,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_PROTOCOL, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_GROUPS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RMEM_ALLOC,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_WMEM_ALLOC,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_DUMP_STR } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_LOCKS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_DROPS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INODE, CONV: long } )


        self.protocol = 0
        self.pid = 0
        self.groups = 0
        self.dump = 0
        self.locks = 0
        self.drops = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# pylint: disable=C0301
#
# sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
# 0000000000000000 0   4196011 00000000 0        0        0000000000000000 2        0        11034
# 0000000000000000 0   0      00000000 0        0        0000000000000000 2        0        8
# 0000000000000000 0   1707   000a0501 0        0        0000000000000000 2        0        11033
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_SOCKET_POINTER] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_PID] = 0
            self.field[PFC.F_GROUPS] = 0
            self.field[PFC.F_RMEM_ALLOC] = 0
            self.field[PFC.F_WMEM_ALLOC] = 0
            self.field[PFC.F_DUMP] = 0
            self.field[PFC.F_DUMP_STR] = ""
            self.field[PFC.F_LOCKS] = 0
            self.field[PFC.F_DROPS] = 0
            self.field[PFC.F_INODE] = 0

        if len(self.field[PFC.F_DUMP_STR]) == 16:
            self.field[PFC.F_DUMP] = long(self.field[PFC.F_DUMP_STR], 16)
        else:
            self.field[PFC.F_DUMP] = long(self.field[PFC.F_DUMP_STR])
        self.protocol = self.field[PFC.F_PROTOCOL]
        self.pid = self.field[PFC.F_PID]
        self.groups = self.field[PFC.F_GROUPS]
        self.dump = self.field[PFC.F_DUMP]
        self.locks = self.field[PFC.F_LOCKS]
        self.drops = self.field[PFC.F_DROPS]

        return(self.protocol, self.pid, self.groups, self.dump, self.locks,
                self.drops)
#
REGISTER_FILE("/proc/net/netlink", ProcNetNETLINK)
REGISTER_PARTIAL_FILE("netlink", ProcNetNETLINK)


# ---
class ProcNetCONNECTOR(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/connector"""
# source: drivers/connector/connector.c
#  list_for_each_entry(cbq, &dev->queue_list, callback_entry) {
#          seq_printf(m, "%-15s %u:%u\n",
#                     cbq->id.name,
#                     cbq->id.id.idx,
#                     cbq->id.id.val);

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Name"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_NAME } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ID_IDX, BEFORE: ":",
                CONV: long })
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ID_VAL, AFTER: ":",
                CONV: long } )

        self.name = ""
        self.id_idx = 0
        self.id_val = 0
        return

    def extra_next(self, sio):

# -- Sample records
# Name            ID
# cn_proc         1:1

        if sio.buff == "":
            self.field[PFC.F_NAME] = ""
            self.field[PFC.F_ID_IDX] = 0
            self.field[PFC.F_ID_VAL] = 0

        self.name = self.field[PFC.F_NAME]
        self.id_idx = self.field[PFC.F_ID_IDX]
        self.id_val = self.field[PFC.F_ID_VAL]

        return(self.name, self.id_idx, self.id_val)
#
REGISTER_FILE("/proc/net/connector", ProcNetCONNECTOR)
REGISTER_PARTIAL_FILE("connector", ProcNetCONNECTOR)


# ---
class ProcNetPROTOCOLS(PBR.FixedWhitespaceDelimRecs):
    """
    Specific use of simple col reading class, for /proc/net/protocols file
    """

# source: net/core/sock.c
#
# pylint: disable=C0301
#
#    seq_printf(seq, "%-9s %4u %6d  %6ld   %-3s %6u   %-3s  %-10s "
#                    "%2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c %2c\n",
#               proto->name,
#               proto->obj_size,
#               sock_prot_inuse_get(seq_file_net(seq), proto),
#               proto->memory_allocated != NULL ? atomic_long_read(proto->memory_allocated) : -1L,
#               proto->memory_pressure != NULL ? *proto->memory_pressure ? "yes" : "no" : "NI",
#               proto->max_header,
#               proto->slab == NULL ? "no" : "yes",
#               module_name(proto->owner),
#               proto_method_implemented(proto->close),
#               proto_method_implemented(proto->connect),
#               proto_method_implemented(proto->disconnect),
#               proto_method_implemented(proto->accept),
#               proto_method_implemented(proto->ioctl),
#               proto_method_implemented(proto->init),
#               proto_method_implemented(proto->destroy),
#               proto_method_implemented(proto->shutdown),
#               proto_method_implemented(proto->setsockopt),
#               proto_method_implemented(proto->getsockopt),
#               proto_method_implemented(proto->sendmsg),
#               proto_method_implemented(proto->recvmsg),
#               proto_method_implemented(proto->sendpage),
#               proto_method_implemented(proto->bind),
#               proto_method_implemented(proto->backlog_rcv),
#               proto_method_implemented(proto->hash),
#               proto_method_implemented(proto->unhash),
#               proto_method_implemented(proto->get_port),
#               proto_method_implemented(proto->enter_memory_pressure));
#
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 27
        self.skipped = "protocol"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PROTOCOL } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_SOCKETS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MEMORY, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_PRESSURE, } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_MAX_HEADER,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_SLAB } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_MODULE } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_CLOSE } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_CONNECT } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_DISCONNECT } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_ACCEPT } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_IOCTL } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_INIT } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_DESTROY } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_SHUTDOWN } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_SETSOCKOPT } )
        PBR.add_parse_rule(self, { POS: 17, NAME: PFC.F_GETSOCKOPT } )
        PBR.add_parse_rule(self, { POS: 18, NAME: PFC.F_SENDMSG } )
        PBR.add_parse_rule(self, { POS: 19, NAME: PFC.F_RECVMSG } )
        PBR.add_parse_rule(self, { POS: 20, NAME: PFC.F_SENDPAGE } )
        PBR.add_parse_rule(self, { POS: 21, NAME: PFC.F_BIND } )
        PBR.add_parse_rule(self, { POS: 22, NAME: PFC.F_BACKLOG_RCV } )
        PBR.add_parse_rule(self, { POS: 23, NAME: PFC.F_HASH } )
        PBR.add_parse_rule(self, { POS: 24, NAME: PFC.F_UNHASH } )
        PBR.add_parse_rule(self, { POS: 25, NAME: PFC.F_GET_PORT } )
        PBR.add_parse_rule(self, { POS: 26, NAME: PFC.F_ENTER_PRESSURE } )

        self.protocol = ""
        self.size = 0
        self.sockets = 0
        self.memory = 0
        self.module = ""
        return

    def extra_next(self, sio):

# -- Sample entries
#
# pylint: disable=C0301
#
# protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em
# BNEP       664      0      -1   NI       0   no   bnep        n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# RFCOMM     680      0      -1   NI       0   no   rfcomm      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# SCO        680      0      -1   NI       0   no   bluetooth   n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# PACKET    1344      1      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_SOCKETS] = 0
            self.field[PFC.F_MEMORY] = 0
            self.field[PFC.F_PRESSURE] = ""
            self.field[PFC.F_MAX_HEADER] = 0
            self.field[PFC.F_SLAB] = ""
            self.field[PFC.F_MODULE] = ""
            self.field[PFC.F_CLOSE] = ""
            self.field[PFC.F_CONNECT] = ""
            self.field[PFC.F_DISCONNECT] = ""
            self.field[PFC.F_ACCEPT] = ""
            self.field[PFC.F_IOCTL] = ""
            self.field[PFC.F_INIT] = ""
            self.field[PFC.F_DESTROY] = ""
            self.field[PFC.F_SHUTDOWN] = ""
            self.field[PFC.F_SETSOCKOPT] = ""
            self.field[PFC.F_GETSOCKOPT] = ""
            self.field[PFC.F_SENDMSG] = ""
            self.field[PFC.F_RECVMSG] = ""
            self.field[PFC.F_SENDPAGE] = ""
            self.field[PFC.F_BIND] = ""
            self.field[PFC.F_BACKLOG_RCV] = ""
            self.field[PFC.F_HASH] = ""
            self.field[PFC.F_UNHASH] = ""
            self.field[PFC.F_GET_PORT] = ""
            self.field[PFC.F_ENTER_PRESSURE] = ""

        self.protocol = self.field[PFC.F_PROTOCOL]
        self.size = self.field[PFC.F_SIZE]
        self.sockets = self.field[PFC.F_SOCKETS]
        self.memory = self.field[PFC.F_MEMORY]
        self.module = self.field[PFC.F_MODULE]

        return(self.protocol, self.size, self.sockets, self.memory,
                self.module)
#
REGISTER_FILE("/proc/net/protocols", ProcNetPROTOCOLS)
REGISTER_PARTIAL_FILE("protocols", ProcNetPROTOCOLS)


# ---
class ProcNetROUTE(PBR.FixedWhitespaceDelimRecs):
    """Specific use of simple col reading class, for /proc/net/route file"""
# source: net/ipv4/fib_trie.c
#                        if (fi)
#                                seq_printf(seq,
#                                         "%s\t%08X\t%08X\t%04X\t%d\t%u\t"
#                                         "%d\t%08X\t%d\t%u\t%u%n",
#                                         fi->fib_dev ? fi->fib_dev->name : "*",
#                                         prefix,
#                                         fi->fib_nh->nh_gw, flags, 0, 0,
#                                         fi->fib_priority,
#                                         mask,
#                                         (fi->fib_advmss ?
#                                          fi->fib_advmss + 40 : 0),
#                                         fi->fib_window,
#                                         fi->fib_rtt >> 3, &len);
#                        else
#                                seq_printf(seq,
#                                         "*\t%08X\t%08X\t%04X\t%d\t%u\t"
#                                         "%d\t%08X\t%d\t%u\t%u%n",
#                                         prefix, 0, flags, 0, 0, 0,
#                                         mask, 0, 0, 0, &len);
#                        seq_printf(seq, "%*s\n", 127 - len, "");

    def extra_init(self, *opts):
        self.minfields = 11
        self.skipped = "Iface"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INTERFACE } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEST_HEXIP } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_GATE_HEXIP } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_FLAGS, CONV: long,
                BASE:16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_USECOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_METRIC, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_MASK_HEXIP } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_MTU, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_WINDOW, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_IRTT, CONV: long } )

        self.interface = ""
        self.destination = ""
        self.gateway = ""
        self.netmask = ""
        return

    def extra_next(self, sio):

# -- Samples lines.
#
# pylint: disable=C0301
#
# Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
# eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0
# eth0	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0
# eth0	0001A8C0	00000000	0001	0	0	1	00FFFFFF	0	0	0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_INTERFACE] = PDC.ANY_INTERFACE
            self.field[PFC.F_DEST_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_GATE_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_FLAGS] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_USECOUNT] = 0
            self.field[PFC.F_METRIC] = 0
            self.field[PFC.F_MASK_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_MTU] = 0
            self.field[PFC.F_WINDOW] = 0
            self.field[PFC.F_IRTT] = 0
            self.field[PFC.F_DEST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_GATEWAY] = PDC.ANY_IP_ADDR
            self.field[PFC.F_NETMASK] = PDC.ANY_IP_ADDR

        else:
            __lip = PBR.conv_by_rules(self.field[PFC.F_DEST_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_GATE_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_GATEWAY] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_MASK_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_NETMASK] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))

        self.interface = self.field[PFC.F_INTERFACE]
        self.destination = self.field[PFC.F_DEST_IP]
        self.gateway = self.field[PFC.F_GATEWAY]
        self.netmask = self.field[PFC.F_NETMASK]

        return(self.interface, self.destination, self.gateway, self.netmask)
#
REGISTER_FILE("/proc/net/route", ProcNetROUTE)
REGISTER_PARTIAL_FILE("route", ProcNetROUTE)


# ---
class ProcNetPACKET(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/packet"""
# source: net/packet/af_packet.c
#        seq_printf(seq,
#                   "%pK %-6d %-4d %04x   %-5d %1d %-6u %-6u %-6lu\n",
#                   s,
#                   atomic_read(&s->sk_refcnt),
#                   s->sk_type,
#                   ntohs(po->num),
#                   po->ifindex,
#                   po->running,
#                   atomic_read(&s->sk_rmem_alloc),
#                   sock_i_uid(s),
#                   sock_i_ino(s));

    def extra_init(self, *opts):
        self.minfields = 9
        self.skipped = "sk"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SOCKET_POINTER,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_TYPE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_PROTOCOL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_INT_INDEX,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_RUNNING, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RMEM_ALLOC,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_INODE, CONV: long } )

        self.type = 0
        self.protocol = 0
        self.interface_index = 0
        self.running = 0
        self.rmem_alloc = 0
        self.uid = 0
        return

    def extra_next(self, sio):
# -- Sample records
# sk       RefCnt Type Proto  Iface R Rmem   User   Inode
# 0000000000000000 3      3    0003   2     1 0      0      36995

        if sio.buff == "":
            self.field[PFC.F_SOCKET_POINTER] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_TYPE] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_RUNNING] = 0
            self.field[PFC.F_RMEM_ALLOC] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_INODE] = 0

        self.type = self.field[PFC.F_TYPE]
        self.protocol = self.field[PFC.F_PROTOCOL]
        self.interface_index = self.field[PFC.F_INT_INDEX]
        self.running = self.field[PFC.F_RUNNING]
        self.rmem_alloc = self.field[PFC.F_RMEM_ALLOC]
        self.uid = self.field[PFC.F_UID]

        return(self.type, self.protocol, self.interface_index, self.running,
                self.rmem_alloc, self.uid)
#
REGISTER_FILE("/proc/net/packet", ProcNetPACKET)
REGISTER_PARTIAL_FILE("packet", ProcNetPACKET)


# ---
class ProcNetSOFTNETSTAT(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/softnet_stat"""
#
# Different kernels handle this differently, barring further changes, one of the
# following should apply to your system.
#
# source: net/core/dev.c
#         seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
#                   sd->processed, sd->dropped, sd->time_squeeze, 0,
#                   0, 0, 0, 0, /* was fastroute */
#                   sd->cpu_collision, sd->received_rps);
#
# --or--
#
# source: net/core/net-procfs.c
#
#        seq_printf(seq,
#                   "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
#                   sd->processed, sd->dropped, sd->time_squeeze, 0,
#                   0, 0, 0, 0, /* was fastroute */
#                   sd->cpu_collision, sd->received_rps, flow_limit_count);

    def extra_init(self, *opts):
        self.minfields = 10

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PROCESSED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DROPPED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_TIME_SQUEEZE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_ZERO1, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_ZERO2, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_ZERO3, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_ZERO4, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_ZERO5, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_CPU_COLL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_RECEIVED_RPS,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_FLOW_LIM_COUNT,
                CONV: long, BASE: 16 } )

        self.processed = 0
        self.dropped = 0
        self.time_squeeze = 0
        self.cpu_coll = 0
        self.received_rps = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
#
# pylint: disable=C0301
#
# Processed Dropped Time_Squeeze Null1 Null2   Null3    Null4    Null5    CPU_Coll Received_RPS
# 001fc1c7 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 00002970 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 000041b2 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
#
# pylint: enable=C0301
#
# For some systems an additional colum with the "flow limit count" will be in
# the file

        if sio.buff == "":
            self.field[PFC.F_PROCESSED] = 0
            self.field[PFC.F_DROPPED] = 0
            self.field[PFC.F_TIME_SQUEEZE] = 0
            self.field[PFC.F_ZERO1] = 0
            self.field[PFC.F_ZERO2] = 0
            self.field[PFC.F_ZERO3] = 0
            self.field[PFC.F_ZERO4] = 0
            self.field[PFC.F_ZERO5] = 0
            self.field[PFC.F_CPU_COLL] = 0
            self.field[PFC.F_RECEIVED_RPS] = 0
            self.field[PFC.F_FLOW_LIM_COUNT] = 0

        self.processed = self.field[PFC.F_PROCESSED]
        self.dropped = self.field[PFC.F_DROPPED]
        self.time_squeeze = self.field[PFC.F_TIME_SQUEEZE]
        self.cpu_coll = self.field[PFC.F_CPU_COLL]
        self.received_rps = self.field[PFC.F_RECEIVED_RPS]

        return(self.processed, self.dropped, self.time_squeeze, self.cpu_coll,
                self.received_rps)
#
REGISTER_FILE("/proc/net/softnet_stat", ProcNetSOFTNETSTAT)
REGISTER_PARTIAL_FILE("softnet_stat", ProcNetSOFTNETSTAT)



# ---
class ProcNetARP(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/arp"""
# source: net/ipv4/arp.c
#        seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
#                   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);

    def extra_init(self, *opts):
        self.minfields = 6
        self.skipped = "IP"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_IP_ADDRESS} )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_HW_TYPE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_FLAGS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HW_ADDRESS } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_MASK } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_DEVICE } )

        self.ip_addr = ""
        self.hw_addr = ""
        self.device = ""
        return

    def extra_next(self, sio):
# -- Samples lines.
# IP address       HW type     Flags       HW address            Mask     Device
# 192.168.1.13     0x1         0x2         00:1f:c6:3b:8c:b8     *        eth0
# 192.168.1.252    0x1         0x2         70:56:81:96:ba:a7     *        eth0
# 192.168.1.178    0x1         0x2         3c:07:54:57:bb:a5     *        eth0

        if sio.buff == "":
            self.field[PFC.F_IP_ADDRESS] = PDC.ANY_IP_ADDR
            self.field[PFC.F_HW_TYPE] = "0x0"
            self.field[PFC.F_FLAGS] = "0x0"
            self.field[PFC.F_HW_ADDRESS] = PDC.ANY_HW_ADDR
            self.field[PFC.F_MASK] = "*"
            self.field[PFC.F_DEVICE] = PDC.ANY_INTERFACE

        self.ip_addr = self.field[PFC.F_IP_ADDRESS]
        self.hw_addr = self.field[PFC.F_HW_TYPE]
        self.device = self.field[PFC.F_DEVICE]

        return(self.ip_addr, self.hw_addr, self.device)
#
REGISTER_FILE("/proc/net/arp", ProcNetARP)
REGISTER_PARTIAL_FILE("arp", ProcNetARP)



# ---
class ProcNetDEVMCAST(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/dev_mcast"""
# source: net/core/dev_addr_lists.ca
#                seq_printf(seq, "%-4d %-15s %-5d %-5d ", dev->ifindex,
#                           dev->name, ha->refcount, ha->global_use);
#
#                for (i = 0; i < dev->addr_len; i++)
#                        seq_printf(seq, "%02x", ha->addr[i]);

    def extra_init(self, *opts):
        self.minfields = 5

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INT_INDEX,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEVICE } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_GLOBAL_USE,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_DEV_ADDR } )

        self.device = ""
        self.ref_count = 0
        self.global_use = 0
        return

    def extra_next(self, sio):
# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# IFaceIndex Device RefCount GlobalUse DeviceAddress
# 2    eth0            1     0     01005e000001
# 2    eth0            1     0     333300000001
# 2    eth0            1     0     3333ff01e486

        if sio.buff == "":
            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_GLOBAL_USE] = 0
            self.field[PFC.F_DEV_ADDR] = "000000000000"

        self.device = self.field[PFC.F_DEVICE]
        self.ref_count = self.field[PFC.F_REFCOUNT]
        self.global_use = self.field[PFC.F_GLOBAL_USE]

        return(self.device, self.ref_count, self.global_use)
#
REGISTER_FILE("/proc/net/dev_mcast", ProcNetDEVMCAST)
REGISTER_PARTIAL_FILE("dev_mcast", ProcNetDEVMCAST)



# ---
class ProcNetDEV(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/net/dev
    """

# source: net/core/dev.c
#
# pylint: disable=C0301
#
#        seq_printf(seq, "%6s: %7llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu "
#                   "%8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
#                   dev->name, stats->rx_bytes, stats->rx_packets,
#                   stats->rx_errors,
#                   stats->rx_dropped + stats->rx_missed_errors,
#                   stats->rx_fifo_errors,
#                   stats->rx_length_errors + stats->rx_over_errors +
#                   stats->rx_crc_errors + stats->rx_frame_errors,
#                   stats->rx_compressed, stats->multicast,
#                   stats->tx_bytes, stats->tx_packets,
#                   stats->tx_errors, stats->tx_dropped,
#                   stats->tx_fifo_errors, stats->collisions,
#                   stats->tx_carrier_errors +
#                   stats->tx_aborted_errors +
#                   stats->tx_window_errors +
#                   stats->tx_heartbeat_errors,
#                   stats->tx_compressed);
#
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 17
        self.skipped = "face"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_DEVICE, SUFFIX: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_RX_BYTES, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_RX_PACKETS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_RX_ERRORS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RX_DROP, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_RX_FIFO, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RX_FRAME, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_RX_COMPRESSED,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_RX_MULTICAST,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_TX_BYTES, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_TX_PACKETS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_TX_ERRORS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_TX_DROP, CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_TX_FIFO, CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_TX_COLLISION,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_TX_CARRIER,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_TX_COMPRESSED,
                CONV: long } )

        self.device = ""
        self.rx_packets = 0
        self.rx_errors = 0
        self.tx_packets = 0
        self.tx_errors = 0
        return

    def extra_next(self, sio):

# -- Samples lines.
#
# pylint: disable=C0301
#
# Inter-|   Receive                                                |  Transmit
#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
#     lo: 102519022  306837    0    0    0     0          0         0 102519022  306837    0    0    0     0       0          0
#   eth0: 1618664727 5080413    0    0    0     0          0    312848 915217483 4396111    0    0    0     0       0          0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_DEVICE] = PDC.ANY_INTERFACE
            self.field[PFC.F_RX_BYTES] = 0
            self.field[PFC.F_RX_PACKETS] = 0
            self.field[PFC.F_RX_ERRORS] = 0
            self.field[PFC.F_RX_DROP] = 0
            self.field[PFC.F_RX_FIFO] = 0
            self.field[PFC.F_RX_FRAME] = 0
            self.field[PFC.F_RX_COMPRESSED] = 0
            self.field[PFC.F_RX_MULTICAST] = 0
            self.field[PFC.F_TX_BYTES] = 0
            self.field[PFC.F_TX_PACKETS] = 0
            self.field[PFC.F_TX_ERRORS] = 0
            self.field[PFC.F_TX_DROP] = 0
            self.field[PFC.F_TX_FIFO] = 0
            self.field[PFC.F_TX_COLLISION] = 0
            self.field[PFC.F_TX_CARRIER] = 0
            self.field[PFC.F_TX_COMPRESSED] = 0

        self.device = self.field[PFC.F_DEVICE]
        self.rx_packets = self.field[PFC.F_RX_PACKETS]
        self.rx_errors = self.field[PFC.F_RX_ERRORS]
        self.tx_packets = self.field[PFC.F_TX_PACKETS]
        self.tx_errors = self.field[PFC.F_TX_ERRORS]

        return(self.device, self.rx_packets, self.rx_errors, self.tx_packets,
                self.tx_errors)
#
REGISTER_FILE("/proc/net/dev", ProcNetDEV)
REGISTER_PARTIAL_FILE("dev", ProcNetDEV)



# ---
class ProcNetIFINET6(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/if_inet6"""
# source: net/ipv6/addrconf.c
#        seq_printf(seq, "%pi6 %02x %02x %02x %02x %8s\n",
#                   &ifp->addr,
#                   ifp->idev->dev->ifindex,
#                   ifp->prefix_len,
#                   ifp->scope,
#                   ifp->flags,
#                   ifp->idev->dev->name);

    def extra_init(self, *opts):
        self.minfields = 6
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_IPV6_HEX } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_INT_INDEX_HEX } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_INT_INDEX, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PREFIX_LEN_HEX } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PREFIX_LEN, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SCOPE_HEX } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SCOPE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_FLAGS_HEX } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_FLAGS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_DEVICE } )

        self.ipv6 = PDC.ANY_IPV6_ADDR
        self.ipv6_hex = PDC.ANY_IPV6_ADDR_HEX
        self.scope = 0
        self.device = PDC.ANY_DEVICE
        return

    def extra_next(self, sio):
# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# ipv6 interface_index prefix_len scope flags device
# fe80000000000000ca6000fffe01e486 02 40 20 80     eth0
# 00000000000000000000000000000001 01 80 10 80       lo

        if sio.buff == "":
            self.field[PFC.F_IPV6_HEX] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_INT_INDEX_HEX] = "00"
            self.field[PFC.F_PREFIX_LEN_HEX] = "00"
            self.field[PFC.F_SCOPE_HEX] = "00"
            self.field[PFC.F_FLAGS_HEX] = "00"
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_IPV6] = PDC.ANY_IPV6_ADDR
            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_PREFIX_LEN] = 0
            self.field[PFC.F_SCOPE] = 0
            self.field[PFC.F_FLAGS] = 0

        else:
            self.field[PFC.F_IPV6] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    sio.get_word(0))

        self.ipv6 = self.field[PFC.F_IPV6]
        self.ipv6_hex = self.field[PFC.F_IPV6_HEX]
        self.scope = self.field[PFC.F_SCOPE]
        self.device = self.field[PFC.F_DEVICE]

        return(self.ipv6, self.ipv6_hex, self.scope, self.device)
#
REGISTER_FILE("/proc/net/if_inet6", ProcNetIFINET6)
REGISTER_PARTIAL_FILE("if_inet6", ProcNetIFINET6)



# ---
class ProcNetIGMP6(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/igmp6"""
# source: net/ipv6/mcast.c
#        seq_printf(seq,
#                   "%-4d %-15s %pi6 %5d %08X %ld\n",
#                   state->dev->ifindex, state->dev->name,
#                   &im->mca_addr,
#                   im->mca_users, im->mca_flags,
#                   (im->mca_flags&MAF_TIMER_RUNNING) ?
#                   jiffies_to_clock_t(im->mca_timer.expires-jiffies) : 0);

    def extra_init(self, *opts):
        self.minfields = 6
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INT_INDEX,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEVICE } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MCAST_ADDR_HEX } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MCAST_USERS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_MCAST_FLAGS,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER_EXPIRE,
                CONV: long } )

        self.device = PDC.ANY_DEVICE
        self.mcast_addr = PDC.PRESENT_ANY_IPV6_ADDR
        self.mcast_users = 0
        self.mcast_flags = PDC.NULL_MASK_HEX
        return

    def extra_next(self, sio):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
#
# pylint: disable=C0301
#
# IntFaceIndex DeviceName MCastAddress             MCastUsers MCastFlags TimerExp
# 1    lo              ff020000000000000000000000000001     1 0000000C 0
# 2    eth0            ff0200000000000000000001ff01e486     1 00000004 0
# 2    eth0            ff020000000000000000000000000001     1 0000000C 0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_MCAST_ADDR_HEX] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_MCAST_ADDR] = PDC.PRESENT_ANY_IPV6_ADDR
            self.field[PFC.F_MCAST_USERS] = 0
            self.field[PFC.F_MCAST_FLAGS] = PDC.NULL_MASK_HEX
            self.field[PFC.F_TIMER_EXPIRE] = 0

        else:
            self.field[PFC.F_MCAST_ADDR] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    sio.get_word(2))

        self.device = self.field[PFC.F_DEVICE]
        self.mcast_addr = self.field[PFC.F_MCAST_ADDR]
        self.mcast_users = self.field[PFC.F_MCAST_USERS]
        self.mcast_flags = self.field[PFC.F_MCAST_FLAGS]

        return(self.device, self.mcast_addr, self.mcast_users,
                self.mcast_flags)
#
REGISTER_FILE("/proc/net/igmp6", ProcNetIGMP6)
REGISTER_PARTIAL_FILE("igmp6", ProcNetIGMP6)



# ---
class ProcNetIPCONNTRACK(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/ip_conntrack"""
#
# source: net/ipv4/netfilter/nf_conntrack_l3proto_ipv4_compat.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 12

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PROTOCOL } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_PROTOCOL_NUM,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_TIMEOUT, CONV: long } )

        self.__tuple_pref = "src="
        self.__unreplied_pref = "["
        self.__packets_pref = "packets="
        self.__bytes_pref = "bytes="
        self.__assured_pref = "["
        self.__mark_pref = "mark="
        self.__secctx_pref = "secctx="
        self.__use_pref = "use="
        self.__val_delim = "="

        self.protocol = ""
        self.src_port = 0
        self.src_ip = PDC.ANY_IP_ADDR
        self.state = PDC.UNKNOWN_STATE
        self.timeout = 0
        self.dst_ip = PDC.ANY_IP_ADDR
        self.dst_port = 0
        return

    def extra_next(self, sio):

# -- Sample records, there is no header line and the fields presented can very
# -- from record to record, only the first 3 are guaranteed to always the
# -- protocol name, protocol number, and timeout. The rest will always be in
# -- the same order, but a number of fields may or may not be there.
#
# pylint: disable=C0301
#
# tcp      6 38 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55894 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55894 [ASSURED] mark=0 use=2
# tcp      6 34 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55890 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55890 [ASSURED] mark=0 use=2
# udp      17 18 src=192.168.1.14 dst=216.69.185.100 sport=9408 dport=53 src=216.69.185.100 dst=192.168.1.14 sport=53 dport=9408 mark=0 use=2
# udp      17 18 src=192.168.1.14 dst=192.42.93.30 sport=15257 dport=53 src=192.42.93.30 dst=192.168.1.14 sport=53 dport=15257 mark=0 use=2
# tcp      6 431959 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=33934 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=33934 [ASSURED] mark=0 use=2
# udp      17 17 src=127.0.0.1 dst=127.0.0.1 sport=60942 dport=53 src=127.0.0.1 dst=127.0.0.1 sport=53 dport=60942 mark=0 use=2
# tcp      6 431988 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=35348 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=35348 [ASSURED] mark=0 use=2
# udp      17 17 src=127.0.0.1 dst=127.0.0.1 sport=59830 dport=53 src=127.0.0.1 dst=127.0.0.1 sport=53 dport=59830 mark=0 use=2
#
# pylint: enable=C0301

        self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
        self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_OR_SRC_PORT] = PDC.NAN
        self.field[PFC.F_OR_DST_PORT] = PDC.NAN
        self.field[PFC.F_UNREPLIED] = ""
        self.field[PFC.F_OR_PACKETS] = PDC.NAN
        self.field[PFC.F_OR_BYTES] = PDC.NAN
        self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_RE_SRC_PORT] = PDC.NAN
        self.field[PFC.F_RE_DST_PORT] = PDC.NAN
        self.field[PFC.F_RE_PACKETS] = PDC.NAN
        self.field[PFC.F_RE_BYTES] = PDC.NAN
        self.field[PFC.F_ASSURED] = ""
        self.field[PFC.F_MARK] = PDC.NAN
        self.field[PFC.F_SECCTX] = ""
        self.field[PFC.F_USE] = PDC.NAN

        if sio.buff == "":
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0

        else:
            __off = 3
            __word = sio.get_word(__off)
            if not __word.startswith(self.__tuple_pref):
                self.field[PFC.F_STATE] = __word
                __off += 1

            self.field[PFC.F_OR_SRC_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_OR_DST_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_OR_SRC_PORT] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=",
                    CONV: long } )
            __off += 1
            self.field[PFC.F_OR_DST_PORT] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=",
                    CONV: long } )
            __off += 1

            __word = sio.get_word(__off)
            if __word.startswith(self.__unreplied_pref):
                self.field[PFC.F_UNREPLIED] = __word
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__packets_pref):
                self.field[PFC.F_OR_PACKETS] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__packets_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__bytes_pref):
                self.field[PFC.F_OR_BYTES] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__bytes_pref } )
                __off += 1
                __word = sio.get_word(__off)

            self.field[PFC.F_RE_SRC_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_RE_DST_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_RE_SRC_PORT] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=",
                    CONV: long } )
            __off += 1
            self.field[PFC.F_RE_DST_PORT] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=",
                    CONV: long } )
            __off += 1

            __word = sio.get_word(__off)
            if __word.startswith(self.__packets_pref):
                self.field[PFC.F_RE_PACKETS] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__packets_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__bytes_pref):
                self.field[PFC.F_RE_BYTES] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__bytes_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__assured_pref):
                self.field[PFC.F_ASSURED] = __word

                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__mark_pref):
                self.field[PFC.F_MARK] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__mark_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__secctx_pref):
                self.field[PFC.F_SECCTX] = PBR.conv_by_rules(__word,
                        { PREFIX: self.__secctx_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__use_pref):
                self.field[PFC.F_USE] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__use_pref } )

        self.protocol = self.field[PFC.F_PROTOCOL]
        self.timeout = self.field[PFC.F_TIMEOUT]
        self.state = self.field[PFC.F_STATE]
        self.src_ip = self.field[PFC.F_OR_SRC_IP]
        self.src_port = self.field[PFC.F_OR_SRC_PORT]
        self.dst_ip = self.field[PFC.F_OR_DST_IP]
        self.dst_port = self.field[PFC.F_OR_DST_PORT]

        return(self.protocol, self.timeout, self.state, self.src_ip,
                self.src_port, self.dst_ip, self.dst_port)
#
REGISTER_FILE("/proc/net/ip_conntrack", ProcNetIPCONNTRACK)
REGISTER_PARTIAL_FILE("net/ip_conntrack", ProcNetIPCONNTRACK)
REGISTER_PARTIAL_FILE("pn/ip_conntrack", ProcNetIPCONNTRACK)



# ---
class ProcNetIPV6ROUTE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/ipv6_route"""
# source: net/ipv6/route.c
#         seq_printf(m, "%pi6 %02x ", &rt->rt6i_dst.addr, rt->rt6i_dst.plen);
#
# #ifdef CONFIG_IPV6_SUBTREES
#         seq_printf(m, "%pi6 %02x ", &rt->rt6i_src.addr, rt->rt6i_src.plen);
# #else
#         seq_puts(m, "00000000000000000000000000000000 00 ");
# #endif
#         rcu_read_lock();
#         n = dst_get_neighbour(&rt->dst);
#         if (n) {
#                 seq_printf(m, "%pi6", n->primary_key);
#         } else {
#                 seq_puts(m, "00000000000000000000000000000000");
#         }
#         rcu_read_unlock();
#         seq_printf(m, " %08x %08x %08x %08x %8s\n",
#                    rt->rt6i_metric, atomic_read(&rt->dst.__refcnt),
#                    rt->dst.__use, rt->rt6i_flags,
#                    rt->rt6i_dev ? rt->rt6i_dev->name : "");

    def extra_init(self, *opts):
        self.minfields = 10
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_DEST_HEXIP } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEST_PREFIX_LEN_HEX } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEST_PREFIX_LEN,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_SRCE_HEXIP } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SRCE_PREFIX_LEN_HEX } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SRCE_PREFIX_LEN,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_PRIMARY_KEY } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_RT6I_METRIC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_DEST_REFCOUNT,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_DEST_USE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_RT6I_FLAGS } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_DEVICE } )

        self.dest_ip = PDC.PRESENT_ANY_IPV6_ADDR
        self.dest_pref_len = 0
        self.src_ip = PDC.PRESENT_ANY_IPV6_ADDR
        self.src_pref_len = 0
        self.dest_refcount = 0
        self.device = PDC.ANY_DEVICE
        return

    def extra_next(self, sio):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
#
# pylint: disable=C0301
#
# DestAddr                DestPrefLen SrcAddr                 AddrPrefLen PrimaryKey                    RT6I_METRIC DestRefCount DestUse RT6I_FLAGS Device
# fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0
# 00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 000010cf 00200200       lo
# fe80000000000000ca6000fffe01e486 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo
# ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_DEST_HEXIP] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_DEST_PREFIX_LEN_HEX] = "00"
            self.field[PFC.F_SRCE_HEXIP] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_SRCE_PREFIX_LEN_HEX] = "00"
            self.field[PFC.F_PRIMARY_KEY] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_RT6I_METRIC] = 0
            self.field[PFC.F_DEST_REFCOUNT] = 0
            self.field[PFC.F_DEST_USE] = 0
            self.field[PFC.F_RT6I_FLAGS] = PDC.NULL_MASK_HEX
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_DEST_IP] = PDC.PRESENT_ANY_IPV6_ADDR
            self.field[PFC.F_DEST_PREFIX_LEN] = 0
            self.field[PFC.F_SOURCE] = PDC.PRESENT_ANY_IPV6_ADDR
            self.field[PFC.F_SRCE_PREFIX_LEN] = 0

        else:
            self.field[PFC.F_DEST_IP] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_DEST_HEXIP])
            self.field[PFC.F_SOURCE] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_SRCE_HEXIP])

        self.dest_ip = self.field[PFC.F_DEST_IP]
        self.dest_pref_len = self.field[PFC.F_DEST_PREFIX_LEN]
        self.src_ip = self.field[PFC.F_SOURCE]
        self.src_pref_len = self.field[PFC.F_SRCE_PREFIX_LEN]
        self.dest_refcount = self.field[PFC.F_DEST_REFCOUNT]
        self.device = self.field[PFC.F_DEVICE]

        return(self.dest_ip, self.dest_pref_len, self.src_ip,
                self.src_pref_len, self.dest_refcount, self.device)
#
REGISTER_FILE("/proc/net/ipv6_route", ProcNetIPV6ROUTE)
REGISTER_PARTIAL_FILE("ipv6_route", ProcNetIPV6ROUTE)



# ---
class ProcNetNFCONNTRACK(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/nf_conntrack"""
#
# source: net/netfilter/nf_conntrack_standalone.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 14

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_L3_PROTOCOL } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_L3_PROTOCOL_NUM,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PROTOCOL } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_PROTOCOL_NUM,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TIMEOUT, CONV: long } )

        self.__tuple_pref = "src="
        self.__unreplied_pref = "["
        self.__packets_pref = "packets="
        self.__bytes_pref = "bytes="
        self.__assured_pref = "["
        self.__mark_pref = "mark="
        self.__secctx_pref = "secctx="
        self.__zone_pref = "zone="
        self.__delta_time_pref = "delta-time="
        self.__use_pref = "use="
        self.__sport_pref = "sport="
        self.__dport_pref = "dport="

        self.__val_delim = "="

        self.protocol = ""
        self.src_port = PDC.NO_PORT
        self.src_ip = PDC.ANY_IP_ADDR
        self.state = PDC.UNKNOWN_STATE
        self.l3_protocol = ""
        self.dst_port = PDC.NO_PORT
        self.timeout = 0
        self.dst_ip = PDC.ANY_IP_ADDR
        return

    def extra_next(self, sio):

# -- Sample records, there is no header line and the fields presented can very
# -- from record to record, only the first 3 are guaranteed to always the
# -- protocol name, protocol number, and timeout. The rest will always be in
# -- the same order, but a number of fields may or may not be there.
#
# pylint: disable=C0301
#
# ipv4     2 tcp      6 14 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55894 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55894 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 9 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55890 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55890 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 21 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55900 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55900 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431934 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=33934 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=33934 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431964 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=35348 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=35348 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431798 ESTABLISHED src=192.168.1.14 dst=72.167.218.187 sport=53880 dport=993 src=72.167.218.187 dst=192.168.1.14 sport=993 dport=53880 [ASSURED] mark=0 zone=0 use=2
#
# And some sample records seen on CentOS that have missing fields
#
# ipv4     2 unknown  2 143 src=192.168.122.1 dst=224.0.0.22 [UNREPLIED] src=224.0.0.22 dst=192.168.122.1 mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
# ipv4     2 unknown  2 136 src=192.168.1.110 dst=224.0.0.22 [UNREPLIED] src=224.0.0.22 dst=192.168.1.110 mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
#
# pylint: enable=C0301

        self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
        self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_OR_SRC_PORT] = PDC.NAN
        self.field[PFC.F_OR_DST_PORT] = PDC.NAN
        self.field[PFC.F_UNREPLIED] = ""
        self.field[PFC.F_OR_PACKETS] = PDC.NAN
        self.field[PFC.F_OR_BYTES] = PDC.NAN
        self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
        self.field[PFC.F_RE_SRC_PORT] = PDC.NAN
        self.field[PFC.F_RE_DST_PORT] = PDC.NAN
        self.field[PFC.F_RE_PACKETS] = PDC.NAN
        self.field[PFC.F_RE_BYTES] = PDC.NAN
        self.field[PFC.F_ASSURED] = ""
        self.field[PFC.F_MARK] = PDC.NAN
        self.field[PFC.F_SECCTX] = ""
        self.field[PFC.F_ZONE] = PDC.NAN
        self.field[PFC.F_DELTA_TIME] = PDC.NAN
        self.field[PFC.F_USE] = PDC.NAN

        if sio.buff == "":
            self.field[PFC.F_L3_PROTOCOL] = ""
            self.field[PFC.F_L3_PROTOCOL_NUM] = 0
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0

        else:
            __off = 5
            __word = sio.get_word(__off)
            if not __word.startswith(self.__tuple_pref):
                self.field[PFC.F_STATE] = __word
                __off += 1

            self.field[PFC.F_OR_SRC_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_OR_DST_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1

            if sio.get_word(__off).startswith(self.__sport_pref):
                self.field[PFC.F_OR_SRC_PORT] = PBR.conv_by_rules(
                        sio.get_word(__off), { AFTER: "=",
                        CONV: long } )
                __off += 1
            else:
                self.field[PFC.F_OR_SRC_PORT] = PDC.NO_PORT

            if sio.get_word(__off).startswith(self.__dport_pref):
                self.field[PFC.F_OR_DST_PORT] = PBR.conv_by_rules(
                        sio.get_word(__off), { AFTER: "=",
                        CONV: long } )
                __off += 1
            else:
                self.field[PFC.F_OR_DST_PORT] = PDC.NO_PORT

            __word = sio.get_word(__off)
            if __word.startswith(self.__unreplied_pref):
                self.field[PFC.F_UNREPLIED] = __word
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__packets_pref):
                self.field[PFC.F_OR_PACKETS] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__packets_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__bytes_pref):
                self.field[PFC.F_OR_BYTES] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__bytes_pref } )
                __off += 1
                __word = sio.get_word(__off)

            self.field[PFC.F_RE_SRC_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1
            self.field[PFC.F_RE_DST_IP] = PBR.conv_by_rules(
                    sio.get_word(__off), { AFTER: "=" } )
            __off += 1

            if sio.get_word(__off).startswith(self.__sport_pref):
                self.field[PFC.F_RE_SRC_PORT] = PBR.conv_by_rules(
                        sio.get_word(__off), { AFTER: "=",
                        CONV: long } )
                __off += 1
            else:
                self.field[PFC.F_RE_SRC_PORT] = PDC.NO_PORT

            if sio.get_word(__off).startswith(self.__dport_pref):
                self.field[PFC.F_RE_DST_PORT] = PBR.conv_by_rules(
                        sio.get_word(__off), { AFTER: "=",
                        CONV: long } )
                __off += 1
            else:
                self.field[PFC.F_RE_DST_PORT] = PDC.NO_PORT

            __word = sio.get_word(__off)
            if __word.startswith(self.__packets_pref):
                self.field[PFC.F_RE_PACKETS] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__packets_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__bytes_pref):
                self.field[PFC.F_RE_BYTES] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__bytes_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__assured_pref):
                self.field[PFC.F_ASSURED] = __word
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__mark_pref):
                self.field[PFC.F_MARK] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__mark_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__secctx_pref):
                self.field[PFC.F_SECCTX] = PBR.conv_by_rules(__word,
                        { PREFIX: self.__secctx_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__zone_pref):
                self.field[PFC.F_ZONE] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__zone_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__delta_time_pref):
                self.field[PFC.F_DELTA_TIME] = PBR.conv_by_rules(__word,
                        { CONV: long,
                          PREFIX: self.__delta_time_pref } )
                __off += 1
                __word = sio.get_word(__off)

            if __word.startswith(self.__use_pref):
                self.field[PFC.F_USE] = PBR.conv_by_rules(__word,
                        { CONV: long, PREFIX: self.__use_pref } )

        self.l3_protocol = self.field[PFC.F_L3_PROTOCOL]
        self.protocol = self.field[PFC.F_PROTOCOL]
        self.timeout = self.field[PFC.F_TIMEOUT]
        self.state = self.field[PFC.F_STATE]
        self.src_ip = self.field[PFC.F_OR_SRC_IP]
        self.src_port = self.field[PFC.F_OR_SRC_PORT]
        self.dst_ip = self.field[PFC.F_OR_DST_IP]
        self.dst_port = self.field[PFC.F_OR_DST_PORT]

        return(self.l3_protocol, self.protocol, self.timeout, self.state,
                self.src_ip, self.src_port, self.dst_ip, self.dst_port)
#
REGISTER_FILE("/proc/net/nf_conntrack", ProcNetNFCONNTRACK)
REGISTER_PARTIAL_FILE("net/nf_conntrack", ProcNetNFCONNTRACK)
REGISTER_PARTIAL_FILE("pn/nf_conntrack", ProcNetNFCONNTRACK)



# ---
class ProcNetPSCHED(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/psched"""
# source: net/sched/sch_api.c
#       seq_printf(seq, "%08x %08x %08x %08x\n",
#                  (u32)NSEC_PER_USEC, (u32)PSCHED_TICKS2NS(1),
#                  1000000,
#                  (u32)NSEC_PER_SEC/(u32)ktime_to_ns(timespec_to_ktime(ts)));

    def extra_init(self, *opts):
        self.minfields = 4

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_NSEC_PER_USEC,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_PSCHED_TICKS,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_UNKNOWN_FIELD,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_NSEC_PER_HRTIME,
                CONV: long, BASE: 16 } )

        self.nsec_per_usec = 0
        self.psched_ticks = 0
        self.nsec_per_hrtime = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# NSec_per_USec PSched_Ticks Unknown_Field NSec_per_HRtimer
# 000003e8 00000040 000f4240 3b9aca00

        if sio.buff == "":
            self.field[PFC.F_NSEC_PER_USEC] = 0
            self.field[PFC.F_PSCHED_TICKS] = 0
            self.field[PFC.F_UNKNOWN_FIELD] = 0
            self.field[PFC.F_NSEC_PER_HRTIME] = 0

        self.nsec_per_usec = self.field[PFC.F_NSEC_PER_USEC]
        self.psched_ticks = self.field[PFC.F_PSCHED_TICKS]
        self.nsec_per_hrtime = self.field[PFC.F_NSEC_PER_HRTIME]

        return(self.nsec_per_usec, self.psched_ticks, self.nsec_per_hrtime)
#
REGISTER_FILE("/proc/net/psched", ProcNetPSCHED)
REGISTER_PARTIAL_FILE("psched", ProcNetPSCHED)



# ---
class ProcNetPTYPE(PBR.FixedColumnRecs):
    """Abstraction layer to pull records from /proc/net/ptype"""
# source: net/core/dev.c
#
# if (v == SEQ_START_TOKEN)
#         seq_puts(seq, "Type Device      Function\n");
# else if (pt->dev == NULL || dev_net(pt->dev) == seq_file_net(seq)) {
#         if (pt->type == htons(ETH_P_ALL))
#                 seq_puts(seq, "ALL ");
#         else
#                 seq_printf(seq, "%04x", ntohs(pt->type));
#
#         seq_printf(seq, " %-8s %pF\n",
#                    pt->dev ? pt->dev->name : "", pt->func);

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Type"

        self.fixedcols[PFC.F_DEVICE_TYPE] = (0, 4)
        self.fixedcols[PFC.F_DEVICE_NAME] = (5, 13)
        self.fixedcols[PFC.F_DEVICE_FUNC] = (14, -1)

        self.device_name = ""
        self.device_type = ""
        self.device_function = ""
        return

    def extra_next(self, sio):

# -- Sample lines for reference...
#
# Note: This file can't be parsed as blank delimited words, since the second
#       field is sometimes blank.  So we have to parse by columns, since the
#       layout is fixed rather than delimited. The normal "read_line" call can
#       still be used to pull in the data.  But we just have to pull column
#       ranges from the buffer.

# Type Device      Function
# 0800          ip_rcv+0x0/0x300
# 0011          llc_rcv+0x0/0x370
# 0004          llc_rcv+0x0/0x370
# 0806          arp_rcv+0x0/0x140

        if sio.buff == "":
            self.field[PFC.F_DEVICE_TYPE] = ""
            self.field[PFC.F_DEVICE_NAME] = ""
            self.field[PFC.F_DEVICE_FUNC] = ""

        self.device_type = self.field[PFC.F_DEVICE_TYPE]
        self.device_name = self.field[PFC.F_DEVICE_NAME]
        self.device_function = self.field[PFC.F_DEVICE_FUNC]

        return(self.device_type, self.device_name, self.device_function)
#
REGISTER_FILE("/proc/net/ptype", ProcNetPTYPE)
REGISTER_PARTIAL_FILE("ptype", ProcNetPTYPE)



# ---
class ProcNetRT6STATS(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/rt6_stats"""
# source: net/ipv6/route.c
#    seq_printf(seq, "%04x %04x %04x %04x %04x %04x %04x\n",
#               net->ipv6.rt6_stats->fib_nodes,
#               net->ipv6.rt6_stats->fib_route_nodes,
#               net->ipv6.rt6_stats->fib_rt_alloc,
#               net->ipv6.rt6_stats->fib_rt_entries,
#               net->ipv6.rt6_stats->fib_rt_cache,
#               dst_entries_get_slow(&net->ipv6.ip6_dst_ops),
#               net->ipv6.rt6_stats->fib_discarded_routes);

    def extra_init(self, *opts):
        self.minfields = 7

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_FIB_NODES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_FIB_ROUTE_NODES,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_FIB_ROUTE_ALLOC,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_FIB_ROUTE_ENTRIES,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_FIB_ROUTE_CACHE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_FIB_DEST_OPS,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_FIB_DISC_ROUTES,
                CONV: long, BASE: 16 } )

        self.nodes = 0
        self.route_nodes = 0
        self.route_entries = 0
        self.route_cache = 0
        self.discarded = 0
        return

    def extra_next(self, sio):
# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# Nodes RouteNotes RouteAlloc RouteEntries RouteCache DestOps DiscardRoutes
# 0000 0004 0000 0004 0000 0002 007a

        if sio.buff == "":
            self.field[PFC.F_FIB_NODES] = 0
            self.field[PFC.F_FIB_ROUTE_NODES] = 0
            self.field[PFC.F_FIB_ROUTE_ALLOC] = 0
            self.field[PFC.F_FIB_ROUTE_ENTRIES] = 0
            self.field[PFC.F_FIB_ROUTE_CACHE] = 0
            self.field[PFC.F_FIB_DEST_OPS] = 0
            self.field[PFC.F_FIB_DISC_ROUTES] = 0

        self.nodes = self.field[PFC.F_FIB_NODES]
        self.route_nodes = self.field[PFC.F_FIB_ROUTE_NODES]
        self.route_entries = self.field[PFC.F_FIB_ROUTE_ENTRIES]
        self.route_cache = self.field[PFC.F_FIB_ROUTE_CACHE]
        self.discarded = self.field[PFC.F_FIB_DISC_ROUTES]

        return(self.nodes, self.route_nodes, self.route_entries,
                self.route_cache, self.discarded)
#
REGISTER_FILE("/proc/net/rt6_stats", ProcNetRT6STATS)
REGISTER_PARTIAL_FILE("rt6_stats", ProcNetRT6STATS)



# ---
class ProcNetRTCACHE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/rt_cache"""
# source: net/ipv4/route.c
#                seq_printf(seq, "%s\t%08X\t%08X\t%8X\t%d\t%u\t%d\t"
#                              "%08X\t%d\t%u\t%u\t%02X\t%d\t%1d\t%08X%n",
#                        r->dst.dev ? r->dst.dev->name : "*",
#                        (__force u32)r->rt_dst,
#                        (__force u32)r->rt_gateway,
#                        r->rt_flags, atomic_read(&r->dst.__refcnt),
#                        r->dst.__use, 0, (__force u32)r->rt_src,
#                        dst_metric_advmss(&r->dst) + 40,
#                        dst_metric(&r->dst, RTAX_WINDOW),
#                        (int)((dst_metric(&r->dst, RTAX_RTT) >> 3) +
#                              dst_metric(&r->dst, RTAX_RTTVAR)),
#                        r->rt_key_tos,
#                        -1,
#                        HHUptod,
#                        r->rt_spec_dst, &len);
#                seq_printf(seq, "%*s\n", 127 - len, "");

    def extra_init(self, *opts):
        self.minfields = 15
        self.skipped = "Iface"
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INTERFACE } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEST_HEXIP } )
        PBR.add_parse_rule(self, { POS: 2,  NAME: PFC.F_GATE_HEXIP } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_FLAGS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_USECOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_METRIC, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_SRCE_HEXIP } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_MTU, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_WINDOW, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_IRTT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_TOS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_HHREF, CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_HHUPTOD, CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_SPEC_HEXIP } )

        self.interface = PDC.ANY_INTERFACE
        self.destination = PDC.ANY_IP_ADDR
        self.gateway = PDC.ANY_IP_ADDR
        self.usecount = 0
        self.source = PDC.ANY_IP_ADDR
        self.spec_dst = PDC.ANY_IP_ADDR
        return

    def extra_next(self, sio):

# -- Samples lines.
#
# pylint: disable=C0301
#
# Iface	Destination	Gateway 	Flags		RefCnt	Use	Metric	Source		MTU	Window	IRTT	TOS	HHRef	HHUptod	SpecDst
# %s    %08X            %08X            %8X             %d      %u      %d      %08X            %d      %u      %u      %02X    %d      %1d     %08X
# eth0	C1874A61	0101A8C0	       0	0	0	0	0E01A8C0	1500	0	182	00	-1	1	0E01A8C0
# eth0	0101A8C0	0101A8C0	       0	0	375723	0	0E01A8C0	1500	0	113	00	-1	1	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	23	0	2BE07D4A	16436	0	0	00	-1	0	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	1	0	28846DD0	16436	0	0	00	-1	0	0E01A8C0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_INTERFACE] = PDC.ANY_INTERFACE
            self.field[PFC.F_DEST_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_GATE_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_FLAGS] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_USECOUNT] = 0
            self.field[PFC.F_METRIC] = 0
            self.field[PFC.F_SRCE_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_MTU] = 0
            self.field[PFC.F_WINDOW] = 0
            self.field[PFC.F_IRTT] = 0
            self.field[PFC.F_TOS] = 0
            self.field[PFC.F_HHREF] = 0
            self.field[PFC.F_HHUPTOD] = 0
            self.field[PFC.F_SPEC_HEXIP] = PDC.ANY_IP_ADDR_HEX
            self.field[PFC.F_DEST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_GATEWAY] = PDC.ANY_IP_ADDR
            self.field[PFC.F_SOURCE] = PDC.ANY_IP_ADDR
            self.field[PFC.F_SPEC_DST] = PDC.ANY_IP_ADDR

        else:
            __lip = PBR.conv_by_rules(self.field[PFC.F_DEST_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_GATE_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_GATEWAY] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_SRCE_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_SOURCE] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_SPEC_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_SPEC_DST] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))

        self.interface = self.field[PFC.F_INTERFACE]
        self.destination = self.field[PFC.F_DEST_IP]
        self.gateway = self.field[PFC.F_GATEWAY]
        self.usecount = self.field[PFC.F_USECOUNT]
        self.source = self.field[PFC.F_SOURCE]
        self.spec_dst = self.field[PFC.F_SPEC_DST]

        return(self.interface, self.destination, self.gateway, self.usecount,
                self.source, self.spec_dst)
#
REGISTER_FILE("/proc/net/rt_cache", ProcNetRTCACHE)
REGISTER_PARTIAL_FILE("net/rt_cache", ProcNetRTCACHE)
REGISTER_PARTIAL_FILE("pn/rt_cache", ProcNetRTCACHE)



# ---
class ProcNetStatARPCACHE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/stat/arp_cache"""
# source: net/core/neighbour.c
#        seq_printf(seq, "%08x  %08lx %08lx %08lx  %08lx %08lx  %08lx  "
#                        "%08lx %08lx  %08lx %08lx %08lx\n",
#                   atomic_read(&tbl->entries),
#                   st->allocs,
#                   st->destroys,
#                   st->hash_grows,
#                   st->lookups,
#                   st->hits,
#                   st->res_failed,
#                   st->rcv_probes_mcast,
#                   st->rcv_probes_ucast,
#                   st->periodic_gc_runs,
#                   st->forced_gc_runs,
#                   st->unres_discards
#                   );

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "entries"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ARP_ENTRIES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ALLOC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DESTROY, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HASH_GROW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_LOOKUP, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_HIT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RES_FAIL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_RCV_MCAST_PROBE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_RCV_UCAST_PROBE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_GC_PERIODIC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_GC_FORCED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_UNRES_DISCARD,
                CONV: long, BASE: 16 } )

        self.lookups = 0
        self.hits = 0
        self.entries = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note that each line is for a different CPU
#
# pylint: disable=C0301
#
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_ARP_ENTRIES] = 0
            self.field[PFC.F_ALLOC] = 0
            self.field[PFC.F_DESTROY] = 0
            self.field[PFC.F_HASH_GROW] = 0
            self.field[PFC.F_LOOKUP] = 0
            self.field[PFC.F_HIT] = 0
            self.field[PFC.F_RES_FAIL] = 0
            self.field[PFC.F_RCV_MCAST_PROBE] = 0
            self.field[PFC.F_RCV_UCAST_PROBE] = 0
            self.field[PFC.F_GC_PERIODIC] = 0
            self.field[PFC.F_GC_FORCED] = 0
            self.field[PFC.F_UNRES_DISCARD] = 0

        self.entries = self.field[PFC.F_ARP_ENTRIES]
        self.lookups = self.field[PFC.F_LOOKUP]
        self.hits = self.field[PFC.F_HIT]

        return(self.entries, self.lookups, self.hits)
#
REGISTER_FILE("/proc/net/stat/arp_cache", ProcNetStatARPCACHE)
REGISTER_PARTIAL_FILE("arp_cache", ProcNetStatARPCACHE)



# ---
class ProcNetStatIPCONNTRACK(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/stat/ip_conntrack"""
# source: net/ipv4/netfilter/nf_conntrack_l3proto_ipv4_compat.c
#       seq_printf(seq, "%08x  %08x %08x %08x %08x %08x %08x %08x "
#                        "%08x %08x %08x %08x %08x  %08x %08x %08x %08x\n",
#                   nr_conntracks,
#                   st->searched,
#                   st->found,
#                   st->new,
#                   st->invalid,
#                   st->ignore,
#                   st->delete,
#                   st->delete_list,
#                   st->insert,
#                   st->insert_failed,
#                   st->drop,
#                   st->early_drop,
#                   st->error,
#                   st->expect_new,
#                   st->expect_create,
#                   st->expect_delete,
#                   st->search_restart
#                );

    def extra_init(self, *opts):
        self.minfields = 17
        self.skipped = "entries"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ENTRIES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SEARCHED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_FOUND, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_NEW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_INVALID, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_IGNORE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_DELETE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_DELETE_LIST, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_INSERT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INSERT_FAILED,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_DROP, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_DROP_EARLY, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_ICMP_ERROR, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_EXP_NEW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_EXP_CREATE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_EXP_DELETE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_SEARCH_RESTART,
                CONV: long, BASE: 16 } )

        self.insert = 0
        self.drop = 0
        self.found = 0
        self.entries = 0
        self.invalid = 0
        self.ignore = 0
        self.searched = 0
        self.new = 0
        self.delete = 0
        return

    def extra_next(self, sio):

# -- sample records, note that there's one line for each CPU on the system
#
# pylint: disable=C0301
#
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000084  00003e17 00770ce7 00024cc0 0000060a 00012bf0 0006e07e 0006778b 0001e3f0 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000084  00000c51 00053265 0001cc23 00000041 0000d313 00006987 00006986 0001cc22 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_ENTRIES] = 0
            self.field[PFC.F_SEARCHED] = 0
            self.field[PFC.F_FOUND] = 0
            self.field[PFC.F_NEW] = 0
            self.field[PFC.F_INVALID] = 0
            self.field[PFC.F_IGNORE] = 0
            self.field[PFC.F_DELETE] = 0
            self.field[PFC.F_DELETE_LIST] = 0
            self.field[PFC.F_INSERT] = 0
            self.field[PFC.F_INSERT_FAILED] = 0
            self.field[PFC.F_DROP] = 0
            self.field[PFC.F_DROP_EARLY] = 0
            self.field[PFC.F_ICMP_ERROR] = 0
            self.field[PFC.F_EXP_NEW] = 0
            self.field[PFC.F_EXP_CREATE] = 0
            self.field[PFC.F_EXP_DELETE] = 0
            self.field[PFC.F_SEARCH_RESTART] = 0

        self.entries = self.field[PFC.F_ENTRIES]
        self.searched = self.field[PFC.F_SEARCHED]
        self.found = self.field[PFC.F_FOUND]
        self.new = self.field[PFC.F_NEW]
        self.invalid = self.field[PFC.F_INVALID]
        self.ignore = self.field[PFC.F_IGNORE]
        self.delete = self.field[PFC.F_DELETE]
        self.insert = self.field[PFC.F_INSERT]
        self.drop = self.field[PFC.F_DROP]

        return(self.entries, self.searched, self.found, self.new,
                self.invalid, self.ignore, self.delete, self.insert, self.drop)
#
REGISTER_FILE("/proc/net/stat/ip_conntrack", ProcNetStatIPCONNTRACK)
REGISTER_PARTIAL_FILE("stat/ip_conntrack", ProcNetStatIPCONNTRACK)



# ---
class ProcNetStatNDISCCACHE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/stat/ndisc_cache"""
# source: net/core/neighbour.c
#        seq_printf(seq, "%08x  %08lx %08lx %08lx  %08lx %08lx  %08lx  "
#                        "%08lx %08lx  %08lx %08lx %08lx\n",
#                   atomic_read(&tbl->entries),
#                   st->allocs,
#                   st->destroys,
#                   st->hash_grows,
#                   st->lookups,
#                   st->hits,
#                   st->res_failed,
#                   st->rcv_probes_mcast,
#                   st->rcv_probes_ucast,
#                   st->periodic_gc_runs,
#                   st->forced_gc_runs,
#                   st->unres_discards
#                   );

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "entries"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ARP_ENTRIES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ALLOC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DESTROY, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HASH_GROW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_LOOKUP, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_HIT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RES_FAIL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_RCV_MCAST_PROBE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_RCV_UCAST_PROBE,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_GC_PERIODIC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_GC_FORCED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_UNRES_DISCARD,
                CONV: long, BASE: 16 } )

        self.entries = 0
        self.lookups = 0
        self.hits = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note that each line is for a different CPU
#
# pylint: disable=C0301
#
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_ARP_ENTRIES] = 0
            self.field[PFC.F_ALLOC] = 0
            self.field[PFC.F_DESTROY] = 0
            self.field[PFC.F_HASH_GROW] = 0
            self.field[PFC.F_LOOKUP] = 0
            self.field[PFC.F_HIT] = 0
            self.field[PFC.F_RES_FAIL] = 0
            self.field[PFC.F_RCV_MCAST_PROBE] = 0
            self.field[PFC.F_RCV_UCAST_PROBE] = 0
            self.field[PFC.F_GC_PERIODIC] = 0
            self.field[PFC.F_GC_FORCED] = 0
            self.field[PFC.F_UNRES_DISCARD] = 0

        self.entries = self.field[PFC.F_ARP_ENTRIES]
        self.lookups = self.field[PFC.F_LOOKUP]
        self.hits = self.field[PFC.F_HIT]

        return(self.entries, self.lookups, self.hits)
#
REGISTER_FILE("/proc/net/stat/ndisc_cache", ProcNetStatNDISCCACHE)
REGISTER_PARTIAL_FILE("ndisc_cache", ProcNetStatNDISCCACHE)



# ---
class ProcNetStatNFCONNTRACK(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/stat/nf_conntrack"""
# source: net/netfilter/nf_conntrack_standalone.c
#        seq_printf(seq, "%08x  %08x %08x %08x %08x %08x %08x %08x "
#                        "%08x %08x %08x %08x %08x  %08x %08x %08x %08x\n",
#                   nr_conntracks,
#                   st->searched,
#                   st->found,
#                   st->new,
#                   st->invalid,
#                   st->ignore,
#                   st->delete,
#                   st->delete_list,
#                   st->insert,
#                   st->insert_failed,
#                   st->drop,
#                   st->early_drop,
#                   st->error,
#                   st->expect_new,
#                   st->expect_create,
#                   st->expect_delete,
#                   st->search_restart
#                );

    def extra_init(self, *opts):
        self.minfields = 17
        self.skipped = "entries"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ENTRIES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SEARCHED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_FOUND, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_NEW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_INVALID, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_IGNORE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_DELETE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_DELETE_LIST, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_INSERT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INSERT_FAILED,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_DROP, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_DROP_EARLY, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_ICMP_ERROR, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_EXP_NEW, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_EXP_CREATE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_EXP_DELETE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_SEARCH_RESTART,
                CONV: long, BASE: 16 } )

        self.insert = 0
        self.drop = 0
        self.found = 0
        self.entries = 0
        self.invalid = 0
        self.ignore = 0
        self.searched = 0
        self.new = 0
        self.delete = 0
        return

    def extra_next(self, sio):

# -- sample records, note that there's one line for each CPU on the system
#
# pylint: disable=C0301
#
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000085  00003e40 007782a9 00024eab 0000060a 00012c63 0006e7c2 00067e99 0001e5a5 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000085  00000c5f 00053a15 0001ce59 00000041 0000d3b2 000069ca 000069c9 0001ce58 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_ENTRIES] = 0
            self.field[PFC.F_SEARCHED] = 0
            self.field[PFC.F_FOUND] = 0
            self.field[PFC.F_NEW] = 0
            self.field[PFC.F_INVALID] = 0
            self.field[PFC.F_IGNORE] = 0
            self.field[PFC.F_DELETE] = 0
            self.field[PFC.F_DELETE_LIST] = 0
            self.field[PFC.F_INSERT] = 0
            self.field[PFC.F_INSERT_FAILED] = 0
            self.field[PFC.F_DROP] = 0
            self.field[PFC.F_DROP_EARLY] = 0
            self.field[PFC.F_ICMP_ERROR] = 0
            self.field[PFC.F_EXP_NEW] = 0
            self.field[PFC.F_EXP_CREATE] = 0
            self.field[PFC.F_EXP_DELETE] = 0
            self.field[PFC.F_SEARCH_RESTART] = 0

        self.entries = self.field[PFC.F_ENTRIES]
        self.searched = self.field[PFC.F_SEARCHED]
        self.found = self.field[PFC.F_FOUND]
        self.new = self.field[PFC.F_NEW]
        self.invalid = self.field[PFC.F_INVALID]
        self.ignore = self.field[PFC.F_IGNORE]
        self.delete = self.field[PFC.F_DELETE]
        self.insert = self.field[PFC.F_INSERT]
        self.drop = self.field[PFC.F_DROP]

        return(self.entries, self.searched, self.found, self.new,
                self.invalid, self.ignore, self.delete, self.insert, self.drop)
#
REGISTER_FILE("/proc/net/stat/nf_conntrack", ProcNetStatNFCONNTRACK)
REGISTER_PARTIAL_FILE("stat/nf_conntrack", ProcNetStatNFCONNTRACK)



# ---
class ProcNetStatRTCACHE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/stat/rt_cache"""
# source: net/ipv4/route.c
#        seq_printf(seq,"%08x  %08x %08x %08x %08x %08x %08x %08x "
#                   " %08x %08x %08x %08x %08x %08x %08x %08x %08x \n",
#                   dst_entries_get_slow(&ipv4_dst_ops),
#                   st->in_hit,
#                   st->in_slow_tot,
#                   st->in_slow_mc,
#                   st->in_no_route,
#                   st->in_brd,
#                   st->in_martian_dst,
#                   st->in_martian_src,
#
#                   st->out_hit,
#                   st->out_slow_tot,
#                   st->out_slow_mc,
#
#                   st->gc_total,
#                   st->gc_ignored,
#                   st->gc_goal_miss,
#                   st->gc_dst_overflow,
#                   st->in_hlist_search,
#                   st->out_hlist_search


    def extra_init(self, *opts):
        self.minfields = 17
        self.skipped = "entries"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ENTRIES, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_IN_HIT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_IN_SLOW_TOT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_IN_SLOW_MC, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_IN_NO_ROUTE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_IN_BRD, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_IN_MARTIAN_DST,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_IN_MARTIAN_SRC,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_OUT_HIT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_OUT_SLOW_TOT,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_OUT_SLOW_MC,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_GC_TOTAL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_GC_IGNORED, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_GC_GOAL_MISS,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_GC_DST_OVERFLOW,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_IN_HL_SEARCH,
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_OUT_HL_SEARCH,
                CONV: long, BASE: 16 } )

        self.entries = 0
        self.in_hit = 0
        self.in_slow = 0
        self.out_hit = 0
        self.out_slow = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note that each line is for a different CPU
#
# pylint: disable=C0301
#
# entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search
# 000000a4  00579509 0002044f 00000000 00000000 00001e53 00000000 00000018  0006f8ff 00002620 00000001 00000000 00000000 00000000 00000000 0000ba0b 00000092
# 000000a4  00000000 00000002 00000000 00000000 00000001 00000000 00000000  0006f479 000027b4 00000000 00000000 00000000 00000000 00000000 00000000 00000008
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_ENTRIES] = 0
            self.field[PFC.F_IN_HIT] = 0
            self.field[PFC.F_IN_SLOW_TOT] = 0
            self.field[PFC.F_IN_SLOW_MC] = 0
            self.field[PFC.F_IN_NO_ROUTE] = 0
            self.field[PFC.F_IN_BRD] = 0
            self.field[PFC.F_IN_MARTIAN_DST] = 0
            self.field[PFC.F_IN_MARTIAN_SRC] = 0
            self.field[PFC.F_OUT_HIT] = 0
            self.field[PFC.F_OUT_SLOW_TOT] = 0
            self.field[PFC.F_OUT_SLOW_MC] = 0
            self.field[PFC.F_GC_TOTAL] = 0
            self.field[PFC.F_GC_IGNORED] = 0
            self.field[PFC.F_GC_GOAL_MISS] = 0
            self.field[PFC.F_GC_DST_OVERFLOW] = 0
            self.field[PFC.F_IN_HL_SEARCH] = 0
            self.field[PFC.F_OUT_HL_SEARCH] = 0

        self.entries = self.field[PFC.F_ENTRIES]
        self.in_hit = self.field[PFC.F_IN_HIT]
        self.in_slow = self.field[PFC.F_IN_SLOW_TOT]
        self.out_hit = self.field[PFC.F_OUT_HIT]
        self.out_slow = self.field[PFC.F_OUT_SLOW_TOT]

        return(self.entries, self.in_hit, self.in_slow, self.out_hit,
                self.out_slow)
#
REGISTER_FILE("/proc/net/stat/rt_cache", ProcNetStatRTCACHE)
REGISTER_PARTIAL_FILE("stat/rt_cache", ProcNetStatRTCACHE)



# ---
class ProcNetTCP6(PBR.FixedWhitespaceDelimRecs):
    """
    Abstraction layer to pull records from /proc/net/tcp6
    """

# source: net/ipv6/tcp_ipv6.c
# Note: Just as with the "tcp4" code, the source has three separate sections
#       that write data to this proc file.  And the one used depends on the
#       state of the connection, "open" is handled one way, "time_wait"
#       another, and the code snippet included here is used for any other
#       connection state.  This one has more fields, so I'm using it as the
#       sample code.  Some of the fields at the end are un-labelled in the proc
#       file (meaning there's no column heading). So the constants used to
#       reference them were picked based on what the values appear to be after
#       reviewing the code.
#
#
# pylint: disable=C0301
#
#  seq_printf(seq,
#             "%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
#             "%02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %pK %lu %lu %u %u %d\n",
#             i,
#             src->s6_addr32[0], src->s6_addr32[1],
#             src->s6_addr32[2], src->s6_addr32[3], srcp,
#             dest->s6_addr32[0], dest->s6_addr32[1],
#             dest->s6_addr32[2], dest->s6_addr32[3], destp,
#             sp->sk_state,
#             tp->write_seq-tp->snd_una,
#             (sp->sk_state == TCP_LISTEN) ? sp->sk_ack_backlog : (tp->rcv_nxt - tp->copied_seq),
#             timer_active,
#             jiffies_to_clock_t(timer_expires - jiffies),
#             icsk->icsk_retransmits,
#             sock_i_uid(sp),
#             icsk->icsk_probes_out,
#             sock_i_ino(sp),
#             atomic_read(&sp->sk_refcnt), sp,
#             jiffies_to_clock_t(icsk->icsk_rto),
#             jiffies_to_clock_t(icsk->icsk_ack.ato),
#             (icsk->icsk_ack.quick << 1 ) | icsk->icsk_ack.pingpong,
#             tp->snd_cwnd,
#             tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh
#             );
#
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "sl"
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_BUCKET, CONV: long,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXPORT,
                AFTER: ":"  } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_PORT, AFTER: ":",
                CONV: long, BASE: 16  } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXPORT,
                AFTER: ":"  } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_PORT, AFTER: ":",
                CONV: long, BASE: 16  } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HEXSTATE } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TXQUEUE, CONV: long,
                BASE: 16, BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RXQUEUE, CONV: long,
                BASE: 16, AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER, CONV: long,
                BASE: 16, BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER_WHEN, CONV: long,
                BASE: 16, AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RETRANS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_TIMEOUT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_REFCOUNT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_POINTER, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_RETRY_TIMEOUT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_ACK_TIMEOUT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_QUICK_OR_PPONG,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_CONGEST_WINDOW,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_SSTART_THRESH,
                CONV: long } )

        self.orig_hexip = self.dest_hexip = ""
        self.orig_ip = self.dest_ip = ""
        self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):

# -- Sample lines for reference...
#
# pylint: disable=C0301
#
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
#   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 1995 1 0000000000000000 100 0 0 2 -1
#   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1892 1 0000000000000000 100 0 0 2 -1
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_BUCKET] = 0
            self.field[PFC.F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "::0"
            self.field[PFC.F_DEST_IP] = "::0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
            self.field[PFC.F_TXQUEUE] = 0
            self.field[PFC.F_RXQUEUE] = 0
            self.field[PFC.F_TIMER] = 0
            self.field[PFC.F_TIMER_WHEN] = 0
            self.field[PFC.F_RETRANS] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_POINTER] = 0
            self.field[PFC.F_RETRY_TIMEOUT] = 0
            self.field[PFC.F_ACK_TIMEOUT] = 0
            self.field[PFC.F_QUICK_OR_PPONG] = 0
            self.field[PFC.F_CONGEST_WINDOW] = 0
            self.field[PFC.F_SSTART_THRESH] = 0

        else:
            self.field[PFC.F_ORIG_IP] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_ORIG_HEXIP])
            self.field[PFC.F_DEST_IP] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_DEST_HEXIP])

            if self.field[PFC.F_HEXSTATE] in STATE_LIST:
                self.field[PFC.F_STATE] = \
                        STATE_LIST[self.field[PFC.F_HEXSTATE]]
            else:
                self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE

        self.orig_hexip = self.field[PFC.F_ORIG_HEXIP]
        self.dest_hexip = self.field[PFC.F_DEST_HEXIP]
        self.orig_ip = self.field[PFC.F_ORIG_IP]
        self.orig_port = self.field[PFC.F_ORIG_PORT]
        self.dest_ip = self.field[PFC.F_DEST_IP]
        self.dest_port = self.field[PFC.F_DEST_PORT]
        self.state = self.field[PFC.F_STATE]

        return(self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port,
                self.dest_ip, self.dest_port, self.state)
REGISTER_FILE("/proc/net/tcp6", ProcNetTCP6)
REGISTER_PARTIAL_FILE("tcp6", ProcNetTCP6)



# ---
class ProcNetTCP(PBR.FixedWhitespaceDelimRecs):
    """
    Abstraction layer to pull records from /proc/net/tcp
    """

# source: net/ipv4/tcp_ipv4.c
# Note: The sample code include is one of three spots where this data is
#       written out. The choice of which code to call depends on the status of
#       the socket and only this version has the "%lu %lu %u %u %d" fields at
#       the end, meaning 6 of the  last seven fields. There are also no column
#       headers for those extra fields so I'm guessing their meaning from the
#       code.
#
#        seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
#                        "%08X %5d %8d %lu %d %pK %lu %lu %u %u %d%n",
#                i, src, srcp, dest, destp, sk->sk_state,
#                tp->write_seq - tp->snd_una,
#                rx_queue,
#                timer_active,
#                jiffies_to_clock_t(timer_expires - jiffies),
#                icsk->icsk_retransmits,
#                sock_i_uid(sk),
#                icsk->icsk_probes_out,
#                sock_i_ino(sk),
#                atomic_read(&sk->sk_refcnt), sk,
#                jiffies_to_clock_t(icsk->icsk_rto),
#                jiffies_to_clock_t(icsk->icsk_ack.ato),
#                (icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
#                tp->snd_cwnd,
#                tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh,
#                len);

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "sl"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_BUCKET, CONV: long,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HEXSTATE } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TXQUEUE, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RXQUEUE, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER_WHEN, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RETRANS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_TIMEOUT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_REFCOUNT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_POINTER, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_RETRY_TIMEOUT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_ACK_TIMEOUT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_QUICK_OR_PPONG,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_CONGEST_WINDOW,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 16, NAME: PFC.F_SSTART_THRESH,
                CONV: long } )

        self.orig_hexip = self.dest_hexip = ""
        self.orig_ip = self.dest_ip = ""
        self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):

# -- Sample lines for reference...
#
# pylint: disable=C0301
#
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
#   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 8633 1 0000000000000000 100 0 0 10 -1
#   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24865 1 0000000000000000 100 0 0 10 -1
#   2: 00000000:4E70 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 69682 1 0000000000000000 100 0 0 10 -1
#   3: 0E01A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 15488 1 0000000000000000 100 0 0 10 -1
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_BUCKET] = 0
            self.field[PFC.F_ORIG_HEXIP] = "00000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "0.0.0.0"
            self.field[PFC.F_DEST_IP] = "0.0.0.0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
            self.field[PFC.F_TXQUEUE] = 0
            self.field[PFC.F_RXQUEUE] = 0
            self.field[PFC.F_TIMER] = 0
            self.field[PFC.F_TIMER_WHEN] = 0
            self.field[PFC.F_RETRANS] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_POINTER] = 0
            self.field[PFC.F_RETRY_TIMEOUT] = 0
            self.field[PFC.F_ACK_TIMEOUT] = 0
            self.field[PFC.F_QUICK_OR_PPONG] = 0
            self.field[PFC.F_CONGEST_WINDOW] = 0
            self.field[PFC.F_SSTART_THRESH] = 0

        else:
            __lip = PBR.conv_by_rules(self.field[PFC.F_ORIG_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_ORIG_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_DEST_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))

            if self.field[PFC.F_HEXSTATE] in STATE_LIST:
                self.field[PFC.F_STATE] = STATE_LIST[
                        self.field[PFC.F_HEXSTATE]]
            else:
                self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE

        self.orig_hexip = self.field[PFC.F_ORIG_HEXIP]
        self.dest_hexip = self.field[PFC.F_DEST_HEXIP]
        self.orig_ip = self.field[PFC.F_ORIG_IP]
        self.orig_port = self.field[PFC.F_ORIG_PORT]
        self.dest_ip = self.field[PFC.F_DEST_IP]
        self.dest_port = self.field[PFC.F_DEST_PORT]
        self.state = self.field[PFC.F_STATE]

        return(self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port,
                self.dest_ip, self.dest_port, self.state)
#
REGISTER_FILE("/proc/net/tcp", ProcNetTCP)
REGISTER_PARTIAL_FILE("tcp", ProcNetTCP)



# ---
class ProcNetUDP6(PBR.FixedWhitespaceDelimRecs):
    """Abstraction layer to pull records from /proc/net/udp6"""
# source: net/ipv6/udp.c
#        seq_printf(seq,
#                   "%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
#                   "%02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %pK %d\n",
#                   bucket,
#                   src->s6_addr32[0], src->s6_addr32[1],
#                   src->s6_addr32[2], src->s6_addr32[3], srcp,
#                   dest->s6_addr32[0], dest->s6_addr32[1],
#                   dest->s6_addr32[2], dest->s6_addr32[3], destp,
#                   sp->sk_state,
#                   sk_wmem_alloc_get(sp),
#                   sk_rmem_alloc_get(sp),
#                   0, 0L, 0,
#                   sock_i_uid(sp), 0,
#                   sock_i_ino(sp),
#                   atomic_read(&sp->sk_refcnt), sp,
#                   atomic_read(&sp->sk_drops));

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "sl"
        self.ipconv = IPAddressConv

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_BUCKET, CONV: long,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HEXSTATE } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TXQUEUE, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RXQUEUE, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER_WHEN, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RETRANS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_TIMEOUT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_REFCOUNT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_POINTER, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_DROPS, CONV: long } )

        self.orig_hexip = self.dest_hexip = ""
        self.orig_ip = self.dest_ip = ""
        self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):

# -- Sample lines for reference...
#
# pylint: disable=C0301
#
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
# 1224: 000080FE00000000FF0060CA86E401FE:BBF1 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   500        0 4893942 2 0000000000000000 0
# 2316: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1994 2 0000000000000000 0
# 2777: 00000000000000000000000000000000:0202 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1899 2 0000000000000000 0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_BUCKET] = 0
            self.field[PFC.F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "::0"
            self.field[PFC.F_DEST_IP] = "::0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
            self.field[PFC.F_TXQUEUE] = 0
            self.field[PFC.F_RXQUEUE] = 0
            self.field[PFC.F_TIMER] = 0
            self.field[PFC.F_TIMER_WHEN] = 0
            self.field[PFC.F_RETRANS] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_POINTER] = 0
            self.field[PFC.F_DROPS] = 0

        else:
            self.field[PFC.F_ORIG_IP] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_ORIG_HEXIP])
            self.field[PFC.F_DEST_IP] = \
                    self.ipconv.ipv6_hexstring_to_presentation(
                    self.field[PFC.F_DEST_HEXIP])

            __hst = self.field[PFC.F_HEXSTATE]
            if __hst in STATE_LIST:
                self.field[PFC.F_STATE] = STATE_LIST[__hst]
            else:
                self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE

        self.orig_hexip = self.field[PFC.F_ORIG_HEXIP]
        self.dest_hexip = self.field[PFC.F_DEST_HEXIP]
        self.orig_ip = self.field[PFC.F_ORIG_IP]
        self.orig_port = self.field[PFC.F_ORIG_PORT]
        self.dest_ip = self.field[PFC.F_DEST_IP]
        self.dest_port = self.field[PFC.F_DEST_PORT]
        self.state = self.field[PFC.F_STATE]

        return(self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port,
                self.dest_ip, self.dest_port, self.state)
#
REGISTER_FILE("/proc/net/udp6", ProcNetUDP6)
REGISTER_PARTIAL_FILE("udp6", ProcNetUDP6)



# ---
class ProcNetUDP(PBR.FixedWhitespaceDelimRecs):
    """Abstraction layer to pull records from /proc/net/udp"""
# source: net/ipv4/udp.c
#        seq_printf(f, "%5d: %08X:%04X %08X:%04X"
#                " %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %pK %d%n",
#                bucket, src, srcp, dest, destp, sp->sk_state,
#                sk_wmem_alloc_get(sp),
#                sk_rmem_alloc_get(sp),
#                0, 0L, 0, sock_i_uid(sp), 0, sock_i_ino(sp),
#                atomic_read(&sp->sk_refcnt), sp,
#                atomic_read(&sp->sk_drops), len);

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "sl"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_BUCKET, CONV: long,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ORIG_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXIP,
                BEFORE: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_HEXPORT,
                AFTER: ":" } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DEST_PORT, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_HEXSTATE } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TXQUEUE, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_RXQUEUE, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TIMER_WHEN, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RETRANS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_TIMEOUT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_REFCOUNT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_POINTER, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_DROPS, CONV: long } )

        self.orig_hexip = self.dest_hexip = ""
        self.orig_ip = self.dest_ip = ""
        self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):

# -- Sample lines for reference...
#
# pylint: disable=C0301
#
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
# %5d : %08X:%04X     %08X:%04X    %02X %08X:%08X        %02X:%08lX  %08X       %5d      %8d %lu  %d %pK              %d
# 2316: 0E01A8C0:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 15487 2 0000000000000000 0
# 2316: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1999 2 0000000000000000 0
# 2777: 00000000:0202 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1898 2 0000000000000000 0
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_BUCKET] = 0
            self.field[PFC.F_ORIG_HEXIP] = "00000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "0.0.0.0"
            self.field[PFC.F_DEST_IP] = "0.0.0.0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE
            self.field[PFC.F_TXQUEUE] = 0
            self.field[PFC.F_RXQUEUE] = 0
            self.field[PFC.F_TIMER] = 0
            self.field[PFC.F_TIMER_WHEN] = 0
            self.field[PFC.F_RETRANS] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_POINTER] = 0
            self.field[PFC.F_DROPS] = 0

        else:
            __lip = PBR.conv_by_rules(self.field[PFC.F_ORIG_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_ORIG_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))
            __lip = PBR.conv_by_rules(self.field[PFC.F_DEST_HEXIP],
                    { CONV: long, BASE: 16 } )
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET,
                    binascii.unhexlify('{0:08x}'.format(socket.htonl(__lip))))

            __hst = self.field[PFC.F_HEXSTATE]
            if __hst in STATE_LIST:
                self.field[PFC.F_STATE] = STATE_LIST[__hst]
            else:
                self.field[PFC.F_STATE] = PDC.UNKNOWN_STATE

        self.orig_hexip = self.field[PFC.F_ORIG_HEXIP]
        self.dest_hexip = self.field[PFC.F_DEST_HEXIP]
        self.orig_ip = self.field[PFC.F_ORIG_IP]
        self.orig_port = self.field[PFC.F_ORIG_PORT]
        self.dest_ip = self.field[PFC.F_DEST_IP]
        self.dest_port = self.field[PFC.F_DEST_PORT]
        self.state = self.field[PFC.F_STATE]

        return(self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port,
                self.dest_ip, self.dest_port, self.state)
#
REGISTER_FILE("/proc/net/udp", ProcNetUDP)
REGISTER_PARTIAL_FILE("udp", ProcNetUDP)



# ---
class ProcNetUNIX(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/net/unix
    """

# source: net/unix/af_unix.c
#
# pylint: disable=C0301
#
#                seq_printf(seq, "%pK: %08X %08X %08X %04X %02X %5lu",
#                        s,
#                        atomic_read(&s->sk_refcnt),
#                        0,
#                        s->sk_state == TCP_LISTEN ? __SO_ACCEPTCON : 0,
#                        s->sk_type,
#                        s->sk_socket ?
#                        (s->sk_state == TCP_ESTABLISHED ? SS_CONNECTED : SS_UNCONNECTED) :
#                        (s->sk_state == TCP_ESTABLISHED ? SS_CONNECTING : SS_DISCONNECTING),
#                        sock_i_ino(s));
#
#                if (u->addr) {
#                        int i, len;
#                        seq_putc(seq, ' ');
#
#                        i = 0;
#                        len = u->addr->len - sizeof(short);
#                        if (!UNIX_ABSTRACT(s))
#                                len--;
#                        else {
#                                seq_putc(seq, '@');
#                                i++;
#                        }
#                        for ( ; i < len; i++)
#                                seq_putc(seq, u->addr->name->sun_path[i]);
#
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 7
        self.skipped = "Num"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_NUM, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_REFCOUNT, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PROTOCOL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_FLAGS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_TYPE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_STATE, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_PATH } )

        self.protocol = 0
        self.refcount = 0
        self.flags = 0
        self.type = 0
        self.state = 0
        self.inode = 0
        self.path = ""
        return

    def extra_next(self, sio):

# -- Sample entries, note that each line is for a different CPU
#
# pylint: disable=C0301
#
# Num       RefCount Protocol Flags    Type St Inode Path
# 0000000000000000: 00000002 00000000 00010000 0001 01 15807 @/tmp/dbus-HTivHd8Iyv
# 0000000000000000: 00000002 00000000 00010000 0001 01 14531 /tmp/.X11-unix/X0
# 0000000000000000: 00000002 00000000 00010000 0001 01 16649 /tmp/keyring-OUNO20/control
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_NUM] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_FLAGS] = "00000000"
            self.field[PFC.F_TYPE] = "0001"
            self.field[PFC.F_STATE] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_PATH] = ""

        self.protocol = self.field[PFC.F_PROTOCOL]
        self.refcount = self.field[PFC.F_REFCOUNT]
        self.flags = self.field[PFC.F_FLAGS]
        self.type = self.field[PFC.F_TYPE]
        self.state = self.field[PFC.F_STATE]
        self.inode = self.field[PFC.F_INODE]
        self.path = self.field[PFC.F_PATH]

        return(self.refcount, self.protocol, self.flags, self.type,
                self.state, self.inode, self.path)
#
REGISTER_FILE("/proc/net/unix", ProcNetUNIX)
REGISTER_PARTIAL_FILE("unix", ProcNetUNIX)



# ---
class ProcNetSNMP6(PBR.SingleNameValueList):
    """Pull records from /proc/net/snmp6"""
# source: net/ipv6/proc.c

# -- Sample records.  This file a series of key/value entries, one per line.
# Ip6InReceives                   	1159
# Ip6InHdrErrors                  	0
# Ip6InTooBigErrors               	0
# Ip6InNoRoutes                   	0
# Ip6InAddrErrors                 	0
# Ip6InUnknownProtos              	0
#
#
REGISTER_FILE("/proc/net/snmp6", ProcNetSNMP6)
REGISTER_PARTIAL_FILE("snmp6", ProcNetSNMP6)



# ---
class ProcNetDEVSNMP6(PBR.SingleNameValueList):
    """
    Pull recs from a device specific file in the /proc/net/dev_snmp6/ directory
    """

# source: net/ipv6/proc.c
#
#  seq_printf(seq, "%-32s\t%u\n", "ifIndex", idev->dev->ifindex);
#  snmp6_seq_show_item(seq, (void __percpu **)idev->stats.ipv6, NULL,
#                      snmp6_ipstats_list);
#  snmp6_seq_show_item(seq, NULL, idev->stats.icmpv6dev->mibs,
#                      snmp6_icmp6_list);
#  snmp6_seq_show_icmpv6msg(seq, NULL, idev->stats.icmpv6msgdev->mibs);

    def extra_init(self, *opts):
        if len(opts) > 0:
            self.infile = PBR.proc_file_to_path(opts[0])
        else:
            self.infile = "{prefix}/{file}".format(
                    prefix=PBR.show_handler_file_path(self), file="lo")
        return

# -- Sample records.  All the files in the /proc/dev_snmp6/ directory use the
# -- same format.  Each line is a key/value indicator.
# ifIndex                         	2
# Ip6InReceives                   	640
# Ip6InHdrErrors                  	0
# Ip6InTooBigErrors               	0
# Ip6InNoRoutes                   	0
# Ip6InAddrErrors                 	0
# Ip6InUnknownProtos              	0
# Ip6InTruncatedPkts              	0
# Ip6InDiscards                   	0
# Ip6InDelivers                   	44
#
#
REGISTER_FILE("/proc/net/dev_snmp6/lo", ProcNetDEVSNMP6)
REGISTER_PARTIAL_FILE("dev_snmp6/", ProcNetDEVSNMP6)



# ---
class ProcNetIGMP(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/net/igmp
    """

# source: net/ipv4/igmp.c
#
# pylint: disable=C0301
#
#        if (rcu_dereference(state->in_dev->mc_list) == im) {
#                seq_printf(seq, "%d\t%-10s: %5d %7s\n",
#                           state->dev->ifindex, state->dev->name, state->in_dev->mc_count, querier);
#        }
#
#        seq_printf(seq,
#                   "\t\t\t\t%08X %5d %d:%08lX\t\t%d\n",
#                   im->multiaddr, im->users,
#                   im->tm_running, im->tm_running ?
#                   jiffies_to_clock_t(im->timer.expires-jiffies) : 0,
#                   im->reporter);
#
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 4
        self.skipped = "Idx"
        self.__label_rec_words = 5

        self.count = 0
        self.index = 0
        self.group = 0
        self.timer = 0
        self.querier = ""
        self.device = PDC.ANY_DEVICE
        self.users = 0
        return

    def extra_next(self, sio):

# -- Sample records, the trick here is that the lines are split in two.
# Idx	Device    : Count Querier	Group    Users Timer	Reporter
# 1	lo        :     1      V3
# 				010000E0     1 0:00000000		0
# 2	eth0      :     1      V3
# 				010000E0     1 0:00000000		0

        if sio.buff == "":
            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_COUNT] = 0
            self.field[PFC.F_QUERIER] = ""
            self.field[PFC.F_GROUP] = 0
            self.field[PFC.F_USERS] = 0
            self.field[PFC.F_TIMER] = 0
            self.field[PFC.F_ZERO1] = 0
            self.field[PFC.F_REPORTER] = 0

        else:

            if sio.linewords == self.__label_rec_words:
                self.field[PFC.F_INDEX] = PBR.conv_by_rules( sio.get_word(0),
                        { CONV: long } )
                self.field[PFC.F_DEVICE] = sio.get_word(1)
                self.field[PFC.F_COUNT] = PBR.conv_by_rules( sio.get_word(3),
                        { CONV: long } )
                self.field[PFC.F_QUERIER] = sio.get_word(4)

# ... need to read the next line for the rest.
                sio.read_line()

            else:
                self.field[PFC.F_INDEX] = 0
                self.field[PFC.F_DEVICE] = ""
                self.field[PFC.F_COUNT] = 0
                self.field[PFC.F_QUERIER] = ""

            if sio.buff == "":
                self.field[PFC.F_INDEX] = 0
                self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
                self.field[PFC.F_COUNT] = 0
                self.field[PFC.F_QUERIER] = ""
                self.field[PFC.F_GROUP] = 0
                self.field[PFC.F_USERS] = 0
                self.field[PFC.F_TIMER] = 0
                self.field[PFC.F_ZERO1] = 0
                self.field[PFC.F_REPORTER] = 0

            else:
                self.field[PFC.F_GROUP] = PBR.conv_by_rules(sio.get_word(0),
                        { CONV: long, BASE: 16 } )
                self.field[PFC.F_USERS] = PBR.conv_by_rules(sio.get_word(1),
                        { CONV: long } )
                self.field[PFC.F_TIMER] = PBR.conv_by_rules(sio.get_word(2),
                        { CONV: long, BEFORE: ":" } )
                self.field[PFC.F_ZERO1] = PBR.conv_by_rules(sio.get_word(2),
                        { CONV: long, BASE: 16, AFTER: ":" } )
                self.field[PFC.F_REPORTER] = PBR.conv_by_rules(
                        sio.get_word(3), { CONV: long } )

        self.index = self.field[PFC.F_INDEX]
        self.device = self.field[PFC.F_DEVICE]
        self.count = self.field[PFC.F_COUNT]
        self.querier = self.field[PFC.F_QUERIER]
        self.group = self.field[PFC.F_GROUP]
        self.users = self.field[PFC.F_USERS]
        self.timer = self.field[PFC.F_TIMER]

        return(self.index, self.device, self.count, self.querier, self.group,
                self.users, self.timer)
#
REGISTER_FILE("/proc/net/igmp", ProcNetIGMP)
REGISTER_PARTIAL_FILE("igmp", ProcNetIGMP)



# ---
class ProcNetSNMP(PBR.TwoLineLogicalRecs):
    """
    Abstraction layer to pull records from /proc/net/snmp
    """

# source: net/ipv4/proc.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

# -- Sample lines for reference...
# pylint: disable=C0301
#
#
# Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
# Tcp: 1 200 120000 -1 160318 5208 5105 523 17 21554159 12995200 11248 0 16685
# Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
# Udp: 890715 230 0 667254 0 0
#
# pylint: enable=C0301

REGISTER_FILE("/proc/net/snmp", ProcNetSNMP)
REGISTER_PARTIAL_FILE("snmp", ProcNetSNMP)



# ---
class ProcNetNETSTAT(PBR.TwoLineLogicalRecs):
    """
    Abstraction layer to pull records from /proc/net/netstat
    """

# source: net/ipv4/proc.c
#
# pylint: disable=C0301
#
# seq_puts(seq, "TcpExt:");
# for (i = 0; snmp4_net_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_net_list[i].name);
#
# seq_puts(seq, "\nTcpExt:");
# for (i = 0; snmp4_net_list[i].name != NULL; i++)
#     seq_printf(seq, " %lu",
#            snmp_fold_field((void __percpu **)net->mib.net_statistics,
#                    snmp4_net_list[i].entry));
#
# seq_puts(seq, "\nIpExt:");
# for (i = 0; snmp4_ipextstats_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_ipextstats_list[i].name);
#
# seq_puts(seq, "\nIpExt:");
# for (i = 0; snmp4_ipextstats_list[i].name != NULL; i++)
#     seq_printf(seq, " %llu",
#            snmp_fold_field64((void __percpu **)net->mib.ip_statistics,
#                      snmp4_ipextstats_list[i].entry,
#                      offsetof(struct ipstats_mib, syncp)));
#
# seq_putc(seq, '\n');
#
# -- Sample lines for reference...
#
# IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets
# IpExt: 0 0 1 0 102161 495 27899358724 1793111008 112 0 20737154 71127
#
# pylint: enable=C0301

REGISTER_FILE("/proc/net/netstat", ProcNetNETSTAT)
REGISTER_PARTIAL_FILE("netstat", ProcNetNETSTAT)



# ---
class ProcNetSOCKSTAT(PBR.LabelledPairList):
    """Abstraction layer to pull records from /proc/net/sockstat"""
# Note: Two different ".c" files write data to /net/sockstat.  They are called
#       in the order listed here.
#
# source #1: net/socket.c
#
# seq_printf(seq, "sockets: used %d\n", counter);
#
# source #2: net/ipv4/proc.c
#
#  seq_printf(seq, "TCP: inuse %d orphan %d tw %d alloc %d mem %ld\n",
#             sock_prot_inuse_get(net, &tcp_prot), orphans,
#             tcp_death_row.tw_count, sockets,
#             atomic_long_read(&tcp_memory_allocated));
#  seq_printf(seq, "UDP: inuse %d mem %ld\n",
#             sock_prot_inuse_get(net, &udp_prot),
#             atomic_long_read(&udp_memory_allocated));
#  seq_printf(seq, "UDPLITE: inuse %d\n",
#             sock_prot_inuse_get(net, &udplite_prot));
#  seq_printf(seq, "RAW: inuse %d\n",
#             sock_prot_inuse_get(net, &raw_prot));
#  seq_printf(seq,  "FRAG: inuse %d memory %d\n",
#             ip_frag_nqueues(net), ip_frag_mem(net));

    def extra_init(self, *opts):
        self.sock_type_list = ([ PFC.F_SOCK_TCP, PFC.F_SOCK_UDP,
                PFC.F_SOCK_UDPLITE, PFC.F_SOCK_RAW, PFC.F_SOCK_FRAG,
                PFC.F_SOCK_SOCKETS ])
        return

# -- Sample lines for reference...
# TCP: inuse 26 orphan 0 tw 1 alloc 30 mem 2
# UDP: inuse 3 mem 3
# UDPLITE: inuse 0
# RAW: inuse 0
# FRAG: inuse 0 memory 0
#
#
REGISTER_FILE("/proc/net/sockstat", ProcNetSOCKSTAT)
REGISTER_PARTIAL_FILE("sockstat", ProcNetSOCKSTAT)



# ---
class ProcNetSOCKSTAT6(PBR.LabelledPairList):
    """Abstraction layer to pull records from /proc/net/sockstat6"""
# source: net/ipv6/proc.c
#
#  seq_printf(seq, "TCP6: inuse %d\n",
#                 sock_prot_inuse_get(net, &tcpv6_prot));
#  seq_printf(seq, "UDP6: inuse %d\n",
#                 sock_prot_inuse_get(net, &udpv6_prot));
#  seq_printf(seq, "UDPLITE6: inuse %d\n",
#                  sock_prot_inuse_get(net, &udplitev6_prot));
#  seq_printf(seq, "RAW6: inuse %d\n",
#                 sock_prot_inuse_get(net, &rawv6_prot));
#  seq_printf(seq, "FRAG6: inuse %d memory %d\n",
#                 ip6_frag_nqueues(net), ip6_frag_mem(net));


    def extra_init(self, *opts):
        self.sock_type_list = ([ PFC.F_SOCK_TCP6, PFC.F_SOCK_UDP6,
                PFC.F_SOCK_UDPLITE6, PFC.F_SOCK_RAW6, PFC.F_SOCK_FRAG6 ])
        return

# -- Sample lines for reference...
# TCP6: inuse 4
# UDP6: inuse 2
# UDPLITE6: inuse 0
# RAW6: inuse 0
# FRAG6: inuse 0 memory 0
#
#
REGISTER_FILE("/proc/net/sockstat6", ProcNetSOCKSTAT6)
REGISTER_PARTIAL_FILE("sockstat6", ProcNetSOCKSTAT6)



# ---
class ProcNetIP6TABLESMATCHES(PBR.ListOfTerms):
    """Pull records from /proc/net/ip6_tables_matches"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# hl
#
#
REGISTER_FILE("/proc/net/ip6_tables_matches", ProcNetIP6TABLESMATCHES)
REGISTER_PARTIAL_FILE("ip6_tables_matches", ProcNetIP6TABLESMATCHES)



# ---
class ProcNetIP6TABLESNAMES(PBR.ListOfTerms):
    """Pull records from /proc/net/ip6_tables_names"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter
#
#
REGISTER_FILE("/proc/net/ip6_tables_names", ProcNetIP6TABLESNAMES)
REGISTER_PARTIAL_FILE("ip6_tables_names", ProcNetIP6TABLESNAMES)



# ---
class ProcNetIP6TABLESTARGETS(PBR.ListOfTerms):
    """Pull records from /proc/net/ip6_tables_targets"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# LOG
# ERROR
#
#
REGISTER_FILE("/proc/net/ip6_tables_targets", ProcNetIP6TABLESTARGETS)
REGISTER_PARTIAL_FILE("ip6_tables_targets", ProcNetIP6TABLESTARGETS)



# ---
class ProcNetIPTABLESMATCHES(PBR.ListOfTerms):
    """Pull records from /proc/net/ip_tables_matches"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# ttl
#
#
REGISTER_FILE("/proc/net/ip_tables_matches", ProcNetIPTABLESMATCHES)
REGISTER_PARTIAL_FILE("ip_tables_matches", ProcNetIPTABLESMATCHES)



# ---
class ProcNetIPTABLESNAMES(PBR.ListOfTerms):
    """Pull records from /proc/net/ip_tables_names"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter
#
#
REGISTER_FILE("/proc/net/ip_tables_names", ProcNetIPTABLESNAMES)
REGISTER_PARTIAL_FILE("ip_tables_names", ProcNetIPTABLESNAMES)



# ---
class ProcNetIPTABLESTARGETS(PBR.ListOfTerms):
    """Pull records from /proc/net/ip_tables_targets"""
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# REJECT
# LOG
# ERROR
#
#
REGISTER_FILE("/proc/net/ip_tables_targets", ProcNetIPTABLESTARGETS)
REGISTER_PARTIAL_FILE("ip_tables_targets", ProcNetIPTABLESTARGETS)



# ---
class ProcNetNetfilterNFLOG(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/netfilter/nf_log"""
# source: net/netfilter/nf_log.c
#  if (!logger)
#          ret = seq_printf(s, "%2lld NONE (", *pos);
#  else
#          ret = seq_printf(s, "%2lld %s (", *pos, logger->name);
#
#  if (ret < 0)
#          return ret;
#
#  list_for_each_entry(t, &nf_loggers_l[*pos], list[*pos]) {
#          ret = seq_printf(s, "%s", t->name);
#          if (ret < 0)
#                  return ret;
#          if (&t->list[*pos] != nf_loggers_l[*pos].prev) {
#                  ret = seq_printf(s, ",");
#                  if (ret < 0)
#                          return ret;
#          }
#  }
#
#  return seq_printf(s, ")\n");

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INDEX, CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_NAME } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_LOGGER_LIST,
                PREFIX: "(", SUFFIX: ")" } )

        self.index = 0
        self.name = ""
        self.log_list = ""
        return

    def extra_next(self, sio):
# -- Sample records.  The column headers are informational only, there is no
# -- header line in the file itself.
# Index Name List_of_Loggers
#  0 NONE ()
#  1 NONE ()
#  2 ipt_LOG (ipt_LOG)

        if sio.buff == "":
            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_NAME] = ""
            self.field[PFC.F_LOGGER_LIST] = ""

        self.index = self.field[PFC.F_INDEX]
        self.name = self.field[PFC.F_NAME]
        self.log_list = self.field[PFC.F_LOGGER_LIST]

        return(self.index, self.name, self.log_list)
#
REGISTER_FILE("/proc/net/netfilter/nf_log", ProcNetNetfilterNFLOG)
REGISTER_PARTIAL_FILE("nf_log", ProcNetNetfilterNFLOG)



# ---
class ProcNetNetfilterNFQUEUE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/net/netfilter/nf_queue"""
# source: net/netfilter/nf_queue.c
#  if (!qh)
#          ret = seq_printf(s, "%2lld NONE\n", *pos);
#  else
#          ret = seq_printf(s, "%2lld %s\n", *pos, qh->name);

    def extra_init(self, *opts):
        self.minfields = 2

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INDEX, CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_NAME } )

        self.index = 0
        self.name = ""
        return

    def extra_next(self, sio):
# -- Sample records.  The column headers are informational only, there is no
# -- header line in the file itself.
# Index Name
# 0 NONE
# 1 NONE
# 2 NONE

        if sio.buff == "":
            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_NAME] = ""

        self.index = self.field[PFC.F_INDEX]
        self.name = self.field[PFC.F_NAME]

        return(self.index, self.name)
#
REGISTER_FILE("/proc/net/netfilter/nf_queue", ProcNetNetfilterNFQUEUE)
REGISTER_PARTIAL_FILE("nf_queue", ProcNetNetfilterNFQUEUE)



#
class ProcNetFIBTRIE(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/net/fib_trie file
    """

# source: net/ipv4/fib_trie.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 1

        self.__empty_tag = ""
        self.__hold_type = self.__empty_tag
        self.__tag_suff = ":"
        self.__id_pref = "Id"
        self.__node_pref = "+--"
        self.__leaf_pref = "|--"
        self.__error = "ParseError"
        self.__is_done = False
        return

    def link_subrec(self, base, field, point):
        """Attach a dictionary to the parent object"""

        try:
            __seq = len(base[field])
        except KeyError:
            __seq = 0
            base[field] = dict()

        base[field][__seq] = point

        return

    def add_node_subrec(self, spot):
        """Parse a line describing a node"""

        sio = self.curr_sio
        spot[PFC.F_NETWORK] = PBR.conv_by_rules(sio.get_word(1),
                { BEFORE: "/" } )
        spot[PFC.F_NETMASK] = PBR.conv_by_rules(sio.get_word(1),
                { AFTER: "/", CONV: long } )
        spot[PFC.F_FIB_BITS] = PBR.conv_by_rules(sio.get_word(2),
                { CONV: long } )
        spot[PFC.F_FULL_CHILDREN] = PBR.conv_by_rules(sio.get_word(3),
                { CONV: long } )
        spot[PFC.F_EMPTY_CHILDREN] = PBR.conv_by_rules(sio.get_word(4),
                { CONV: long } )

        return

    def add_leaf_subrec(self, spot):
        """Parse a leaf record"""

        sio = self.curr_sio
        spot[PFC.F_NETWORK] = sio.get_word(1)

        return

    def add_scope_subrec(self, parent):
        """Parse a line describing route under a leaf rec"""

        sio = self.curr_sio
        __val = dict()

        __val[PFC.F_NETMASK] = PBR.conv_by_rules(sio.get_word(0),
                { AFTER: "/", CONV: long } )
        __val[PFC.F_SCOPE] = sio.get_word(1)
        __val[PFC.F_TYPE] = sio.get_word(2)


        self.link_subrec(parent, PFC.F_SCOPE, __val)
        return


    def parse_subrec(self, spot, parent):
        """Figure out which type of record and call parser"""

        sio = self.curr_sio
        __first = sio.get_word(0)

        if __first == self.__node_pref:
            self.link_subrec(parent, PFC.F_NODE, spot)
            self.add_node_subrec(spot)

        elif __first == self.__leaf_pref:
            self.link_subrec(parent, PFC.F_FIB_LEAF, spot)
            self.add_leaf_subrec(spot)

        else:
            self.add_scope_subrec(parent)

        return

# Sample records:
#
# Main:
#   +-- 0.0.0.0/0 2 0 1
#      |-- 0.0.0.0
#         /0 universe UNICAST
#      |-- 169.254.0.0
#         /16 link UNICAST
#      |-- 192.168.1.0
#         /24 link UNICAST
# Local:
#   +-- 0.0.0.0/0 1 0 0
#      +-- 127.0.0.0/8 1 0 0
#         +-- 127.0.0.0/31 1 0 0
#            |-- 127.0.0.0
#               /32 link BROADCAST
#               /8 host LOCAL

    def extra_next(self, sio):
        self.__is_done = False
        __fib = dict()
        __point = __fib
        __lomap = dict()
        __lomap[0] = __fib
        __previous = 0

        self.field[PFC.F_NODE_NAME] = self.__hold_type

        while not self.__is_done:
            __level = (len(sio.buff) - len(sio.buff.lstrip(" ")) + 1) / 3

            if __level < __previous:
                for __off in range(__level, __previous+1):
                    __lomap[__off] = dict()

            if __level == 0:
                __type = sio.get_word(sio.linewords-1)
                __type = __type.partition(self.__tag_suff)[0]
                if self.field[PFC.F_NODE_NAME] == self.__empty_tag:
                    self.field[PFC.F_NODE_NAME] = __type
                if self.__hold_type != self.__empty_tag:
                    self.__is_done = True
                self.__hold_type = __type

            else:
                try:
                    __point = __lomap[__level]
                except KeyError:
                    __point = self.__empty_tag

                if __point == self.__empty_tag:
                    __point = dict()
                    __lomap[__level] = __point

                __parent = __lomap[__level-1]

                self.parse_subrec(__point, __parent)

            __previous = __level

            if not self.__is_done:
                try:
                    sio.read_line()
                except StopIteration:
                    self.__is_done = True

        self.field[PFC.F_FIB_TRIE] = __fib

        return self.field

REGISTER_FILE("/proc/net/fib_trie", ProcNetFIBTRIE)
REGISTER_PARTIAL_FILE("fib_trie", ProcNetFIBTRIE)


# pylint: disable=R0914
#
class ProcNetFIBTRIESTAT(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/net/fib_triestat file
    """

# source: net/ipv4/fib_trie.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 1
        self.skipped = "Counters:"

        self.__empty_tag = ""
        self.__glinfo = (0, 0)
        self.__hold_node = self.__empty_tag
        self.__tag_suff = ":"
        self.__id_pref = "Id"
        self.__intnode_pref = "\t  "
        self.__basic_tag = "Basic"

        __aver_depth = "\tAver depth:"
        __max_depth = "\tMax depth:"
        __leaves = "\tLeaves:"
        __prefixes = "\tPrefixes:"
        __internal = "\tInternal nodes:"
        __pointers = "\tPointers:"
        __null_ptrs = "Null ptrs:"
        __total = "Total size:"
        __gets = "gets ="
        __backtracks = "backtracks ="
        __sem_pass = "semantic match passed ="
        __sem_miss = "semantic match miss ="
        __null_node = "null node hit="
        __skipped = "skipped node resize ="

        __rs = []
        __rs = __rs + [ (PFC.F_AVER_DEPTH, { PREFIX: __aver_depth,
                CONV: float }) ]
        __rs = __rs + [ (PFC.F_MAX_DEPTH, { PREFIX: __max_depth,
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_LEAVES, { PREFIX: __leaves, CONV: long }) ]
        __rs = __rs + [ (PFC.F_PREFIXES, { PREFIX: __prefixes, CONV: long }) ]
        __rs = __rs + [ (PFC.F_INT_NODES, { PREFIX: __internal, CONV: long }) ]
        __rs = __rs + [ (PFC.F_POINTERS, { PREFIX: __pointers, CONV: long }) ]
        __rs = __rs + [ (PFC.F_NULL_PTRS, { PREFIX: __null_ptrs,
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_TOTAL_SIZE, { PREFIX: __total, CONV: long,
                BEFORE: " kB" }) ]
        __rs = __rs + [ (PFC.F_GETS, { PREFIX: __gets, CONV: long }) ]
        __rs = __rs + [ (PFC.F_BACKTRACKS, { PREFIX: __backtracks,
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_SEM_PASS, { PREFIX: __sem_pass, CONV: long }) ]
        __rs = __rs + [ (PFC.F_SEM_MISS, { PREFIX: __sem_miss, CONV: long }) ]
        __rs = __rs + [ (PFC.F_NULL_NODE, { PREFIX: __null_node,
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_SKIPPED, { PREFIX: __skipped, CONV: long }) ]
        self.__rset = __rs

        return

    def apply_matching_rules(self):
        """Match records with the appropriate parse rule"""

        sio = self.curr_sio
        __line = sio.buff.rstrip("\n")

        for __rinfo in self.__rset:
            __field = __rinfo[0]
            __rule = __rinfo[1]
            try:
                __ord = __rinfo[2]
            except IndexError:
                __ord = ""
            if PBR.matches_all_crit(__line, __rule, __ord):
                self.field[__field] = PBR.conv_by_rules(__line, __rule, __ord)

        return


    def extra_next(self, sio):
        __is_done = False

        self.field[PFC.F_NODE_NAME] = self.__hold_node
        self.field[PFC.F_INT_NODE_LIST] = dict()

        if sio.get_word(0) == self.__basic_tag:
            __leaf = PBR.conv_by_rules(sio.get_word(5), { CONV: long } )
            __tnode = PBR.conv_by_rules(sio.get_word(10), { CONV: long } )
            self.__glinfo = (__leaf, __tnode)
            sio.read_line()

        while not __is_done:
            __first = sio.get_word(0)

            if sio.linewords == 1 or __first == self.__id_pref:
                __node = sio.get_word(sio.linewords-1)
                if __node[-1:] == self.__tag_suff:
                    __node = __node[:-1]
                    self.__hold_node = __node
                    if self.field[PFC.F_NODE_NAME] != self.__empty_tag:
                        __is_done = True
                    else:
                        self.field[PFC.F_NODE_NAME] = __node

            elif sio.buff.startswith(self.__intnode_pref):
                __off = 0
                for __nw in range(1, sio.linewords, 2):
                    __key = sio.get_word(__nw - 1).rstrip(":")
                    __val = sio.get_word(__nw)
                    self.field[PFC.F_INT_NODE_LIST][__off] = (__key, __val)
                    __off += 1

            else:
                self.apply_matching_rules()

            if not __is_done:
                try:
                    sio.read_line()
                except StopIteration:
                    __is_done = True

        self.field[PFC.F_LEAF_SIZE] = self.__glinfo[0]
        self.field[PFC.F_TNODE_SIZE] = self.__glinfo[1]

        return self.field

REGISTER_FILE("/proc/net/fib_triestat", ProcNetFIBTRIESTAT)
REGISTER_PARTIAL_FILE("fib_triestat", ProcNetFIBTRIESTAT)



#
class ProcNetGPBLUETOOTH(PBR.FixedWhitespaceDelimRecs):
    """
    General purpose parse for multiple 'bluetooth' files in /proc/net
    """

# source: net/bluetooth/af_bluetooth.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = BTOOTH_MIN_REC_SIZE
        self.skipped = "sk"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SK_ADDR, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_RMEM_ALLOC,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_WMEM_ALLOC,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_BT_SOURCE, CONV: str } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_BT_DEST, CONV: str } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_PARENT, CONV: long } )

        return

    def extra_next(self, sio):
        if sio.linewords >= BTOOTH_FULL_REC_SIZE:
            self.field[PFC.F_BT_SOURCE] = sio.get_word(6)
            self.field[PFC.F_BT_DEST] = sio.get_word(7)
            self.field[PFC.F_PARENT] = long(sio.get_word(8))

        else:
            self.field[PFC.F_PARENT] = long(sio.get_word(6))
            self.field[PFC.F_BT_SOURCE] = PDC.NO_BLUETOOTH_ADDR
            self.field[PFC.F_BT_DEST] = PDC.NO_BLUETOOTH_ADDR

        return (self.field[PFC.F_SK_ADDR], self.field[PFC.F_REFCOUNT],
                self.field[PFC.F_RMEM_ALLOC], self.field[PFC.F_WMEM_ALLOC],
                self.field[PFC.F_UID], self.field[PFC.F_INODE],
                self.field[PFC.F_BT_SOURCE], self.field[PFC.F_BT_DEST],
                self.field[PFC.F_PARENT])



#
class ProcNetBNEP(ProcNetGPBLUETOOTH):
    """
    Parse /proc/net/bnep files (generic 'bluetooth' format)
    """

REGISTER_FILE("/proc/net/bnep", ProcNetBNEP)
REGISTER_PARTIAL_FILE("bnep", ProcNetBNEP)



#
class ProcNetSCO(ProcNetGPBLUETOOTH):
    """
    Parse /proc/net/sco files (generic 'bluetooth' format)
    """

REGISTER_FILE("/proc/net/sco", ProcNetSCO)
REGISTER_PARTIAL_FILE("sco", ProcNetSCO)



#
class ProcNetHCI(ProcNetGPBLUETOOTH):
    """
    Parse /proc/net/hci files (generic 'bluetooth' format)
    """

REGISTER_FILE("/proc/net/hci", ProcNetHCI)
REGISTER_PARTIAL_FILE("hci", ProcNetHCI)



#
class ProcNetL2CAP(ProcNetGPBLUETOOTH):
    """
    Parse /proc/net/l2cap files (generic 'bluetooth' format)
    """

REGISTER_FILE("/proc/net/l2cap", ProcNetL2CAP)
REGISTER_PARTIAL_FILE("l2cap", ProcNetL2CAP)



#
class ProcNetPNP(PBR.FixedWhitespaceDelimRecs):
    """
    Parse nameserver config data file /proc/net/pnp
    """

# source: net/ipv4/ipconfig.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 1
        self.proto_used_pref = "#"
        self.__proto_used = ""
        self.dtype_map = { "domain": PFC.F_DOMAIN,
                "nameserver": PFC.F_NAMESERVER,
                "bootserver": PFC.F_BOOTSERVER }
        return

    def extra_next(self, sio):

        self.field[PFC.F_PROTO_USED] = self.__proto_used
        self.field[PFC.F_DOMAIN] = ""
        self.field[PFC.F_NAMESERVER] = ""
        self.field[PFC.F_BOOTSERVER] = ""

        if sio.linewords == 1:
            __prot = sio.get_word(0)
            if __prot[:1] == self.proto_used_pref:
                self.__proto_used = __prot[1:]
            return self.next()

        __dtype = sio.get_word(0)

        try:
            __vname = self.dtype_map[__dtype]
            self.field[__vname] = sio.get_word(1)

        except KeyError:
            pass

        return (self.field[PFC.F_PROTO_USED], self.field[PFC.F_DOMAIN],
                self.field[PFC.F_NAMESERVER], self.field[PFC.F_BOOTSERVER])

REGISTER_FILE("/proc/net/pnp", ProcNetPNP)
REGISTER_PARTIAL_FILE("pnp", ProcNetPNP)



# ---
class ProcNetRAW6(ProcNetUDP6):
    """
    Parse records from /proc/net/raw6, format is identical to 'udp6'
    """

# source #1: net/ipv6/raw.c
# source #2: include/net/transp_v6.h
# source #3: net/ipv6/datagram.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.

REGISTER_FILE("/proc/net/raw6", ProcNetRAW6)
REGISTER_PARTIAL_FILE("raw6", ProcNetRAW6)



# ---
class ProcNetXFRMSTAT(PBR.TaggedMultiLineFile):
    """
    Parsing class for Fedora/Centos file /proc/net/xfrm_stat
    """

# source: net/xfrm/xfrm_proc.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
        self.minfields = 2

        PBR.add_parse_rule(self, { PREFIX: "XfrmInError ", NAME: PFC.F_INERROR,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInBufferError ",
                NAME: PFC.F_INBUFFERERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInHdrError ",
                NAME: PFC.F_INHDRERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInNoStates ",
                NAME: PFC.F_INNOSTATES, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateProtoError ",
                NAME: PFC.F_INSTATEPROTOERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateModeError ",
                NAME: PFC.F_INSTATEMODEERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateSeqError ",
                NAME: PFC.F_INSTATESEQERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateExpired ",
                NAME: PFC.F_INSTATEEXPIRED, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateMismatch ",
                NAME: PFC.F_INSTATEMISMATCH, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInStateInvalid ",
                NAME: PFC.F_INSTATEINVALID, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInTmplMismatch ",
                NAME: PFC.F_INTMPLMISMATCH, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInNoPols ",
                NAME: PFC.F_INNOPOLS, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInPolBlock ",
                NAME: PFC.F_INPOLBLOCK, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmInPolError ",
                NAME: PFC.F_INPOLERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutError ",
                NAME: PFC.F_OUTERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutBundleGenError ",
                NAME: PFC.F_OUTBUNDLEGENERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutBundleCheckError ",
                NAME: PFC.F_OUTBUNDLECHECKERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutNoStates ",
                NAME: PFC.F_OUTNOSTATES, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutStateProtoError ",
                NAME: PFC.F_OUTSTATEPROTOERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutStateModeError ",
                NAME: PFC.F_OUTSTATEMODEERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutStateSeqError ",
                NAME: PFC.F_OUTSTATESEQERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutStateExpired ",
                NAME: PFC.F_OUTSTATEEXPIRED, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutPolBlock ",
                NAME: PFC.F_OUTPOLBLOCK, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutPolDead ",
                NAME: PFC.F_OUTPOLDEAD, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutPolError ",
                NAME: PFC.F_OUTPOLERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmFwdHdrError ",
                NAME: PFC.F_FWDHDRERROR, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmOutStateInvalid ",
                NAME: PFC.F_OUTSTATEINVALID, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "XfrmAcquireError ",
                NAME: PFC.F_ACQUIREERROR, CONV: long } )

        return

    def extra_next(self, sio):
        return self.field

REGISTER_FILE("/proc/net/xfrm_stat", ProcNetXFRMSTAT)
REGISTER_PARTIAL_FILE("xfrm_stat", ProcNetXFRMSTAT)


#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

if __name__ == "__main__":

    print "Collection of handlers to parse file in the /proc/net directory"
