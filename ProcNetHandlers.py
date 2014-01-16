#!/usr/bin/env python

# ---
# (C) 2012-2013 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.


import socket
import binascii
import IPAddressConv
import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

RegisterProcFileHandler = PBR.RegisterProcFileHandler
RegisterPartialProcFileHandler = PBR.RegisterPartialProcFileHandler
ShowHandlerFilePath = PBR.ShowHandlerFilePath
ProcFileToPath = PBR.ProcFileToPath

state_list = PDC.state_list




# ---
class ProcNetNETLINK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/netlink"""
# DCHK: 11/19/12
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

        self.protocol = 0
        self.pid = 0
        self.groups = 0
        self.dump = 0
        self.locks = 0
        self.drops = 0
        return

    def extra_next(self, sio):

# -- Sample records
# sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
# 0000000000000000 0   4196011 00000000 0        0        0000000000000000 2        0        11034   
# 0000000000000000 0   0      00000000 0        0        0000000000000000 2        0        8       
# 0000000000000000 0   1707   000a0501 0        0        0000000000000000 2        0        11033   

        if sio.buff == "":

            self.protocol = 0
            self.pid = 0
            self.groups = 0
            self.dump = 0
            self.locks = 0
            self.drops = 0

            self.field = dict()

            self.field[PFC.F_SOCKET_POINTER] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_PID] = 0
            self.field[PFC.F_GROUPS] = 0
            self.field[PFC.F_RMEM_ALLOC] = 0
            self.field[PFC.F_WMEM_ALLOC] = 0
            self.field[PFC.F_DUMP] = 0
            self.field[PFC.F_LOCKS] = 0
            self.field[PFC.F_DROPS] = 0
            self.field[PFC.F_INODE] = 0

        else:
            self.field[PFC.F_SOCKET_POINTER] = long(sio.lineparts[0], 16)
            self.field[PFC.F_PROTOCOL] = long(sio.lineparts[1])
            self.field[PFC.F_PID] = long(sio.lineparts[2])
            self.field[PFC.F_GROUPS] = long(sio.lineparts[3], 16)
            self.field[PFC.F_RMEM_ALLOC] = long(sio.lineparts[4])
            self.field[PFC.F_WMEM_ALLOC] = long(sio.lineparts[5])
            self.field[PFC.F_DUMP] = long(sio.lineparts[6], 16)
            self.field[PFC.F_LOCKS] = long(sio.lineparts[7])
            self.field[PFC.F_DROPS] = long(sio.lineparts[8])
            self.field[PFC.F_INODE] = long(sio.lineparts[9])

            self.protocol = self.field[PFC.F_PROTOCOL]
            self.pid = self.field[PFC.F_PID]
            self.groups = self.field[PFC.F_GROUPS]
            self.dump = self.field[PFC.F_DUMP]
            self.locks = self.field[PFC.F_LOCKS]
            self.drops = self.field[PFC.F_DROPS]

        return( self.protocol, self.pid, self.groups, self.dump, self.locks, self.drops)
#
RegisterProcFileHandler("/proc/net/netlink", ProcNetNETLINK)
RegisterPartialProcFileHandler("netlink", ProcNetNETLINK)


# ---
class ProcNetCONNECTOR(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/connector"""
# DCHK: 11/19/12
# source: drivers/connector/connector.c
#  list_for_each_entry(cbq, &dev->queue_list, callback_entry) {
#          seq_printf(m, "%-15s %u:%u\n",
#                     cbq->id.name,
#                     cbq->id.id.idx,
#                     cbq->id.id.val);

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Name"
        self.__FieldSplitDelim = ":"

        self.name = ""
        self.id_idx = 0
        self.id_val = 0
        return

    def extra_next(self, sio):

# -- Sample records
# Name            ID
# cn_proc         1:1

        if sio.buff == "":

            self.name = ""
            self.id_idx = 0
            self.id_val = 0

            self.field = dict()

            self.field[PFC.F_NAME] = ""
            self.field[PFC.F_ID_IDX] = 0
            self.field[PFC.F_ID_VAL] = 0

        else:
            self.field[PFC.F_NAME] = str(sio.lineparts[0])
            __split = sio.lineparts[1].partition(self.__FieldSplitDelim)
            self.field[PFC.F_ID_IDX] = long(__split[0])
            self.field[PFC.F_ID_VAL] = long(__split[2])

            self.name = self.field[PFC.F_NAME]
            self.id_idx = self.field[PFC.F_ID_IDX]
            self.id_val = self.field[PFC.F_ID_VAL]

        return( self.name, self.id_idx, self.id_val)
#
RegisterProcFileHandler("/proc/net/connector", ProcNetCONNECTOR)
RegisterPartialProcFileHandler("connector", ProcNetCONNECTOR)


# ---
class ProcNetPROTOCOLS(PBR.fixed_delim_format_recs):
    """Specific use of simple col reading class, for /proc/net/protocols file"""
# DCHK: 11/18/12
# source: net/core/sock.c
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

    def extra_init(self, *opts):
        self.minfields = 27
        self.skipped = "protocol"

        self.protocol = ""
        self.size = 0
        self.sockets = 0
        self.memory = 0
        self.module = ""
        return

    def extra_next(self, sio):
# -- Sample entries
# protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em
# BNEP       664      0      -1   NI       0   no   bnep        n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# RFCOMM     680      0      -1   NI       0   no   rfcomm      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# SCO        680      0      -1   NI       0   no   bluetooth   n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# PACKET    1344      1      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n

        if sio.buff == "":

            self.protocol = ""
            self.size = 0
            self.sockets = 0
            self.memory = 0
            self.module = ""

            self.field = dict()

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

        else:
            self.field[PFC.F_PROTOCOL] = str(sio.lineparts[0])
            self.field[PFC.F_SIZE] = long(sio.lineparts[1])
            self.field[PFC.F_SOCKETS] = long(sio.lineparts[2])
            self.field[PFC.F_MEMORY] = long(sio.lineparts[3])
            self.field[PFC.F_PRESSURE] = str(sio.lineparts[4])
            self.field[PFC.F_MAX_HEADER] = long(sio.lineparts[5])
            self.field[PFC.F_SLAB] = str(sio.lineparts[6])
            self.field[PFC.F_MODULE] = str(sio.lineparts[7])
            self.field[PFC.F_CLOSE] = str(sio.lineparts[8])
            self.field[PFC.F_CONNECT] = str(sio.lineparts[9])
            self.field[PFC.F_DISCONNECT] = str(sio.lineparts[10])
            self.field[PFC.F_ACCEPT] = str(sio.lineparts[11])
            self.field[PFC.F_IOCTL] = str(sio.lineparts[12])
            self.field[PFC.F_INIT] = str(sio.lineparts[13])
            self.field[PFC.F_DESTROY] = str(sio.lineparts[14])
            self.field[PFC.F_SHUTDOWN] = str(sio.lineparts[15])
            self.field[PFC.F_SETSOCKOPT] = str(sio.lineparts[16])
            self.field[PFC.F_GETSOCKOPT] = str(sio.lineparts[17])
            self.field[PFC.F_SENDMSG] = str(sio.lineparts[18])
            self.field[PFC.F_RECVMSG] = str(sio.lineparts[19])
            self.field[PFC.F_SENDPAGE] = str(sio.lineparts[20])
            self.field[PFC.F_BIND] = str(sio.lineparts[21])
            self.field[PFC.F_BACKLOG_RCV] = str(sio.lineparts[22])
            self.field[PFC.F_HASH] = str(sio.lineparts[23])
            self.field[PFC.F_UNHASH] = str(sio.lineparts[24])
            self.field[PFC.F_GET_PORT] = str(sio.lineparts[25])
            self.field[PFC.F_ENTER_PRESSURE] = str(sio.lineparts[26])

            self.protocol = self.field[PFC.F_PROTOCOL]
            self.size = self.field[PFC.F_SIZE]
            self.sockets = self.field[PFC.F_SOCKETS]
            self.memory = self.field[PFC.F_MEMORY]
            self.module = self.field[PFC.F_MODULE]

        return( self.protocol, self.size, self.sockets, self.memory, self.module)
#
RegisterProcFileHandler("/proc/net/protocols", ProcNetPROTOCOLS)
RegisterPartialProcFileHandler("protocols", ProcNetPROTOCOLS)


# ---
class ProcNetROUTE(PBR.fixed_delim_format_recs):
    """Specific use of simple col reading class, for /proc/net/route file"""
# DCHK: 11/16/12
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

        self.interface = ""
        self.destination = ""
        self.gateway = ""
        self.netmask = ""
        return

    def extra_next(self, sio):
# -- Samples lines.
# Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT                                                       
# eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0                                                                               
# eth0	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0                                                                            
# eth0	0001A8C0	00000000	0001	0	0	1	00FFFFFF	0	0	0                                                                               

        if sio.buff == "":
            self.interface = PDC.ANY_INTERFACE
            self.destination = PDC.ANY_IP_ADDR
            self.gateway = PDC.ANY_IP_ADDR
            self.netmask = PDC.ANY_IP_ADDR

            self.field = dict()

            self.field[PFC.F_INTERFACE] = PDC.ANY_INTERFACE
            self.field[PFC.F_DEST_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_GATE_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_FLAGS] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_USECOUNT] = 0
            self.field[PFC.F_METRIC] = 0
            self.field[PFC.F_MASK_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_MTU] = 0
            self.field[PFC.F_WINDOW] = 0
            self.field[PFC.F_IRTT] = 0
            self.field[PFC.F_DEST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_GATEWAY] = PDC.ANY_IP_ADDR
            self.field[PFC.F_NETMASK] = PDC.ANY_IP_ADDR
    
        else:
            self.field[PFC.F_INTERFACE] = sio.lineparts[0]
            self.field[PFC.F_DEST_HEXIP] = str(sio.lineparts[1])
            self.field[PFC.F_GATE_HEXIP] = str(sio.lineparts[2])
            self.field[PFC.F_FLAGS] = long(sio.lineparts[3], 16)
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[4])
            self.field[PFC.F_USECOUNT] = long(sio.lineparts[5])
            self.field[PFC.F_METRIC] = long(sio.lineparts[6])
            self.field[PFC.F_MASK_HEXIP] = str(sio.lineparts[7])
            self.field[PFC.F_MTU] = long(sio.lineparts[8])
            self.field[PFC.F_WINDOW] = long(sio.lineparts[9])
            self.field[PFC.F_IRTT] = long(sio.lineparts[10])

            __hexip = self.field[PFC.F_DEST_HEXIP]
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            __hexip = self.field[PFC.F_GATE_HEXIP]
            self.field[PFC.F_GATEWAY] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            __hexip = self.field[PFC.F_MASK_HEXIP]
            self.field[PFC.F_NETMASK] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            self.interface = self.field[PFC.F_INTERFACE]
            self.destination = self.field[PFC.F_DEST_IP]
            self.gateway = self.field[PFC.F_GATEWAY]
            self.netmask = self.field[PFC.F_NETMASK]

        return( self.interface, self.destination, self.gateway, self.netmask)
#
RegisterProcFileHandler("/proc/net/route", ProcNetROUTE)
RegisterPartialProcFileHandler("route", ProcNetROUTE)


# ---
class ProcNetPACKET(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/packet"""
# DCHK: 11/18/12
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

            self.type = 0
            self.protocol = 0
            self.interface_index = 0
            self.running = 0
            self.rmem_alloc = 0
            self.uid = 0

            self.field = dict()

            self.field[PFC.F_SOCKET_POINTER] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_TYPE] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_RUNNING] = 0
            self.field[PFC.F_RMEM_ALLOC] = 0
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_INODE] = 0

        else:
            self.field[PFC.F_SOCKET_POINTER] = long(sio.lineparts[0], 16)
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[1])
            self.field[PFC.F_TYPE] = long(sio.lineparts[2])
            self.field[PFC.F_PROTOCOL] = long(sio.lineparts[3], 16)
            self.field[PFC.F_INT_INDEX] = long(sio.lineparts[4])
            self.field[PFC.F_RUNNING] = long(sio.lineparts[5])
            self.field[PFC.F_RMEM_ALLOC] = long(sio.lineparts[6])
            self.field[PFC.F_UID] = long(sio.lineparts[7])
            self.field[PFC.F_INODE] = long(sio.lineparts[8])

            self.type = self.field[PFC.F_TYPE]
            self.protocol = self.field[PFC.F_PROTOCOL]
            self.interface_index = self.field[PFC.F_INT_INDEX]
            self.running = self.field[PFC.F_RUNNING]
            self.rmem_alloc = self.field[PFC.F_RMEM_ALLOC]
            self.uid = self.field[PFC.F_UID]

        return( self.type, self.protocol, self.interface_index, self.running, self.rmem_alloc, self.uid)
#
RegisterProcFileHandler("/proc/net/packet", ProcNetPACKET)
RegisterPartialProcFileHandler("packet", ProcNetPACKET)


# ---
class ProcNetSOFTNET_STAT(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/softnet_stat"""
# DCHK: 11/18/12
# source: net/core/dev.c
#         seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
#                   sd->processed, sd->dropped, sd->time_squeeze, 0,
#                   0, 0, 0, 0, /* was fastroute */
#                   sd->cpu_collision, sd->received_rps);

    def extra_init(self, *opts):
        self.minfields = 10

        self.processed = 0
        self.dropped = 0
        self.time_squeeze = 0
        self.cpu_coll = 0
        self.received_rps = 0
        return

    def extra_next(self, sio):
# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# Processed Dropped Time_Squeeze Null1 Null2   Null3    Null4    Null5    CPU_Coll Received_RPS
# 001fc1c7 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 00002970 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 000041b2 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

        if sio.buff == "":

            self.processed = 0
            self.dropped = 0
            self.time_squeeze = 0
            self.cpu_coll = 0
            self.received_rps = 0

            self.field = dict()

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

        else:
            self.field[PFC.F_PROCESSED] = long(sio.lineparts[0], 16)
            self.field[PFC.F_DROPPED] = long(sio.lineparts[1], 16)
            self.field[PFC.F_TIME_SQUEEZE] = long(sio.lineparts[2], 16)
            self.field[PFC.F_ZERO1] = long(sio.lineparts[3], 16)
            self.field[PFC.F_ZERO2] = long(sio.lineparts[4], 16)
            self.field[PFC.F_ZERO3] = long(sio.lineparts[5], 16)
            self.field[PFC.F_ZERO4] = long(sio.lineparts[6], 16)
            self.field[PFC.F_ZERO5] = long(sio.lineparts[7], 16)
            self.field[PFC.F_CPU_COLL] = long(sio.lineparts[8], 16)
            self.field[PFC.F_RECEIVED_RPS] = long(sio.lineparts[9], 16)

            self.processed = self.field[PFC.F_PROCESSED]
            self.dropped = self.field[PFC.F_DROPPED]
            self.time_squeeze = self.field[PFC.F_TIME_SQUEEZE]
            self.cpu_coll = self.field[PFC.F_CPU_COLL]
            self.received_rps = self.field[PFC.F_RECEIVED_RPS]

        return( self.processed, self.dropped, self.time_squeeze, self.cpu_coll, self.received_rps)
#
RegisterProcFileHandler("/proc/net/softnet_stat", ProcNetSOFTNET_STAT)
RegisterPartialProcFileHandler("softnet_stat", ProcNetSOFTNET_STAT)



# ---
class ProcNetARP(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/arp"""
# DCHK: 11/16/12
# source: net/ipv4/arp.c
#        seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
#                   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);

    def extra_init(self, *opts):
        self.minfields = 6
        self.skipped = "IP"

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
            self.ip_addr = PDC.ANY_IP_ADDR
            self.hw_addr = PDC.ANY_HW_ADDR
            self.device = PDC.ANY_INTERFACE

            self.field = dict()

            self.field[PFC.F_IP_ADDRESS] = PDC.ANY_IP_ADDR
            self.field[PFC.F_HW_TYPE] = "0x0"
            self.field[PFC.F_FLAGS] = "0x0"
            self.field[PFC.F_HW_ADDRESS] = PDC.ANY_HW_ADDR
            self.field[PFC.F_MASK] = "*"
            self.field[PFC.F_DEVICE] = PDC.ANY_INTERFACE

        else:
            self.field[PFC.F_IP_ADDRESS] = sio.lineparts[0]
            self.field[PFC.F_HW_TYPE] = long(sio.lineparts[1], 16)
            self.field[PFC.F_FLAGS] = long(sio.lineparts[2], 16)
            self.field[PFC.F_HW_ADDRESS] = sio.lineparts[3]
            self.field[PFC.F_MASK] = sio.lineparts[4]
            self.field[PFC.F_DEVICE] = sio.lineparts[5]

            self.ip_addr = self.field[PFC.F_IP_ADDRESS]
            self.hw_addr = self.field[PFC.F_HW_TYPE]
            self.device = self.field[PFC.F_DEVICE]

        return( self.ip_addr, self.hw_addr, self.device)
#
RegisterProcFileHandler("/proc/net/arp", ProcNetARP)
RegisterPartialProcFileHandler("arp", ProcNetARP)



# ---
class ProcNetDEV_MCAST(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/dev_mcast"""
# DCHK: 11/17/12
# source: net/core/dev_addr_lists.ca
#                seq_printf(seq, "%-4d %-15s %-5d %-5d ", dev->ifindex,
#                           dev->name, ha->refcount, ha->global_use);
#
#                for (i = 0; i < dev->addr_len; i++)
#                        seq_printf(seq, "%02x", ha->addr[i]);

    def extra_init(self, *opts):
        self.minfields = 5

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
            self.device = ""
            self.ref_count = 0
            self.global_use = 0

            self.field = dict()

            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_GLOBAL_USE] = 0
            self.field[PFC.F_DEV_ADDR] = "000000000000"

        else:
            self.field[PFC.F_INT_INDEX] = long(sio.lineparts[0])
            self.field[PFC.F_DEVICE] = str(sio.lineparts[1])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[2])
            self.field[PFC.F_GLOBAL_USE] = long(sio.lineparts[3])
            self.field[PFC.F_DEV_ADDR] = str(sio.lineparts[4])

            self.device = self.field[PFC.F_DEVICE]
            self.ref_count = self.field[PFC.F_REFCOUNT]
            self.global_use = self.field[PFC.F_GLOBAL_USE]

        return( self.device, self.ref_count, self.global_use)
#
RegisterProcFileHandler("/proc/net/dev_mcast", ProcNetDEV_MCAST)
RegisterPartialProcFileHandler("dev_mcast", ProcNetDEV_MCAST)



# ---
class ProcNetDEV(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/dev"""
# DCHK: 11/16/12
# source: net/core/dev.c
#        seq_printf(seq, "%6s: %7llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu "
#                   "%8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
#                   dev->name, stats->rx_bytes, stats->rx_packets,
#                   stats->rx_errors,
#                   stats->rx_dropped + stats->rx_missed_errors,
#                   stats->rx_fifo_errors,
#                   stats->rx_length_errors + stats->rx_over_errors +
#                    stats->rx_crc_errors + stats->rx_frame_errors,
#                   stats->rx_compressed, stats->multicast,
#                   stats->tx_bytes, stats->tx_packets,
#                   stats->tx_errors, stats->tx_dropped,
#                   stats->tx_fifo_errors, stats->collisions,
#                   stats->tx_carrier_errors +
#                    stats->tx_aborted_errors +
#                    stats->tx_window_errors +
#                    stats->tx_heartbeat_errors,
#                   stats->tx_compressed);

    def extra_init(self, *opts):
        self.minfields = 17
        self.skipped = "face"

        self.device = ""
        self.rx_packets = 0
        self.rx_errors = 0
        self.tx_packets = 0
        self.tx_errors = 0
        return

    def extra_next(self, sio):
# -- Samples lines.
# Inter-|   Receive                                                |  Transmit
#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
#     lo: 102519022  306837    0    0    0     0          0         0 102519022  306837    0    0    0     0       0          0
#   eth0: 1618664727 5080413    0    0    0     0          0    312848 915217483 4396111    0    0    0     0       0          0

        if sio.buff == "":
            self.device = PDC.ANY_INTERFACE
            self.rx_packets = 0
            self.rx_errors = 0
            self.tx_packets = 0
            self.tx_errors = 0

            self.field = dict()

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

        else:
            __dev = sio.lineparts[0]
            if __dev[-1:] == ":":
                __dev = __dev[:-1]
            self.field[PFC.F_DEVICE] = __dev
            self.field[PFC.F_RX_BYTES] = long(sio.lineparts[1])
            self.field[PFC.F_RX_PACKETS] = long(sio.lineparts[2])
            self.field[PFC.F_RX_ERRORS] = long(sio.lineparts[3])
            self.field[PFC.F_RX_DROP] = long(sio.lineparts[4])
            self.field[PFC.F_RX_FIFO] = long(sio.lineparts[5])
            self.field[PFC.F_RX_FRAME] = long(sio.lineparts[6])
            self.field[PFC.F_RX_COMPRESSED] = long(sio.lineparts[7])
            self.field[PFC.F_RX_MULTICAST] = long(sio.lineparts[8])
            self.field[PFC.F_TX_BYTES] = long(sio.lineparts[9])
            self.field[PFC.F_TX_PACKETS] = long(sio.lineparts[10])
            self.field[PFC.F_TX_ERRORS] = long(sio.lineparts[11])
            self.field[PFC.F_TX_DROP] = long(sio.lineparts[12])
            self.field[PFC.F_TX_FIFO] = long(sio.lineparts[13])
            self.field[PFC.F_TX_COLLISION] = long(sio.lineparts[14])
            self.field[PFC.F_TX_CARRIER] = long(sio.lineparts[15])
            self.field[PFC.F_TX_COMPRESSED] = long(sio.lineparts[16])

            self.device = self.field[PFC.F_DEVICE]
            self.rx_packets = self.field[PFC.F_RX_PACKETS]
            self.rx_errors = self.field[PFC.F_RX_ERRORS]
            self.tx_packets = self.field[PFC.F_TX_PACKETS]
            self.tx_errors = self.field[PFC.F_TX_ERRORS]

        return( self.device, self.rx_packets, self.rx_errors, self.tx_packets, self.tx_errors)
#
RegisterProcFileHandler("/proc/net/dev", ProcNetDEV)
RegisterPartialProcFileHandler("dev", ProcNetDEV)



# ---
class ProcNetIF_INET6(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/if_inet6"""
# DCHK: 11/16/12
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

            self.ipv6 = PDC.ANY_IPV6_ADDR
            self.ipv6_hex = PDC.ANY_IPV6_ADDR_HEX
            self.scope = 0
            self.device = PDC.ANY_DEVICE

            self.field = dict()

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
            self.field[PFC.F_IPV6_HEX] = str(sio.lineparts[0])
            self.field[PFC.F_INT_INDEX_HEX] = str(sio.lineparts[1])
            self.field[PFC.F_INT_INDEX] = long(sio.lineparts[1], 16)
            self.field[PFC.F_PREFIX_LEN_HEX] = str(sio.lineparts[2])
            self.field[PFC.F_PREFIX_LEN_HEX] = long(sio.lineparts[2], 16)
            self.field[PFC.F_SCOPE_HEX] = str(sio.lineparts[3])
            self.field[PFC.F_SCOPE] = long(sio.lineparts[3], 16)
            self.field[PFC.F_FLAGS_HEX] = str(sio.lineparts[4])
            self.field[PFC.F_FLAGS] = long(sio.lineparts[4], 16)
            self.field[PFC.F_DEVICE] = sio.lineparts[5]
            self.field[PFC.F_IPV6] = self.ipconv.ipv6_hexstring_to_presentation(str(sio.lineparts[0]))

            self.ipv6 = self.field[PFC.F_IPV6]
            self.ipv6_hex = self.field[PFC.F_IPV6_HEX]
            self.scope = self.field[PFC.F_SCOPE]
            self.device = self.field[PFC.F_DEVICE]

        return( self.ipv6, self.ipv6_hex, self.scope, self.device)
#
RegisterProcFileHandler("/proc/net/if_inet6", ProcNetIF_INET6)
RegisterPartialProcFileHandler("if_inet6", ProcNetIF_INET6)



# ---
class ProcNetIGMP6(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/igmp6"""
# DCHK: 11/17/12
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

        self.device = PDC.ANY_DEVICE
        self.mcast_addr = PDC.PRESENT_ANY_IPV6_ADDR
        self.mcast_users = 0
        self.mcast_flags = PDC.NULL_MASK_HEX
        return

    def extra_next(self, sio):
# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# IntFaceIndex DeviceName MCastAddress             MCastUsers MCastFlags TimerExp 
# 1    lo              ff020000000000000000000000000001     1 0000000C 0
# 2    eth0            ff0200000000000000000001ff01e486     1 00000004 0
# 2    eth0            ff020000000000000000000000000001     1 0000000C 0

        if sio.buff == "":
            self.device = PDC.ANY_DEVICE
            self.mcast_addr = PDC.PRESENT_ANY_IPV6_ADDR
            self.mcast_users = 0
            self.mcast_flags = PDC.NULL_MASK_HEX
       
            self.field = dict()

            self.field[PFC.F_INT_INDEX] = 0
            self.field[PFC.F_DEVICE] = PDC.ANY_DEVICE
            self.field[PFC.F_MCAST_ADDR_HEX] = PDC.ANY_IPV6_ADDR_HEX
            self.field[PFC.F_MCAST_ADDR] = PDC.PRESENT_ANY_IPV6_ADDR
            self.field[PFC.F_MCAST_USERS] = 0
            self.field[PFC.F_MCAST_FLAGS] = PDC.NULL_MASK_HEX
            self.field[PFC.F_TIMER_EXPIRE] = 0

        else:
            self.field[PFC.F_INT_INDEX] = long(sio.lineparts[0])
            self.field[PFC.F_DEVICE] = str(sio.lineparts[1])
            self.field[PFC.F_MCAST_ADDR_HEX] = str(sio.lineparts[2])
            self.field[PFC.F_MCAST_USERS] = long(sio.lineparts[3])
            self.field[PFC.F_MCAST_FLAGS] = str(sio.lineparts[4])
            self.field[PFC.F_TIMER_EXPIRE] = long(sio.lineparts[5])
            self.field[PFC.F_MCAST_ADDR] = self.ipconv.ipv6_hexstring_to_presentation(str(sio.lineparts[2]))

            self.device = self.field[PFC.F_DEVICE]
            self.mcast_addr = self.field[PFC.F_MCAST_ADDR]
            self.mcast_users = self.field[PFC.F_MCAST_USERS]
            self.mcast_flags = self.field[PFC.F_MCAST_FLAGS]

        return( self.device, self.mcast_addr, self.mcast_users, self.mcast_flags)
#
RegisterProcFileHandler("/proc/net/igmp6", ProcNetIGMP6)
RegisterPartialProcFileHandler("igmp6", ProcNetIGMP6)



# ---
class ProcNetIP_CONNTRACK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/ip_conntrack"""
# DCHK: 11/25/12
# source: net/ipv4/netfilter/nf_conntrack_l3proto_ipv4_compat.c
#
# if (seq_printf(s, "%-8s %u %ld ",
# 	      l4proto->name, nf_ct_protonum(ct),
# 	      timer_pending(&ct->timeout)
# 	      ? (long)(ct->timeout.expires - jiffies)/HZ : 0) != 0)
# 	goto release;
#
# if (l4proto->print_conntrack && l4proto->print_conntrack(s, ct))
# 	goto release;
#
# if (print_tuple(s, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
# 		l3proto, l4proto))
# 	goto release;
#
# if (seq_print_acct(s, ct, IP_CT_DIR_ORIGINAL))
# 	goto release;
#
# if (!(test_bit(IPS_SEEN_REPLY_BIT, &ct->status)))
# 	if (seq_printf(s, "[UNREPLIED] "))
# 		goto release;
#
# if (print_tuple(s, &ct->tuplehash[IP_CT_DIR_REPLY].tuple,
# 		l3proto, l4proto))
# 	goto release;
#
# if (seq_print_acct(s, ct, IP_CT_DIR_REPLY))
# 	goto release;
#
# if (test_bit(IPS_ASSURED_BIT, &ct->status))
# 	if (seq_printf(s, "[ASSURED] "))
# 		goto release;
#
# #ifdef CONFIG_NF_CONNTRACK_MARK
# if (seq_printf(s, "mark=%u ", ct->mark))
# 	goto release;
# #endif
#
# if (ct_show_secctx(s, ct))
# 	goto release;
#
# if (seq_printf(s, "use=%u\n", atomic_read(&ct->ct_general.use)))
#
# ------------
# -- from seq_print_acct()
# return seq_printf(s, "packets=%llu bytes=%llu ",
#         (unsigned long long)acct[dir].packets,
#         (unsigned long long)acct[dir].bytes);
#
# ------------
# -- from ct_show_secctx()
#  ret = seq_printf(s, "secctx=%s ", secctx);

    def extra_init(self, *opts):
        self.minfields = 12

        self.__TUPLE_PREF = "src="
        self.__UNREPLIED_PREF = "["
        self.__PACKETS_PREF = "packets="
        self.__BYTES_PREF = "bytes="
        self.__USE_PREF = "use="
        self.__ASSURED_PREF = "["
        self.__MARK_PREF = "mark="
        self.__SECCTX_PREF = "secctx="
        self.__Val_Delim = "="

        self.protocol = ""
        self.__off = 0
        self.src_port = 0
        self.src_ip = PDC.ANY_IP_ADDR
        self.state = PDC.unknown_state
        self.timeout = 0
        self.dst_ip = PDC.ANY_IP_ADDR
        self.dst_port = 0
        return

    def extra_next(self, sio):
# -- Sample records, there is no header line and the fields presented can very from record to record, only the
# -- first 3 are guaranteed to always the protocol name, protocol number, and timeout. The rest will always
# -- be in the same order, but a number of fields may or may not be there.
# tcp      6 38 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55894 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55894 [ASSURED] mark=0 use=2
# tcp      6 34 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55890 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55890 [ASSURED] mark=0 use=2
# udp      17 18 src=192.168.1.14 dst=216.69.185.100 sport=9408 dport=53 src=216.69.185.100 dst=192.168.1.14 sport=53 dport=9408 mark=0 use=2
# udp      17 18 src=192.168.1.14 dst=192.42.93.30 sport=15257 dport=53 src=192.42.93.30 dst=192.168.1.14 sport=53 dport=15257 mark=0 use=2
# tcp      6 431959 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=33934 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=33934 [ASSURED] mark=0 use=2
# udp      17 17 src=127.0.0.1 dst=127.0.0.1 sport=60942 dport=53 src=127.0.0.1 dst=127.0.0.1 sport=53 dport=60942 mark=0 use=2
# tcp      6 431988 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=35348 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=35348 [ASSURED] mark=0 use=2
# udp      17 17 src=127.0.0.1 dst=127.0.0.1 sport=59830 dport=53 src=127.0.0.1 dst=127.0.0.1 sport=53 dport=59830 mark=0 use=2

        if sio.buff == "":

            self.protocol = ""
            self.timeout = 0
            self.state = PDC.unknown_state
            self.src_ip = PDC.ANY_IP_ADDR
            self.src_port = 0
            self.dst_ip = PDC.ANY_IP_ADDR
            self.dst_port = 0
           
            self.field = dict()

            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_STATE] = PDC.unknown_state
            self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_SRC_PORT] = 0
            self.field[PFC.F_OR_DST_PORT] = 0
            self.field[PFC.F_UNREPLIED] = ""
            self.field[PFC.F_OR_PACKETS] = 0
            self.field[PFC.F_OR_BYTES] = 0
            self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_SRC_PORT] = 0
            self.field[PFC.F_RE_DST_PORT] = 0
            self.field[PFC.F_RE_PACKETS] = 0
            self.field[PFC.F_RE_BYTES] = 0
            self.field[PFC.F_ASSURED] = ""
            self.field[PFC.F_MARK] = 0
            self.field[PFC.F_SECCTX] = 0
            self.field[PFC.F_USE] = 0

        else:
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_STATE] = PDC.unknown_state
            self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_SRC_PORT] = 0
            self.field[PFC.F_OR_DST_PORT] = 0
            self.field[PFC.F_UNREPLIED] = ""
            self.field[PFC.F_OR_PACKETS] = 0
            self.field[PFC.F_OR_BYTES] = 0
            self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_SRC_PORT] = 0
            self.field[PFC.F_RE_DST_PORT] = 0
            self.field[PFC.F_RE_PACKETS] = 0
            self.field[PFC.F_RE_BYTES] = 0
            self.field[PFC.F_ASSURED] = ""
            self.field[PFC.F_MARK] = 0
            self.field[PFC.F_SECCTX] = 0
            self.field[PFC.F_USE] = 0

            self.field[PFC.F_PROTOCOL] = str(sio.lineparts[0])
            self.field[PFC.F_PROTOCOL_NUM] = long(sio.lineparts[1])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[2])

            self.__off = 3

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__TUPLE_PREF)] != self.__TUPLE_PREF:
                self.field[PFC.F_STATE] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_OR_SRC_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_DST_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_SRC_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_DST_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__UNREPLIED_PREF)] == self.__UNREPLIED_PREF:
                self.field[PFC.F_UNREPLIED] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[PFC.F_OR_PACKETS] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[PFC.F_OR_BYTES] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_RE_SRC_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_DST_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_SRC_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_DST_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[PFC.F_RE_PACKETS] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[PFC.F_RE_BYTES] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__ASSURED_PREF)] == self.__ASSURED_PREF:
                self.field[PFC.F_ASSURED] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__MARK_PREF)] == self.__MARK_PREF:
                self.field[PFC.F_MARK] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__SECCTX_PREF)] == self.__SECCTX_PREF:
                self.field[PFC.F_SECCTX] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_USE] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
           
            self.protocol = self.field[PFC.F_PROTOCOL]
            self.timeout = self.field[PFC.F_TIMEOUT]
            self.state = self.field[PFC.F_STATE]
            self.src_ip = self.field[PFC.F_OR_SRC_IP]
            self.src_port = self.field[PFC.F_OR_SRC_PORT]
            self.dst_ip = self.field[PFC.F_OR_DST_IP]
            self.dst_port = self.field[PFC.F_OR_DST_PORT]

        return( self.protocol, self.timeout, self.state, self.src_ip, self.src_port, self.dst_ip, self.dst_port)
#
RegisterProcFileHandler("/proc/net/ip_conntrack", ProcNetIP_CONNTRACK)
RegisterPartialProcFileHandler("net/ip_conntrack", ProcNetIP_CONNTRACK)



# ---
class ProcNetIPV6_ROUTE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/ipv6_route"""
# DCHK: 11/17/12
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
# DestAddr                DestPrefLen SrcAddr                 AddrPrefLen PrimaryKey                    RT6I_METRIC DestRefCount DestUse RT6I_FLAGS Device
# fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0
# 00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 000010cf 00200200       lo
# fe80000000000000ca6000fffe01e486 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo
# ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0

        if sio.buff == "":
            self.dest_ip = PDC.PRESENT_ANY_IPV6_ADDR
            self.dest_pref_len = 0
            self.src_ip = PDC.PRESENT_ANY_IPV6_ADDR
            self.src_pref_len = 0
            self.dest_refcount = 0
            self.device = PDC.ANY_DEVICE

            self.field = dict()

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
            self.field[PFC.F_DEST_HEXIP] = str(sio.lineparts[0])
            self.field[PFC.F_DEST_PREFIX_LEN_HEX] = str(sio.lineparts[1])
            self.field[PFC.F_SRCE_HEXIP] = str(sio.lineparts[2])
            self.field[PFC.F_SRCE_PREFIX_LEN_HEX] = str(sio.lineparts[3])
            self.field[PFC.F_PRIMARY_KEY] = str(sio.lineparts[4])
            self.field[PFC.F_RT6I_METRIC] = long(sio.lineparts[5], 16)
            self.field[PFC.F_DEST_REFCOUNT] = long(sio.lineparts[6], 16)
            self.field[PFC.F_DEST_USE] = long(sio.lineparts[7], 16)
            self.field[PFC.F_RT6I_FLAGS] = str(sio.lineparts[8])
            self.field[PFC.F_DEVICE] = str(sio.lineparts[9])

            self.field[PFC.F_DEST_IP] = self.ipconv.ipv6_hexstring_to_presentation(self.field[PFC.F_DEST_HEXIP])
            self.field[PFC.F_DEST_PREFIX_LEN] = long(self.field[PFC.F_DEST_PREFIX_LEN_HEX], 16)
            self.field[PFC.F_SOURCE] = self.ipconv.ipv6_hexstring_to_presentation(self.field[PFC.F_SRCE_HEXIP])
            self.field[PFC.F_SRCE_PREFIX_LEN] = long(self.field[PFC.F_SRCE_PREFIX_LEN_HEX], 16)

            self.dest_ip = self.field[PFC.F_DEST_IP] 
            self.dest_pref_len = self.field[PFC.F_DEST_PREFIX_LEN]
            self.src_ip = self.field[PFC.F_SOURCE]
            self.src_pref_len = self.field[PFC.F_SRCE_PREFIX_LEN]
            self.dest_refcount = self.field[PFC.F_DEST_REFCOUNT]
            self.device = self.field[PFC.F_DEVICE]

        return( self.dest_ip, self.dest_pref_len, self.src_ip, self.src_pref_len, self.dest_refcount, self.device)
#
RegisterProcFileHandler("/proc/net/ipv6_route", ProcNetIPV6_ROUTE)
RegisterPartialProcFileHandler("ipv6_route", ProcNetIPV6_ROUTE)



# ---
class ProcNetNF_CONNTRACK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/nf_conntrack"""
# DCHK: 11/25/12
# source: net/netfilter/nf_conntrack_standalone.c
#
#    if (seq_printf(s, "%-8s %u %-8s %u %ld ",
#                   l3proto->name, nf_ct_l3num(ct),
#                   l4proto->name, nf_ct_protonum(ct),
#                   timer_pending(&ct->timeout)
#                   ? (long)(ct->timeout.expires - jiffies)/HZ : 0) != 0)
#            goto release;
# 
#    if (l4proto->print_conntrack && l4proto->print_conntrack(s, ct))
#            goto release;
# 
#    if (print_tuple(s, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
#                    l3proto, l4proto))
#            goto release;
# 
#    if (seq_print_acct(s, ct, IP_CT_DIR_ORIGINAL))
#            goto release;
# 
#    if (!(test_bit(IPS_SEEN_REPLY_BIT, &ct->status)))
#            if (seq_printf(s, "[UNREPLIED] "))
#                    goto release;
# 
#    if (print_tuple(s, &ct->tuplehash[IP_CT_DIR_REPLY].tuple,
#                    l3proto, l4proto))
#            goto release;
# 
#    if (seq_print_acct(s, ct, IP_CT_DIR_REPLY))
#            goto release;
# 
#    if (test_bit(IPS_ASSURED_BIT, &ct->status))
#            if (seq_printf(s, "[ASSURED] "))
#                    goto release;
# 
# #if defined(CONFIG_NF_CONNTRACK_MARK)
#    if (seq_printf(s, "mark=%u ", ct->mark))
#            goto release;
# #endif
# 
#    if (ct_show_secctx(s, ct))
#            goto release;
# 
# #ifdef CONFIG_NF_CONNTRACK_ZONES
#    if (seq_printf(s, "zone=%u ", nf_ct_zone(ct)))
#            goto release;
# #endif
# 
#    if (ct_show_delta_time(s, ct))
#            goto release;
# 
#    if (seq_printf(s, "use=%u\n", atomic_read(&ct->ct_general.use)))
#            goto release;
#
# ------------
# -- from ct_show_delta_time()
#         return seq_printf(s, "delta-time=%llu ",
#                          (unsigned long long)delta_time);
#
# ------------
# -- from seq_print_acct()
# return seq_printf(s, "packets=%llu bytes=%llu ",
#         (unsigned long long)acct[dir].packets,
#         (unsigned long long)acct[dir].bytes);
#
# ------------
# -- from ct_show_secctx()
#  ret = seq_printf(s, "secctx=%s ", secctx);

    def extra_init(self, *opts):
        self.minfields = 14

        self.__TUPLE_PREF = "src="
        self.__UNREPLIED_PREF = "["
        self.__PACKETS_PREF = "packets="
        self.__BYTES_PREF = "bytes="
        self.__USE_PREF = "use="
        self.__ASSURED_PREF = "["
        self.__MARK_PREF = "mark="
        self.__SECCTX_PREF = "secctx="
        self.__ZONE_PREF = "zone="
        self.__DELTA_TIME_PREF = "delta-time="

        self.__Val_Delim = "="

        self.protocol = ""
        self.src_port = 0
        self.src_ip = PDC.ANY_IP_ADDR
        self.state = PDC.unknown_state
        self.__off = 0
        self.l3_protocol = ""
        self.dst_port = 0
        self.timeout = 0
        self.dst_ip = PDC.ANY_IP_ADDR
        return

    def extra_next(self, sio):
# -- Sample records, there is no header line and the fields presented can very from record to record, only the
# -- first 3 are guaranteed to always the protocol name, protocol number, and timeout. The rest will always
# -- be in the same order, but a number of fields may or may not be there.
# ipv4     2 tcp      6 14 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55894 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55894 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 9 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55890 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55890 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 21 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55900 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55900 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431934 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=33934 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=33934 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431964 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=35348 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=35348 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431798 ESTABLISHED src=192.168.1.14 dst=72.167.218.187 sport=53880 dport=993 src=72.167.218.187 dst=192.168.1.14 sport=993 dport=53880 [ASSURED] mark=0 zone=0 use=2

        if sio.buff == "":

            self.l3_protocol = ""
            self.protocol = ""
            self.timeout = 0
            self.state = PDC.unknown_state
            self.src_ip = PDC.ANY_IP_ADDR
            self.src_port = 0
            self.dst_ip = PDC.ANY_IP_ADDR
            self.dst_port = 0
           
            self.field = dict()

            self.field[PFC.F_L3_PROTOCOL] = ""
            self.field[PFC.F_L3_PROTOCOL_NUM] = 0
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_STATE] = PDC.unknown_state
            self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_SRC_PORT] = 0
            self.field[PFC.F_OR_DST_PORT] = 0
            self.field[PFC.F_UNREPLIED] = ""
            self.field[PFC.F_OR_PACKETS] = 0
            self.field[PFC.F_OR_BYTES] = 0
            self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_SRC_PORT] = 0
            self.field[PFC.F_RE_DST_PORT] = 0
            self.field[PFC.F_RE_PACKETS] = 0
            self.field[PFC.F_RE_BYTES] = 0
            self.field[PFC.F_ASSURED] = ""
            self.field[PFC.F_MARK] = 0
            self.field[PFC.F_SECCTX] = 0
            self.field[PFC.F_ZONE] = 0
            self.field[PFC.F_DELTA_TIME] = 0
            self.field[PFC.F_USE] = 0

        else:
            self.field[PFC.F_L3_PROTOCOL] = ""
            self.field[PFC.F_L3_PROTOCOL_NUM] = 0
            self.field[PFC.F_PROTOCOL] = ""
            self.field[PFC.F_PROTOCOL_NUM] = 0
            self.field[PFC.F_TIMEOUT] = 0
            self.field[PFC.F_STATE] = PDC.unknown_state
            self.field[PFC.F_OR_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_OR_SRC_PORT] = 0
            self.field[PFC.F_OR_DST_PORT] = 0
            self.field[PFC.F_UNREPLIED] = ""
            self.field[PFC.F_OR_PACKETS] = 0
            self.field[PFC.F_OR_BYTES] = 0
            self.field[PFC.F_RE_SRC_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_DST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_RE_SRC_PORT] = 0
            self.field[PFC.F_RE_DST_PORT] = 0
            self.field[PFC.F_RE_PACKETS] = 0
            self.field[PFC.F_RE_BYTES] = 0
            self.field[PFC.F_ASSURED] = ""
            self.field[PFC.F_MARK] = 0
            self.field[PFC.F_SECCTX] = 0
            self.field[PFC.F_ZONE] = 0
            self.field[PFC.F_DELTA_TIME] = 0
            self.field[PFC.F_USE] = 0

            self.field[PFC.F_L3_PROTOCOL] = str(sio.lineparts[0])
            self.field[PFC.F_L3_PROTOCOL_NUM] = long(sio.lineparts[1])
            self.field[PFC.F_PROTOCOL] = str(sio.lineparts[2])
            self.field[PFC.F_PROTOCOL_NUM] = long(sio.lineparts[3])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[4])

            self.__off = 5

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__TUPLE_PREF)] != self.__TUPLE_PREF:
                self.field[PFC.F_STATE] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_OR_SRC_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_DST_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_SRC_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_OR_DST_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__UNREPLIED_PREF)] == self.__UNREPLIED_PREF:
                self.field[PFC.F_UNREPLIED] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[PFC.F_OR_PACKETS] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[PFC.F_OR_BYTES] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_RE_SRC_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_DST_IP] = str(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_SRC_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < sio.linewords:
                self.field[PFC.F_RE_DST_PORT] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[PFC.F_RE_PACKETS] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[PFC.F_RE_BYTES] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__ASSURED_PREF)] == self.__ASSURED_PREF:
                self.field[PFC.F_ASSURED] = str(sio.lineparts[self.__off])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__MARK_PREF)] == self.__MARK_PREF:
                self.field[PFC.F_MARK] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__SECCTX_PREF)] == self.__SECCTX_PREF:
                self.field[PFC.F_SECCTX] = sio.lineparts[self.__off].partition(self.__Val_Delim)[2]
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__ZONE_PREF)] == self.__ZONE_PREF:
                self.field[PFC.F_ZONE] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords and sio.lineparts[self.__off][0:len(self.__DELTA_TIME_PREF)] == self.__DELTA_TIME_PREF:
                self.field[PFC.F_DELTA_TIME] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < sio.linewords:
                self.field[PFC.F_USE] = long(sio.lineparts[self.__off].partition(self.__Val_Delim)[2])
           
            self.l3_protocol = self.field[PFC.F_L3_PROTOCOL]
            self.protocol = self.field[PFC.F_PROTOCOL]
            self.timeout = self.field[PFC.F_TIMEOUT]
            self.state = self.field[PFC.F_STATE]
            self.src_ip = self.field[PFC.F_OR_SRC_IP]
            self.src_port = self.field[PFC.F_OR_SRC_PORT]
            self.dst_ip = self.field[PFC.F_OR_DST_IP]
            self.dst_port = self.field[PFC.F_OR_DST_PORT]

        return( self.l3_protocol, self.protocol, self.timeout, self.state, self.src_ip, self.src_port, self.dst_ip, self.dst_port)
#
RegisterProcFileHandler("/proc/net/nf_conntrack", ProcNetNF_CONNTRACK)
RegisterPartialProcFileHandler("net/nf_conntrack", ProcNetNF_CONNTRACK)



# ---
class ProcNetPSCHED(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/psched"""
# DCHK: 11/18/12
# source: net/sched/sch_api.c
#       seq_printf(seq, "%08x %08x %08x %08x\n",
#                  (u32)NSEC_PER_USEC, (u32)PSCHED_TICKS2NS(1),
#                  1000000,
#                  (u32)NSEC_PER_SEC/(u32)ktime_to_ns(timespec_to_ktime(ts)));

    def extra_init(self, *opts):
        self.minfields = 4

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
            self.nsec_per_usec = 0
            self.psched_ticks = 0
            self.nsec_per_hrtime = 0

            self.field = dict()

            self.field[PFC.F_NSEC_PER_USEC] = 0
            self.field[PFC.F_PSCHED_TICKS] = 0
            self.field[PFC.F_UNKNOWN_FIELD] = 0
            self.field[PFC.F_NSEC_PER_HRTIME] = 0

        else:
            self.field[PFC.F_NSEC_PER_USEC] = long(sio.lineparts[0], 16)
            self.field[PFC.F_PSCHED_TICKS] = long(sio.lineparts[1], 16)
            self.field[PFC.F_UNKNOWN_FIELD] = long(sio.lineparts[2], 16)
            self.field[PFC.F_NSEC_PER_HRTIME] = long(sio.lineparts[3], 16)

            self.nsec_per_usec = self.field[PFC.F_NSEC_PER_USEC] 
            self.psched_ticks = self.field[PFC.F_PSCHED_TICKS] 
            self.nsec_per_hrtime = self.field[PFC.F_NSEC_PER_HRTIME]

        return( self.nsec_per_usec, self.psched_ticks, self.nsec_per_hrtime)
#
RegisterProcFileHandler("/proc/net/psched", ProcNetPSCHED)
RegisterPartialProcFileHandler("psched", ProcNetPSCHED)



# ---
class ProcNetPTYPE(PBR.fixed_delim_format_recs):
    """Abstraction layer to pull records from /proc/net/ptype"""
# DCHK: 2/5/13
#
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

        self.device_name = ""
        self.device_type = 0
        self.device_function = ""
        return

    def extra_next(self, sio):
# -- Sample lines for reference...
#
# Note: This file can't be parsed as blank delimited words, since the second field is sometimes
#       blank.  So we have to parse by columns, since the layout is fixed rather than delimited.
#       The normal "read_line" call can still be used to pull in the data.  But we just have to
#       pull column ranges from the buffer and the split words in the "lineparts" array is
#       ignored.
#
# Type Device      Function
# 0800          ip_rcv+0x0/0x300
# 0011          llc_rcv+0x0/0x370
# 0004          llc_rcv+0x0/0x370
# 0806          arp_rcv+0x0/0x140

        if sio.buff == "":
            self.device_name = self.device_function = ""
            self.device_type = 0

            self.field = dict()
            self.field[PFC.F_DEVICE_TYPE] = 0
            self.field[PFC.F_DEVICE_NAME] = ""
            self.field[PFC.F_DEVICE_FUNC] = ""

        else:
            self.device_type = sio.buff[0:4]
            if self.device_type != "ALL ":
                self.device_type = long(sio.buff[0:4], 16)
            self.device_name = str(sio.buff[5:13])
            self.device_function = str(sio.buff[14:-1])

            if self.device_name == "        ":
                self.device_name = ""

            self.field[PFC.F_DEVICE_TYPE] = self.device_type
            self.field[PFC.F_DEVICE_NAME] = self.device_name
            self.field[PFC.F_DEVICE_FUNC] = self.device_function

        return( self.device_type, self.device_name, self.device_function)
#
RegisterProcFileHandler("/proc/net/ptype", ProcNetPTYPE)
RegisterPartialProcFileHandler("ptype", ProcNetPTYPE)



# ---
class ProcNetRT6_STATS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/rt6_stats"""
# DCHK: 11/18/12
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
            self.nodes = 0
            self.route_nodes = 0
            self.route_entries = 0
            self.route_cache = 0
            self.discarded = 0

            self.field = dict()

            self.field[PFC.F_FIB_NODES] = 0
            self.field[PFC.F_FIB_ROUTE_NODES] = 0
            self.field[PFC.F_FIB_ROUTE_ALLOC] = 0
            self.field[PFC.F_FIB_ROUTE_ENTRIES] = 0
            self.field[PFC.F_FIB_ROUTE_CACHE] = 0
            self.field[PFC.F_FIB_DEST_OPS] = 0
            self.field[PFC.F_FIB_DISC_ROUTES] = 0

        else:
            self.field[PFC.F_FIB_NODES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_FIB_ROUTE_NODES] = long(sio.lineparts[1], 16)
            self.field[PFC.F_FIB_ROUTE_ALLOC] = long(sio.lineparts[2], 16)
            self.field[PFC.F_FIB_ROUTE_ENTRIES] = long(sio.lineparts[3], 16)
            self.field[PFC.F_FIB_ROUTE_CACHE] = long(sio.lineparts[4], 16)
            self.field[PFC.F_FIB_DEST_OPS] = long(sio.lineparts[5], 16)
            self.field[PFC.F_FIB_DISC_ROUTES] = long(sio.lineparts[6], 16)

            self.nodes = self.field[PFC.F_FIB_NODES] 
            self.route_nodes = self.field[PFC.F_FIB_ROUTE_NODES] 
            self.route_entries = self.field[PFC.F_FIB_ROUTE_ENTRIES] 
            self.route_cache = self.field[PFC.F_FIB_ROUTE_CACHE] 
            self.discarded = self.field[PFC.F_FIB_DISC_ROUTES] 

        return( self.nodes, self.route_nodes, self.route_entries, self.route_cache, self.discarded)
#
RegisterProcFileHandler("/proc/net/rt6_stats", ProcNetRT6_STATS)
RegisterPartialProcFileHandler("rt6_stats", ProcNetRT6_STATS)



# ---
class ProcNetRT_CACHE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/rt_cache"""
# DCHK: 11/16/12
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

        self.interface = PDC.ANY_INTERFACE
        self.destination = PDC.ANY_IP_ADDR
        self.gateway = PDC.ANY_IP_ADDR
        self.usecount = 0
        self.source = PDC.ANY_IP_ADDR
        self.spec_dst = PDC.ANY_IP_ADDR
        return

    def extra_next(self, sio):
# -- Samples lines.
# Iface	Destination	Gateway 	Flags		RefCnt	Use	Metric	Source		MTU	Window	IRTT	TOS	HHRef	HHUptod	SpecDst
# %s    %08X            %08X            %8X             %d      %u      %d      %08X            %d      %u      %u      %02X    %d      %1d     %08X
# eth0	C1874A61	0101A8C0	       0	0	0	0	0E01A8C0	1500	0	182	00	-1	1	0E01A8C0
# eth0	0101A8C0	0101A8C0	       0	0	375723	0	0E01A8C0	1500	0	113	00	-1	1	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	23	0	2BE07D4A	16436	0	0	00	-1	0	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	1	0	28846DD0	16436	0	0	00	-1	0	0E01A8C0

        if sio.buff == "":
            self.interface = PDC.ANY_INTERFACE
            self.destination = PDC.ANY_IP_ADDR
            self.gateway = PDC.ANY_IP_ADDR
            self.usecount = 0
            self.source = PDC.ANY_IP_ADDR
            self.spec_dst = PDC.ANY_IP_ADDR

            self.field = dict()

            self.field[PFC.F_INTERFACE] = PDC.ANY_INTERFACE
            self.field[PFC.F_DEST_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_GATE_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_FLAGS] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_USECOUNT] = 0
            self.field[PFC.F_METRIC] = 0
            self.field[PFC.F_SRCE_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_MTU] = 0
            self.field[PFC.F_WINDOW] = 0
            self.field[PFC.F_IRTT] = 0
            self.field[PFC.F_TOS] = 0
            self.field[PFC.F_HHREF] = 0
            self.field[PFC.F_HHUPTOD] = 0
            self.field[PFC.F_SPEC_HEXIP] = str(PDC.ANY_IP_ADDR_HEX)
            self.field[PFC.F_DEST_IP] = PDC.ANY_IP_ADDR
            self.field[PFC.F_GATEWAY] = PDC.ANY_IP_ADDR
            self.field[PFC.F_SOURCE] = PDC.ANY_IP_ADDR
            self.field[PFC.F_SPEC_DST] = PDC.ANY_IP_ADDR

        else:
            self.field[PFC.F_INTERFACE] = sio.lineparts[0]
            self.field[PFC.F_DEST_HEXIP] = str(sio.lineparts[1])
            self.field[PFC.F_GATE_HEXIP] = str(sio.lineparts[2])
            self.field[PFC.F_FLAGS] = long(sio.lineparts[3], 16)
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[4])
            self.field[PFC.F_USECOUNT] = long(sio.lineparts[5])
            self.field[PFC.F_METRIC] = long(sio.lineparts[6])
            self.field[PFC.F_SRCE_HEXIP] = str(sio.lineparts[7])
            self.field[PFC.F_MTU] = long(sio.lineparts[8])
            self.field[PFC.F_WINDOW] = long(sio.lineparts[9])
            self.field[PFC.F_IRTT] = long(sio.lineparts[10])
            self.field[PFC.F_TOS] = long(sio.lineparts[11], 16)
            self.field[PFC.F_HHREF] = long(sio.lineparts[12])
            self.field[PFC.F_HHUPTOD] = long(sio.lineparts[13])
            self.field[PFC.F_SPEC_HEXIP] = str(sio.lineparts[14])

            __hexip = self.field[PFC.F_DEST_HEXIP]
            self.field[PFC.F_DEST_IP] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            __hexip = self.field[PFC.F_GATE_HEXIP]
            self.field[PFC.F_GATEWAY] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            __hexip = self.field[PFC.F_SRCE_HEXIP]
            self.field[PFC.F_SOURCE] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            __hexip = self.field[PFC.F_SPEC_HEXIP]
            self.field[PFC.F_SPEC_DST] = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip, 16)))))

            self.interface = self.field[PFC.F_INTERFACE]
            self.destination = self.field[PFC.F_DEST_IP]
            self.gateway = self.field[PFC.F_GATEWAY]
            self.usecount = self.field[PFC.F_USECOUNT]
            self.source = self.field[PFC.F_SOURCE]
            self.spec_dst = self.field[PFC.F_SPEC_DST]

        return( self.interface, self.destination, self.gateway, self.usecount, self.source, self.spec_dst)
#
RegisterProcFileHandler("/proc/net/rt_cache", ProcNetRT_CACHE)
RegisterPartialProcFileHandler("net/rt_cache", ProcNetRT_CACHE)



# ---
class ProcNetStatARP_CACHE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/stat/arp_cache"""
# DCHK: 11/16/12
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

        self.lookups = 0
        self.hits = 0
        self.entries = 0
        return

    def extra_next(self, sio):
# -- Sample entries, note that each line is for a different CPU
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000

        if sio.buff == "":
            self.entries = 0
            self.lookups = 0
            self.hits = 0

            self.field = dict()

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
    
        else:
            self.field[PFC.F_ARP_ENTRIES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_ALLOC] = long(sio.lineparts[1], 16)
            self.field[PFC.F_DESTROY] = long(sio.lineparts[2], 16)
            self.field[PFC.F_HASH_GROW] = long(sio.lineparts[3], 16)
            self.field[PFC.F_LOOKUP] = long(sio.lineparts[4], 16)
            self.field[PFC.F_HIT] = long(sio.lineparts[5], 16)
            self.field[PFC.F_RES_FAIL] = long(sio.lineparts[6], 16)
            self.field[PFC.F_RCV_MCAST_PROBE] = long(sio.lineparts[7], 16)
            self.field[PFC.F_RCV_UCAST_PROBE] = long(sio.lineparts[8], 16)
            self.field[PFC.F_GC_PERIODIC] = long(sio.lineparts[9], 16)
            self.field[PFC.F_GC_FORCED] = long(sio.lineparts[10], 16)
            self.field[PFC.F_UNRES_DISCARD] = long(sio.lineparts[11], 16)

            self.entries = self.field[PFC.F_ARP_ENTRIES]
            self.lookups = self.field[PFC.F_LOOKUP]
            self.hits = self.field[PFC.F_HIT]

        return( self.entries, self.lookups, self.hits)
#
RegisterProcFileHandler("/proc/net/stat/arp_cache", ProcNetStatARP_CACHE)
RegisterPartialProcFileHandler("arp_cache", ProcNetStatARP_CACHE)



# ---
class ProcNetStatIP_CONNTRACK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/stat/ip_conntrack"""
# DCHK: 11/16/12
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
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000084  00003e17 00770ce7 00024cc0 0000060a 00012bf0 0006e07e 0006778b 0001e3f0 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000084  00000c51 00053265 0001cc23 00000041 0000d313 00006987 00006986 0001cc22 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000

        if sio.buff == "":
            self.entries = 0
            self.searched = 0
            self.found = 0
            self.new = 0
            self.invalid = 0
            self.ignore = 0
            self.delete = 0
            self.insert = 0
            self.drop = 0

            self.field = dict()

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

        else:
            self.field[PFC.F_ENTRIES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_SEARCHED] = long(sio.lineparts[1], 16)
            self.field[PFC.F_FOUND] = long(sio.lineparts[2], 16)
            self.field[PFC.F_NEW] = long(sio.lineparts[3], 16)
            self.field[PFC.F_INVALID] = long(sio.lineparts[4], 16)
            self.field[PFC.F_IGNORE] = long(sio.lineparts[5], 16)
            self.field[PFC.F_DELETE] = long(sio.lineparts[6], 16)
            self.field[PFC.F_DELETE_LIST] = long(sio.lineparts[7], 16)
            self.field[PFC.F_INSERT] = long(sio.lineparts[8], 16)
            self.field[PFC.F_INSERT_FAILED] = long(sio.lineparts[9], 16)
            self.field[PFC.F_DROP] = long(sio.lineparts[10], 16)
            self.field[PFC.F_DROP_EARLY] = long(sio.lineparts[11], 16)
            self.field[PFC.F_ICMP_ERROR] = long(sio.lineparts[12], 16)
            self.field[PFC.F_EXP_NEW] = long(sio.lineparts[13], 16)
            self.field[PFC.F_EXP_CREATE] = long(sio.lineparts[14], 16)
            self.field[PFC.F_EXP_DELETE] = long(sio.lineparts[15], 16)
            self.field[PFC.F_SEARCH_RESTART] = long(sio.lineparts[16], 16)

            self.entries = self.field[PFC.F_ENTRIES]
            self.searched = self.field[PFC.F_SEARCHED]
            self.found = self.field[PFC.F_FOUND]
            self.new = self.field[PFC.F_NEW]
            self.invalid = self.field[PFC.F_INVALID]
            self.ignore = self.field[PFC.F_IGNORE]
            self.delete = self.field[PFC.F_DELETE]
            self.insert = self.field[PFC.F_INSERT]
            self.drop = self.field[PFC.F_DROP]

        return( self.entries, self.searched, self.found, self.new, self.invalid, self.ignore, self.delete, self.insert, self.drop)
#
RegisterProcFileHandler("/proc/net/stat/ip_conntrack", ProcNetStatIP_CONNTRACK)
RegisterPartialProcFileHandler("stat/ip_conntrack", ProcNetStatIP_CONNTRACK)



# ---
class ProcNetStatNDISC_CACHE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/stat/ndisc_cache"""
# DCHK: 11/16/12
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

        self.entries = 0
        self.lookups = 0
        self.hits = 0
        return

    def extra_next(self, sio):

# -- Sample entries, note that each line is for a different CPU
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000

        if sio.buff == "":
            self.entries = 0
            self.lookups = 0
            self.hits = 0
    
            self.field = dict()
    
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
    
        else:
            self.field[PFC.F_ARP_ENTRIES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_ALLOC] = long(sio.lineparts[1], 16)
            self.field[PFC.F_DESTROY] = long(sio.lineparts[2], 16)
            self.field[PFC.F_HASH_GROW] = long(sio.lineparts[3], 16)
            self.field[PFC.F_LOOKUP] = long(sio.lineparts[4], 16)
            self.field[PFC.F_HIT] = long(sio.lineparts[5], 16)
            self.field[PFC.F_RES_FAIL] = long(sio.lineparts[6], 16)
            self.field[PFC.F_RCV_MCAST_PROBE] = long(sio.lineparts[7], 16)
            self.field[PFC.F_RCV_UCAST_PROBE] = long(sio.lineparts[8], 16)
            self.field[PFC.F_GC_PERIODIC] = long(sio.lineparts[9], 16)
            self.field[PFC.F_GC_FORCED] = long(sio.lineparts[10], 16)
            self.field[PFC.F_UNRES_DISCARD] = long(sio.lineparts[11], 16)

            self.entries = self.field[PFC.F_ARP_ENTRIES]
            self.lookups = self.field[PFC.F_LOOKUP]
            self.hits = self.field[PFC.F_HIT]

        return( self.entries, self.lookups, self.hits)
#
RegisterProcFileHandler("/proc/net/stat/ndisc_cache", ProcNetStatNDISC_CACHE)
RegisterPartialProcFileHandler("ndisc_cache", ProcNetStatNDISC_CACHE)



# ---
class ProcNetStatNF_CONNTRACK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/stat/nf_conntrack"""
# DCHK: 11/16/12
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
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000085  00003e40 007782a9 00024eab 0000060a 00012c63 0006e7c2 00067e99 0001e5a5 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000085  00000c5f 00053a15 0001ce59 00000041 0000d3b2 000069ca 000069c9 0001ce58 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000

        if sio.buff == "":
            self.entries = 0
            self.searched = 0
            self.found = 0
            self.new = 0
            self.invalid = 0
            self.ignore = 0
            self.delete = 0
            self.insert = 0
            self.drop = 0
    
            self.field = dict()
    
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

        else:
            self.field[PFC.F_ENTRIES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_SEARCHED] = long(sio.lineparts[1], 16)
            self.field[PFC.F_FOUND] = long(sio.lineparts[2], 16)
            self.field[PFC.F_NEW] = long(sio.lineparts[3], 16)
            self.field[PFC.F_INVALID] = long(sio.lineparts[4], 16)
            self.field[PFC.F_IGNORE] = long(sio.lineparts[5], 16)
            self.field[PFC.F_DELETE] = long(sio.lineparts[6], 16)
            self.field[PFC.F_DELETE_LIST] = long(sio.lineparts[7], 16)
            self.field[PFC.F_INSERT] = long(sio.lineparts[8], 16)
            self.field[PFC.F_INSERT_FAILED] = long(sio.lineparts[9], 16)
            self.field[PFC.F_DROP] = long(sio.lineparts[10], 16)
            self.field[PFC.F_DROP_EARLY] = long(sio.lineparts[11], 16)
            self.field[PFC.F_ICMP_ERROR] = long(sio.lineparts[12], 16)
            self.field[PFC.F_EXP_NEW] = long(sio.lineparts[13], 16)
            self.field[PFC.F_EXP_CREATE] = long(sio.lineparts[14], 16)
            self.field[PFC.F_EXP_DELETE] = long(sio.lineparts[15], 16)
            self.field[PFC.F_SEARCH_RESTART] = long(sio.lineparts[16], 16)

            self.entries = self.field[PFC.F_ENTRIES]
            self.searched = self.field[PFC.F_SEARCHED]
            self.found = self.field[PFC.F_FOUND]
            self.new = self.field[PFC.F_NEW]
            self.invalid = self.field[PFC.F_INVALID]
            self.ignore = self.field[PFC.F_IGNORE]
            self.delete = self.field[PFC.F_DELETE]
            self.insert = self.field[PFC.F_INSERT]
            self.drop = self.field[PFC.F_DROP]

        return( self.entries, self.searched, self.found, self.new, self.invalid, self.ignore, self.delete, self.insert, self.drop)
#
RegisterProcFileHandler("/proc/net/stat/nf_conntrack", ProcNetStatNF_CONNTRACK)
RegisterPartialProcFileHandler("stat/nf_conntrack", ProcNetStatNF_CONNTRACK)



# ---
class ProcNetStatRT_CACHE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/stat/rt_cache"""
# DCHK: 11/16/12
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

        self.entries = 0
        self.in_hit = 0
        self.in_slow = 0
        self.out_hit = 0
        self.out_slow = 0
        return

    def extra_next(self, sio):
# -- Sample entries, note that each line is for a different CPU
# entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search
# 000000a4  00579509 0002044f 00000000 00000000 00001e53 00000000 00000018  0006f8ff 00002620 00000001 00000000 00000000 00000000 00000000 0000ba0b 00000092 
# 000000a4  00000000 00000002 00000000 00000000 00000001 00000000 00000000  0006f479 000027b4 00000000 00000000 00000000 00000000 00000000 00000000 00000008 

        if sio.buff == "":
            self.entries = 0
            self.in_hit = 0
            self.in_slow = 0
            self.out_hit = 0
            self.out_slow = 0
    
            self.field = dict()
    
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
    
        else:
            self.field[PFC.F_ENTRIES] = long(sio.lineparts[0], 16)
            self.field[PFC.F_IN_HIT] = long(sio.lineparts[1], 16)
            self.field[PFC.F_IN_SLOW_TOT] = long(sio.lineparts[2], 16)
            self.field[PFC.F_IN_SLOW_MC] = long(sio.lineparts[3], 16)
            self.field[PFC.F_IN_NO_ROUTE] = long(sio.lineparts[4], 16)
            self.field[PFC.F_IN_BRD] = long(sio.lineparts[5], 16)
            self.field[PFC.F_IN_MARTIAN_DST] = long(sio.lineparts[6], 16)
            self.field[PFC.F_IN_MARTIAN_SRC] = long(sio.lineparts[7], 16)
            self.field[PFC.F_OUT_HIT] = long(sio.lineparts[8], 16)
            self.field[PFC.F_OUT_SLOW_TOT] = long(sio.lineparts[9], 16)
            self.field[PFC.F_OUT_SLOW_MC] = long(sio.lineparts[10], 16)
            self.field[PFC.F_GC_TOTAL] = long(sio.lineparts[11], 16)
            self.field[PFC.F_GC_IGNORED] = long(sio.lineparts[12], 16)
            self.field[PFC.F_GC_GOAL_MISS] = long(sio.lineparts[13], 16)
            self.field[PFC.F_GC_DST_OVERFLOW] = long(sio.lineparts[14], 16)
            self.field[PFC.F_IN_HL_SEARCH] = long(sio.lineparts[15], 16)
            self.field[PFC.F_OUT_HL_SEARCH] = long(sio.lineparts[16], 16)

            self.entries = self.field[PFC.F_ENTRIES]
            self.in_hit = self.field[PFC.F_IN_HIT]
            self.in_slow = self.field[PFC.F_IN_SLOW_TOT]
            self.out_hit = self.field[PFC.F_OUT_HIT]
            self.out_slow = self.field[PFC.F_OUT_SLOW_TOT]

        return( self.entries, self.in_hit, self.in_slow, self.out_hit, self.out_slow)
#
RegisterProcFileHandler("/proc/net/stat/rt_cache", ProcNetStatRT_CACHE)
RegisterPartialProcFileHandler("stat/rt_cache", ProcNetStatRT_CACHE)



# ---
class ProcNetTCP6(PBR.fixed_delim_format_recs):
    """Abstraction layer to pull records from /proc/net/tcp6"""
# DCHK: 2/3/13
# source: net/ipv6/tcp_ipv6.c
# Note: Just as with the "tcp4" code, the source has three separate sections that
#       write data to this proc file.  And the one used depends on the state of the
#       connection, "open" is handled one way, "time_wait" another, and the code
#       snippet included here is used for any other connection state.  This one has
#       more fields, so I'm using it as the sample code.  Some of the fields at the
#       end are un-labelled in the proc file (meaning there's no column heading).
#       So the constants used to reference them were picked based on what the values
#       appear to be after reviewing the code.
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

    def extra_init(self, *opts):
        self.minfields = 12
        self.skipped = "sl"
        self.__FieldSplitDelim = ":"
        self.ipconv = IPAddressConv

        self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):
# -- Sample lines for reference...
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
#   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 1995 1 0000000000000000 100 0 0 2 -1
#   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1892 1 0000000000000000 100 0 0 2 -1

        if sio.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[PFC.F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "::0"
            self.field[PFC.F_DEST_IP] = "::0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.unknown_state
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
            self.orig_hexip = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = self.ipconv.ipv6_hexstring_to_presentation(self.orig_hexip)
            self.dest_ip = self.ipconv.ipv6_hexstring_to_presentation(self.dest_hexip)

            self.orig_port = long(sio.lineparts[1].partition(self.__FieldSplitDelim)[2], 16)
            self.dest_port = long(sio.lineparts[2].partition(self.__FieldSplitDelim)[2], 16)

            if sio.lineparts[3] in state_list:
                self.state = state_list[sio.lineparts[3]]
            else:
                self.state = PDC.unknown_state

            self.field[PFC.F_ORIG_HEXIP] = self.orig_hexip
            self.field[PFC.F_DEST_HEXIP] = self.dest_hexip
            self.field[PFC.F_ORIG_HEXPORT] = self.orig_hexport
            self.field[PFC.F_DEST_HEXPORT] = self.dest_hexport
            self.field[PFC.F_ORIG_IP] = self.orig_ip
            self.field[PFC.F_DEST_IP] = self.dest_ip
            self.field[PFC.F_ORIG_PORT] = self.orig_port
            self.field[PFC.F_DEST_PORT] = self.dest_port
            self.field[PFC.F_HEXSTATE] = str(sio.lineparts[3])
            self.field[PFC.F_STATE] = self.state
            self.field[PFC.F_TXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_RXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_TIMER] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_TIMER_WHEN] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_RETRANS] = long(sio.lineparts[6], 16)
            self.field[PFC.F_UID] = long(sio.lineparts[7])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[8])
            self.field[PFC.F_INODE] = long(sio.lineparts[9])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[10])
            self.field[PFC.F_POINTER] = long(sio.lineparts[11], 16)

            if sio.linewords == 17:
                self.field[PFC.F_RETRY_TIMEOUT] = long(sio.lineparts[12])
                self.field[PFC.F_ACK_TIMEOUT] = long(sio.lineparts[13])
                self.field[PFC.F_QUICK_OR_PPONG] = long(sio.lineparts[14])
                self.field[PFC.F_CONGEST_WINDOW] = long(sio.lineparts[15])
                self.field[PFC.F_SSTART_THRESH] = long(sio.lineparts[16])

        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)
RegisterProcFileHandler("/proc/net/tcp6", ProcNetTCP6)
RegisterPartialProcFileHandler("tcp6", ProcNetTCP6)



# ---
class ProcNetTCP(PBR.fixed_delim_format_recs):
    """Abstraction layer to pull records from /proc/net/tcp"""
# DCHK: 11/17/12
# source: net/ipv4/tcp_ipv4.c
# Note: The sample code include is one of three spots where this data is written out.
#       The choice of which code to call depends on the status of the socket and only
#       this version has the "%lu %lu %u %u %d" fields at the end, meaning 6 of the 
#       last seven fields.  There are also no column headers for those extra fields
#       so I'm guessing their meaning from the code.
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
        self.__FieldSplitDelim = ":"

        self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):
# -- Sample lines for reference...
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
#   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 8633 1 0000000000000000 100 0 0 10 -1                     
#   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24865 1 0000000000000000 100 0 0 10 -1                    
#   2: 00000000:4E70 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 69682 1 0000000000000000 100 0 0 10 -1                    
#   3: 0E01A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 15488 1 0000000000000000 100 0 0 10 -1                    

        if sio.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[PFC.F_ORIG_HEXIP] = "00000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "0.0.0.0"
            self.field[PFC.F_DEST_IP] = "0.0.0.0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.unknown_state
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
            self.orig_hexip = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.orig_hexip, 16)))))
            self.dest_ip = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.dest_hexip, 16)))))

            self.orig_port = long(sio.lineparts[1].partition(self.__FieldSplitDelim)[2], 16)
            self.dest_port = long(sio.lineparts[2].partition(self.__FieldSplitDelim)[2], 16)

            if sio.lineparts[3] in state_list:
                self.state = state_list[sio.lineparts[3]]
            else:
                self.state = PDC.unknown_state

            self.field[PFC.F_ORIG_HEXIP] = self.orig_hexip
            self.field[PFC.F_DEST_HEXIP] = self.dest_hexip
            self.field[PFC.F_ORIG_HEXPORT] = self.orig_hexport
            self.field[PFC.F_DEST_HEXPORT] = self.dest_hexport
            self.field[PFC.F_ORIG_IP] = self.orig_ip
            self.field[PFC.F_DEST_IP] = self.dest_ip
            self.field[PFC.F_ORIG_PORT] = self.orig_port
            self.field[PFC.F_DEST_PORT] = self.dest_port
            self.field[PFC.F_HEXSTATE] = str(sio.lineparts[3])
            self.field[PFC.F_STATE] = self.state
            self.field[PFC.F_TXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_RXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_TIMER] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_TIMER_WHEN] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_RETRANS] = long(sio.lineparts[6], 16)
            self.field[PFC.F_UID] = long(sio.lineparts[7])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[8])
            self.field[PFC.F_INODE] = long(sio.lineparts[9])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[10])
            self.field[PFC.F_POINTER] = long(sio.lineparts[11], 16)

            if sio.linewords == 17:
                self.field[PFC.F_RETRY_TIMEOUT] = long(sio.lineparts[12])
                self.field[PFC.F_ACK_TIMEOUT] = long(sio.lineparts[13])
                self.field[PFC.F_QUICK_OR_PPONG] = long(sio.lineparts[14])
                self.field[PFC.F_CONGEST_WINDOW] = long(sio.lineparts[15])
                self.field[PFC.F_SSTART_THRESH] = long(sio.lineparts[16])

        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)
#
RegisterProcFileHandler("/proc/net/tcp", ProcNetTCP)
RegisterPartialProcFileHandler("tcp", ProcNetTCP)



# ---
class ProcNetUDP6(PBR.fixed_delim_format_recs):
    """Abstraction layer to pull records from /proc/net/udp6"""
# DCHK: 11/16/12 
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
        self.__FieldSplitDelim = ":"
        self.ipconv = IPAddressConv

        self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):
# -- Sample lines for reference...
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
# 1224: 000080FE00000000FF0060CA86E401FE:BBF1 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   500        0 4893942 2 0000000000000000 0
# 2316: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1994 2 0000000000000000 0
# 2777: 00000000000000000000000000000000:0202 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1899 2 0000000000000000 0

        if sio.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[PFC.F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "::0"
            self.field[PFC.F_DEST_IP] = "::0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.unknown_state
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
            self.orig_hexip = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = self.ipconv.ipv6_hexstring_to_presentation(self.orig_hexip)
            self.dest_ip = self.ipconv.ipv6_hexstring_to_presentation(self.dest_hexip)

            self.orig_port = long(sio.lineparts[1].partition(self.__FieldSplitDelim)[2], 16)
            self.dest_port = long(sio.lineparts[2].partition(self.__FieldSplitDelim)[2], 16)

            if sio.lineparts[3] in state_list:
                self.state = state_list[sio.lineparts[3]]
            else:
                self.state = PDC.unknown_state

            self.field[PFC.F_ORIG_HEXIP] = self.orig_hexip
            self.field[PFC.F_DEST_HEXIP] = self.dest_hexip
            self.field[PFC.F_ORIG_HEXPORT] = self.orig_hexport
            self.field[PFC.F_DEST_HEXPORT] = self.dest_hexport
            self.field[PFC.F_ORIG_IP] = self.orig_ip
            self.field[PFC.F_DEST_IP] = self.dest_ip
            self.field[PFC.F_ORIG_PORT] = self.orig_port
            self.field[PFC.F_DEST_PORT] = self.dest_port
            self.field[PFC.F_HEXSTATE] = str(sio.lineparts[3])
            self.field[PFC.F_STATE] = self.state
            self.field[PFC.F_TXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_RXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_TIMER] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_TIMER_WHEN] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_RETRANS] = long(sio.lineparts[6], 16)
            self.field[PFC.F_UID] = long(sio.lineparts[7])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[8])
            self.field[PFC.F_INODE] = long(sio.lineparts[9])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[10])
            self.field[PFC.F_POINTER] = long(sio.lineparts[11], 16)
            self.field[PFC.F_DROPS] = long(sio.lineparts[12])

        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)
#
RegisterProcFileHandler("/proc/net/udp6", ProcNetUDP6)
RegisterPartialProcFileHandler("udp6", ProcNetUDP6)



# ---
class ProcNetUDP(PBR.fixed_delim_format_recs):
    """Abstraction layer to pull records from /proc/net/udp"""
# DCHK: 11/17/12
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
        self.__FieldSplitDelim = ":"

        self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
        self.orig_port = self.dest_port = 0
        self.orig_hexport = ""
        self.dest_hexport = ""
        return

    def extra_next(self, sio):
# -- Sample lines for reference...
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops        
# %5d : %08X:%04X     %08X:%04X    %02X %08X:%08X        %02X:%08lX  %08X       %5d      %8d %lu  %d %pK              %d
# 2316: 0E01A8C0:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 15487 2 0000000000000000 0
# 2316: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1999 2 0000000000000000 0
# 2777: 00000000:0202 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1898 2 0000000000000000 0

        if sio.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[PFC.F_ORIG_HEXIP] = "00000000"
            self.field[PFC.F_DEST_HEXIP] = "00000000"
            self.field[PFC.F_ORIG_HEXPORT] = "0000"
            self.field[PFC.F_DEST_HEXPORT] = "0000"
            self.field[PFC.F_ORIG_IP] = "0.0.0.0"
            self.field[PFC.F_DEST_IP] = "0.0.0.0"
            self.field[PFC.F_ORIG_PORT] = 0
            self.field[PFC.F_DEST_PORT] = 0
            self.field[PFC.F_HEXSTATE] = "00"
            self.field[PFC.F_STATE] = PDC.unknown_state
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
            self.orig_hexip = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(sio.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(sio.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.orig_hexip, 16)))))
            self.dest_ip = socket.inet_ntop(socket.AF_INET, binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.dest_hexip, 16)))))

            self.orig_port = long(sio.lineparts[1].partition(self.__FieldSplitDelim)[2], 16)
            self.dest_port = long(sio.lineparts[2].partition(self.__FieldSplitDelim)[2], 16)

            if sio.lineparts[3] in state_list:
                self.state = state_list[sio.lineparts[3]]
            else:
                self.state = PDC.unknown_state

            self.field[PFC.F_ORIG_HEXIP] = self.orig_hexip
            self.field[PFC.F_DEST_HEXIP] = self.dest_hexip
            self.field[PFC.F_ORIG_HEXPORT] = self.orig_hexport
            self.field[PFC.F_DEST_HEXPORT] = self.dest_hexport
            self.field[PFC.F_ORIG_IP] = self.orig_ip
            self.field[PFC.F_DEST_IP] = self.dest_ip
            self.field[PFC.F_ORIG_PORT] = self.orig_port
            self.field[PFC.F_DEST_PORT] = self.dest_port
            self.field[PFC.F_HEXSTATE] = str(sio.lineparts[3])
            self.field[PFC.F_STATE] = self.state
            self.field[PFC.F_TXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_RXQUEUE] = long(sio.lineparts[4].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_TIMER] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[0], 16)
            self.field[PFC.F_TIMER_WHEN] = long(sio.lineparts[5].partition(self.__FieldSplitDelim)[2], 16)
            self.field[PFC.F_RETRANS] = long(sio.lineparts[6], 16)
            self.field[PFC.F_UID] = long(sio.lineparts[7])
            self.field[PFC.F_TIMEOUT] = long(sio.lineparts[8])
            self.field[PFC.F_INODE] = long(sio.lineparts[9])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[10])
            self.field[PFC.F_POINTER] = long(sio.lineparts[11], 16)
            self.field[PFC.F_DROPS] = long(sio.lineparts[12])


        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)
#
RegisterProcFileHandler("/proc/net/udp", ProcNetUDP)
RegisterPartialProcFileHandler("udp", ProcNetUDP)



# ---
class ProcNetUNIX(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/unix"""
# DCHK: 11/16/12
# source: net/unix/af_unix.c
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


    def extra_init(self, *opts):
        self.minfields = 7
        self.skipped = "Num"

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
# Num       RefCount Protocol Flags    Type St Inode Path
# 0000000000000000: 00000002 00000000 00010000 0001 01 15807 @/tmp/dbus-HTivHd8Iyv
# 0000000000000000: 00000002 00000000 00010000 0001 01 14531 /tmp/.X11-unix/X0
# 0000000000000000: 00000002 00000000 00010000 0001 01 16649 /tmp/keyring-OUNO20/control

        if sio.buff == "":
            self.protocol = 0
            self.refcount = 0
            self.flags = 0
            self.type = 0
            self.state = 0
            self.inode = 0
            self.path = ""

            self.field = dict()

            self.field[PFC.F_NUM] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_PROTOCOL] = 0
            self.field[PFC.F_FLAGS] = "00000000"
            self.field[PFC.F_TYPE] = "0001"
            self.field[PFC.F_STATE] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_PATH] = ""

        else:
            __seq = sio.lineparts[0]
            if __seq[-1:] == ":":
                __seq = __seq[:-1]
            self.field[PFC.F_NUM] = long(__seq, 16)
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[1], 16)
            self.field[PFC.F_PROTOCOL] = long(sio.lineparts[2], 16)
            self.field[PFC.F_FLAGS] = long(sio.lineparts[3], 16)
            self.field[PFC.F_TYPE] = long(sio.lineparts[4], 16)
            self.field[PFC.F_STATE] = long(sio.lineparts[5], 16)
            self.field[PFC.F_INODE] = long(sio.lineparts[6])
            if sio.linewords > sio.MinWords:
                self.field[PFC.F_PATH] = sio.lineparts[7]
            else:
                self.field[PFC.F_PATH] = ""

            self.protocol = self.field[PFC.F_PROTOCOL]
            self.refcount = self.field[PFC.F_REFCOUNT]
            self.flags = self.field[PFC.F_FLAGS]
            self.type = self.field[PFC.F_TYPE]
            self.state = self.field[PFC.F_STATE]
            self.inode = self.field[PFC.F_INODE]
            self.path = self.field[PFC.F_PATH]

        return( self.refcount, self.protocol, self.flags, self.type, self.state, self.inode, self.path)
#
RegisterProcFileHandler("/proc/net/unix", ProcNetUNIX)
RegisterPartialProcFileHandler("unix", ProcNetUNIX)



# ---
class ProcNetSNMP6(PBR.single_name_value_list):
    """Pull records from /proc/net/snmp6"""
# DCHK: 11/25/12
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
RegisterProcFileHandler("/proc/net/snmp6", ProcNetSNMP6)
RegisterPartialProcFileHandler("snmp6", ProcNetSNMP6)



# ---
class ProcNetDEV_SNMP6(PBR.single_name_value_list):
    """Pull records from a device specific file in the /proc/net/dev_snmp6/ directory"""
# DCHK: 11/25/12
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
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = "{prefix}/{file}".format(prefix=ShowHandlerFilePath(self), file="lo")
        return

# -- Sample records.  All the files in the /proc/dev_snmp6/ directory use the same format.
# -- Each line is a key/value indicator.
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
RegisterProcFileHandler("/proc/net/dev_snmp6", ProcNetDEV_SNMP6)
RegisterPartialProcFileHandler("dev_snmp6", ProcNetDEV_SNMP6)



# ---
class ProcNetIGMP(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/igmp"""
# DCHK: 11/20/12
# source: net/ipv4/igmp.c
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

    def extra_init(self, *opts):
        self.__MinWords_first = 5
        self.__MinWords_second = 4
        self.minfields = self.__MinWords_first
        self.skipped = "Idx"
        self.__FieldSplitDelim = ":"

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

            self.index = 0
            self.device = PDC.ANY_DEVICE
            self.count = 0
            self.querier = ""
            self.group = 0
            self.users = 0
            self.timer = 0
        
            self.field = dict()

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
            self.field[PFC.F_INDEX] = long(sio.lineparts[0])
            self.field[PFC.F_DEVICE] = str(sio.lineparts[1])
            self.field[PFC.F_COUNT] = long(sio.lineparts[3])
            self.field[PFC.F_QUERIER] = str(sio.lineparts[4])

# ... need to read the next line for the rest.
            sio.MinWords = self.__MinWords_second
            sio.read_line()
            sio.MinWords = self.__MinWords_first

            if sio.buff == "":

                self.index = 0
                self.device = PDC.ANY_DEVICE
                self.count = 0
                self.querier = ""
                self.group = 0
                self.users = 0
                self.timer = 0

                self.field = dict()

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
                self.field[PFC.F_GROUP] = long(sio.lineparts[0], 16)
                self.field[PFC.F_USERS] = long(sio.lineparts[1])
                __split = sio.lineparts[2].partition(self.__FieldSplitDelim)
                self.field[PFC.F_TIMER] = long(__split[0])
                self.field[PFC.F_ZERO1] = long(__split[2], 16)
                self.field[PFC.F_REPORTER] = long(sio.lineparts[3])

                self.index = self.field[PFC.F_INDEX]
                self.device = self.field[PFC.F_DEVICE]
                self.count = self.field[PFC.F_COUNT]
                self.querier = self.field[PFC.F_QUERIER]
                self.group = self.field[PFC.F_GROUP]
                self.users = self.field[PFC.F_USERS]
                self.timer = self.field[PFC.F_TIMER]

        return( self.index, self.device, self.count, self.querier, self.group, self.users, self.timer)
#
RegisterProcFileHandler("/proc/net/igmp", ProcNetIGMP)
RegisterPartialProcFileHandler("igmp", ProcNetIGMP)



# ---
class ProcNetSNMP(PBR.twoline_logical_records):
    """Abstraction layer to pull records from /proc/net/snmp"""
# DCHK: 4/8/13
#
# source: net/ipv4/proc.c
#
#... from icmpmsg_put()
# for (i = 0; i < ICMPMSG_MIB_MAX; i++) {
#     val = snmp_fold_field((void __percpu **) net->mib.icmpmsg_statistics, i);
#     if (val) {
#         type[count] = i;
#         vals[count++] = val;
#     }
#     if (count == PERLINE) {
#         icmpmsg_put_line(seq, vals, type, count);
#         count = 0;
#     }
# }
# icmpmsg_put_line(seq, vals, type, count);
#
#
#
#... from icmp_put()
# seq_puts(seq, "\nIcmp: InMsgs InErrors");
# for (i=0; icmpmibmap[i].name != NULL; i++)
#     seq_printf(seq, " In%s", icmpmibmap[i].name);
# seq_printf(seq, " OutMsgs OutErrors");
# for (i=0; icmpmibmap[i].name != NULL; i++)
#     seq_printf(seq, " Out%s", icmpmibmap[i].name);
# seq_printf(seq, "\nIcmp: %lu %lu",
#     snmp_fold_field((void __percpu **) net->mib.icmp_statistics, ICMP_MIB_INMSGS),
#     snmp_fold_field((void __percpu **) net->mib.icmp_statistics, ICMP_MIB_INERRORS));
# for (i=0; icmpmibmap[i].name != NULL; i++)
#     seq_printf(seq, " %lu",
#         snmp_fold_field((void __percpu **) net->mib.icmpmsg_statistics,
#             icmpmibmap[i].index));
# seq_printf(seq, " %lu %lu",
#     snmp_fold_field((void __percpu **) net->mib.icmp_statistics, ICMP_MIB_OUTMSGS),
#     snmp_fold_field((void __percpu **) net->mib.icmp_statistics, ICMP_MIB_OUTERRORS));
# for (i=0; icmpmibmap[i].name != NULL; i++)
#     seq_printf(seq, " %lu",
#         snmp_fold_field((void __percpu **) net->mib.icmpmsg_statistics,
#             icmpmibmap[i].index | 0x100));
#
#
#
#...from snmp_seq_show()
# seq_puts(seq, "Ip: Forwarding DefaultTTL");
#
# for (i = 0; snmp4_ipstats_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_ipstats_list[i].name);
#
# seq_printf(seq, "\nIp: %d %d",
#        IPV4_DEVCONF_ALL(net, FORWARDING) ? 1 : 2,
#        sysctl_ip_default_ttl);
#
# BUILD_BUG_ON(offsetof(struct ipstats_mib, mibs) != 0);
# for (i = 0; snmp4_ipstats_list[i].name != NULL; i++)
#     seq_printf(seq, " %llu",
#            snmp_fold_field64((void __percpu **)net->mib.ip_statistics,
#                      snmp4_ipstats_list[i].entry,
#                      offsetof(struct ipstats_mib, syncp)));
#
# icmp_put(seq);    /* RFC 2011 compatibility */
# icmpmsg_put(seq);
#
# seq_puts(seq, "\nTcp:");
# for (i = 0; snmp4_tcp_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_tcp_list[i].name);
#
# seq_puts(seq, "\nTcp:");
# for (i = 0; snmp4_tcp_list[i].name != NULL; i++) {
#     /* MaxConn field is signed, RFC 2012 */
#     if (snmp4_tcp_list[i].entry == TCP_MIB_MAXCONN)
#         seq_printf(seq, " %ld",
#                snmp_fold_field((void __percpu **)net->mib.tcp_statistics,
#                        snmp4_tcp_list[i].entry));
#     else
#         seq_printf(seq, " %lu",
#                snmp_fold_field((void __percpu **)net->mib.tcp_statistics,
#                        snmp4_tcp_list[i].entry));
# }
#
# seq_puts(seq, "\nUdp:");
# for (i = 0; snmp4_udp_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_udp_list[i].name);
#
# seq_puts(seq, "\nUdp:");
# for (i = 0; snmp4_udp_list[i].name != NULL; i++)
#     seq_printf(seq, " %lu",
#            snmp_fold_field((void __percpu **)net->mib.udp_statistics,
#                    snmp4_udp_list[i].entry));
#
# /* the UDP and UDP-Lite MIBs are the same */
# seq_puts(seq, "\nUdpLite:");
# for (i = 0; snmp4_udp_list[i].name != NULL; i++)
#     seq_printf(seq, " %s", snmp4_udp_list[i].name);
#
# seq_puts(seq, "\nUdpLite:");
# for (i = 0; snmp4_udp_list[i].name != NULL; i++)
#     seq_printf(seq, " %lu",
#            snmp_fold_field((void __percpu **)net->mib.udplite_statistics,
#                    snmp4_udp_list[i].entry));
#
# seq_putc(seq, '\n');
#

# -- Sample lines for reference...
#       
# Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
# Tcp: 1 200 120000 -1 160318 5208 5105 523 17 21554159 12995200 11248 0 16685
# Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
# Udp: 890715 230 0 667254 0 0
#
#
RegisterProcFileHandler("/proc/net/snmp", ProcNetSNMP)
RegisterPartialProcFileHandler("snmp", ProcNetSNMP)



# ---
class ProcNetNETSTAT(PBR.twoline_logical_records):
    """Abstraction layer to pull records from /proc/net/netstat"""
# DCHK: 4/8/13
#
# source: net/ipv4/proc.c
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
#
RegisterProcFileHandler("/proc/net/netstat", ProcNetNETSTAT)
RegisterPartialProcFileHandler("netstat", ProcNetNETSTAT)



# ---
class ProcNetSOCKSTAT(PBR.labelled_pair_list_records):
    """Abstraction layer to pull records from /proc/net/sockstat"""
# DCHK: 2/4/13
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
        self.sock_type_list = ([ PFC.F_SOCK_TCP, PFC.F_SOCK_UDP, PFC.F_SOCK_UDPLITE, PFC.F_SOCK_RAW, PFC.F_SOCK_FRAG, PFC.F_SOCK_SOCKETS ])
        return

# -- Sample lines for reference...
# TCP: inuse 26 orphan 0 tw 1 alloc 30 mem 2
# UDP: inuse 3 mem 3
# UDPLITE: inuse 0
# RAW: inuse 0
# FRAG: inuse 0 memory 0
#
#
RegisterProcFileHandler("/proc/net/sockstat", ProcNetSOCKSTAT)
RegisterPartialProcFileHandler("sockstat", ProcNetSOCKSTAT)



# ---
class ProcNetSOCKSTAT6(PBR.labelled_pair_list_records):
    """Abstraction layer to pull records from /proc/net/sockstat6"""
# DCHK: 2/4/13
#
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
        self.sock_type_list = ([ PFC.F_SOCK_TCP6, PFC.F_SOCK_UDP6, PFC.F_SOCK_UDPLITE6, PFC.F_SOCK_RAW6, PFC.F_SOCK_FRAG6 ])
        return

# -- Sample lines for reference...
# TCP6: inuse 4
# UDP6: inuse 2
# UDPLITE6: inuse 0
# RAW6: inuse 0
# FRAG6: inuse 0 memory 0
#
#
RegisterProcFileHandler("/proc/net/sockstat6", ProcNetSOCKSTAT6)
RegisterPartialProcFileHandler("sockstat6", ProcNetSOCKSTAT6)



# ---
class ProcNetIP6_TABLES_MATCHES(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip6_tables_matches"""
# DCHK: 11/20/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# hl
#
#
RegisterProcFileHandler("/proc/net/ip6_tables_matches", ProcNetIP6_TABLES_MATCHES)
RegisterPartialProcFileHandler("ip6_tables_matches", ProcNetIP6_TABLES_MATCHES)



# ---
class ProcNetIP6_TABLES_NAMES(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip6_tables_names"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter
#
#
RegisterProcFileHandler("/proc/net/ip6_tables_names", ProcNetIP6_TABLES_NAMES)
RegisterPartialProcFileHandler("ip6_tables_names", ProcNetIP6_TABLES_NAMES)



# ---
class ProcNetIP6_TABLES_TARGETS(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip6_tables_targets"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# LOG
# ERROR
#
#
RegisterProcFileHandler("/proc/net/ip6_tables_targets", ProcNetIP6_TABLES_TARGETS)
RegisterPartialProcFileHandler("ip6_tables_targets", ProcNetIP6_TABLES_TARGETS)



# ---
class ProcNetIP_TABLES_MATCHES(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip_tables_matches"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# ttl
#
#
RegisterProcFileHandler("/proc/net/ip_tables_matches", ProcNetIP_TABLES_MATCHES)
RegisterPartialProcFileHandler("ip_tables_matches", ProcNetIP_TABLES_MATCHES)



# ---
class ProcNetIP_TABLES_NAMES(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip_tables_names"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter
#
#
RegisterProcFileHandler("/proc/net/ip_tables_names", ProcNetIP_TABLES_NAMES)
RegisterPartialProcFileHandler("ip_tables_names", ProcNetIP_TABLES_NAMES)



# ---
class ProcNetIP_TABLES_TARGETS(PBR.list_of_terms_format):
    """Pull records from /proc/net/ip_tables_targets"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# REJECT
# LOG
# ERROR
#
#
RegisterProcFileHandler("/proc/net/ip_tables_targets", ProcNetIP_TABLES_TARGETS)
RegisterPartialProcFileHandler("ip_tables_targets", ProcNetIP_TABLES_TARGETS)



# ---
class ProcNetNetfilterNF_LOG(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/netfilter/nf_log"""
# DCHK: 11/19/12
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

            self.index = 0
            self.name = ""
            self.log_list = ""

            self.field = dict()

            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_NAME] = ""
            self.field[PFC.F_LOGGER_LIST] = ""

        else:
            self.field[PFC.F_INDEX] = long(sio.lineparts[0])
            self.field[PFC.F_NAME] = str(sio.lineparts[1])
            __clean = str(sio.lineparts[2])
            if __clean[:1] == "(" and __clean[-1:] == ")":
                __clean = __clean[2:-1]
            self.field[PFC.F_LOGGER_LIST] = __clean

            self.index = self.field[PFC.F_INDEX]
            self.name = self.field[PFC.F_NAME]
            self.log_list = self.field[PFC.F_LOGGER_LIST]

        return( self.index, self.name, self.log_list)
#
RegisterProcFileHandler("/proc/net/netfilter/nf_log", ProcNetNetfilterNF_LOG)
RegisterPartialProcFileHandler("nf_log", ProcNetNetfilterNF_LOG)



# ---
class ProcNetNetfilterNF_QUEUE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/net/netfilter/nf_queue"""
# DCHK: 11/19/12
# source: net/netfilter/nf_queue.c
#  if (!qh)
#          ret = seq_printf(s, "%2lld NONE\n", *pos);
#  else
#          ret = seq_printf(s, "%2lld %s\n", *pos, qh->name);

    def extra_init(self, *opts):
        self.minfields = 2
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

            self.index = 0
            self.name = ""
        
            self.field = dict()

            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_NAME] = ""

        else:
            self.field[PFC.F_INDEX] = long(sio.lineparts[0])
            self.field[PFC.F_NAME] = str(sio.lineparts[1])

            self.index = self.field[PFC.F_INDEX]
            self.name = self.field[PFC.F_NAME]

        return( self.index, self.name)
#
RegisterProcFileHandler("/proc/net/netfilter/nf_queue", ProcNetNetfilterNF_QUEUE)
RegisterPartialProcFileHandler("nf_queue", ProcNetNetfilterNF_QUEUE)



if __name__ == "__main__":

    print "Collection of handlers to parse file in the /proc/net directory"
