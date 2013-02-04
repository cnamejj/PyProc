#!/usr/bin/env python
"""A collection of classes the get information from the system

Describe what's in this module and put that info here...
"""

# ---
# (C) 2012-2013 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.


import time
import socket
from subprocess import Popen, PIPE
import binascii
import sys


unknown_state = "UNRECOGNIZED"

ANY_HW_ADDR = "00:00:00:00:00:00"
ANY_INTERFACE = "any"
ANY_IPV6_ADDR = "::"
ANY_IP_ADDR = "0.0.0.0"
ANY_IP_ADDR_HEX = "00000000"
ANY_IPV6_ADDR_HEX = "00000000000000000000000000000000"
ANY_MASK_HEX = "FFFFFFFF"
NULL_MASK_HEX = "00000000"
PRESENT_ANY_IPV6_ADDR = "::0"
PRESENT_ANY_IP_ADDR = "0.0.0.0"
ANY_DEVICE = "any"

state_list = dict()
state_list["01"] = "ESTABLISHED"
state_list["02"] = "SYN_SENT"
state_list["03"] = "SYN_RECV"
state_list["04"] = "FIN_WAIT1"
state_list["05"] = "FIN_WAIT2"
state_list["06"] = "TIME_WAIT"
state_list["07"] = "CLOSE"
state_list["08"] = "CLOSE_WAIT"
state_list["09"] = "LACK_ACK"
state_list["0A"] = "LISTEN"
state_list["0B"] = "CLOSING"


# -- fields used for tcp, tcp6, udp and udp6 
F_ORIG_HEXIP = "orig_hexip"
F_DEST_HEXIP = "dest_hexip"
F_ORIG_HEXPORT = "orig_hexport"
F_DEST_HEXPORT = "dest_hexport"
F_ORIG_IP = "orig_ip"
F_DEST_IP = "dest_ip"
F_ORIG_PORT = "orig_port"
F_DEST_PORT = "dest_port"
F_HEXSTATE = "hexstate"
F_STATE = "state"
F_TXQUEUE = "tx_queue"
F_RXQUEUE = "rx_queue"
F_TIMER = "timer"
F_TIMER_WHEN = "tm_when"
F_RETRANS = "retrnsmt"
F_UID = "uid"
F_TIMEOUT = "timeout"
F_INODE = "inode"
F_REFCOUNT = "ref_count"
F_POINTER = "pointer"
F_DROPS = "drops"
F_RETRY_TIMEOUT = "retry_timeout"
F_ACK_TIMEOUT = "ack_timeout"
F_QUICK_OR_PPONG = "quick_pingpong"
F_CONGEST_WINDOW = "congest_window"
F_SSTART_THRESH = "slow_start_thresh"

# -- fields used for "arp" data
F_IP_ADDRESS = "ip_address"
F_HW_TYPE = "hw_type"
F_FLAGS = "flags"
F_HW_ADDRESS = "hw_address"
F_MASK = "mask"
F_DEVICE = "device"

# -- fields added by "dev" data
F_RX_BYTES = "rx_bytes"
F_RX_PACKETS = "rx_packets"
F_RX_ERRORS = "rx_errors"
F_RX_DROP = "rx_drop"
F_RX_FIFO = "rx_fifo"
F_RX_FRAME = "rx_frame"
F_RX_COMPRESSED = "rx_compressed"
F_RX_MULTICAST = "rx_multicast"
F_TX_BYTES = "tx_bytes"
F_TX_PACKETS = "tx_packets"
F_TX_ERRORS = "tx_errors"
F_TX_DROP = "tx_drop"
F_TX_FIFO = "tx_fifo"
F_TX_COLLISION = "tx_colls"
F_TX_CARRIER = "tx_carrier"
F_TX_COMPRESSED = "tx_compressed"

# -- fields added by "route" data
F_INTERFACE = "iface"
F_GATEWAY = "gateway"
F_USECOUNT = "use_count"
F_METRIC = "metric"
F_MTU = "mtu"
F_WINDOW = "window"
F_IRTT = "irtt"
F_NETMASK = "netmask"
F_GATE_HEXIP = "gateway_hex"
F_MASK_HEXIP = "netmask_hex"

# -- fields added by "rt_cache" data
F_SRCE_HEXIP = "source_hex"
F_SOURCE = "source_ip"
F_TOS = "tos"
F_HHREF = "hhref"
F_HHUPTOD = "hhuptod"
F_SPEC_HEXIP = "spec_dst_hexip"
F_SPEC_DST = "spec_dst"

# -- fields added to support "stat/arp_cache" data
F_ARP_ENTRIES = "arp_entries"
F_ALLOC = "alloc_count"
F_DESTROY = "destroy_count"
F_HASH_GROW = "hash_grow_count"
F_LOOKUP = "lookup_count"
F_HIT = "hit_count"
F_RES_FAIL = "res_fail_count"
F_RCV_MCAST_PROBE = "rx_mcast_count"
F_RCV_UCAST_PROBE = "rx_ucast_count"
F_GC_PERIODIC = "gc_peri_count"
F_GC_FORCED = "gc_forc_count"
F_UNRES_DISCARD = "unres_dis_count"

# -- fields added to support "stat/ip_conntrack" data
F_ENTRIES = "entries"
F_SEARCHED = "searched"
F_FOUND = "found"
F_NEW = "new"
F_INVALID = "invalid"
F_IGNORE = "ignore"
F_DELETE = "delete"
F_DELETE_LIST = "delete_list"
F_INSERT = "insert"
F_INSERT_FAILED = "insert_failed"
F_DROP = "drop"
F_DROP_EARLY = "early_drop"
F_ICMP_ERROR = "icmp_err"
F_EXP_NEW = "expect_new"
F_EXP_CREATE = "expect_create"
F_EXP_DELETE = "expect_delete"
F_SEARCH_RESTART = "search_restart"

# -- fields added to support "stat/rt_cache" data
F_IN_HIT = "in_hit"
F_IN_SLOW_TOT = "in_slow_tot"
F_IN_SLOW_MC = "in_slow_mc"
F_IN_NO_ROUTE = "in_no_route"
F_IN_BRD = "in_brd"
F_IN_MARTIAN_DST = "in_martian_dst"
F_IN_MARTIAN_SRC = "in_martian_src"
F_OUT_HIT = "out_hit"
F_OUT_SLOW_TOT = "out_slow_tot"
F_OUT_SLOW_MC = "out_slow_mc"
F_GC_TOTAL = "gc_total"
F_GC_IGNORED = "gc_ignored"
F_GC_GOAL_MISS = "gc_goal_miss"
F_GC_DST_OVERFLOW = "gc_dst_overflow"
F_IN_HL_SEARCH = "in_hlist_search"
F_OUT_HL_SEARCH = "out_hlist_search"

# -- fields added to support "unix" data
F_NUM = "num"
F_PROTOCOL = "protocol"
F_TYPE = "type"
F_PATH = "path"

# -- fields added to support "if_inet6" data
F_IPV6_HEX = "ipv6_hex"
F_INT_INDEX_HEX = "int_index_hex"
F_PREFIX_LEN_HEX = "prefix_len_hex"
F_FLAGS_HEX = "flags_hex"
F_SCOPE_HEX = "scope_hex"
F_INT_INDEX = "int_index"
F_PREFIX_LEN = "prefix_len"
F_SCOPE = "scope"
F_IPV6 = "ipv6"

# -- fields added to support "dev_mcast" data
F_GLOBAL_USE = "global_use"
F_DEV_ADDR = "device_address"

# -- fields added to support "igmp6" data
F_MCAST_ADDR = "mcast_addr"
F_MCAST_USERS = "mcast_users"
F_MCAST_FLAGS = "mcast_flags"
F_TIMER_EXPIRE = "timer_expiration"
F_MCAST_ADDR_HEX = "mcast_addr_hex"

# -- fields added to support "ipv6_route"
F_DEST_PREFIX_LEN_HEX = "dest_preflen_hex"
F_SRCE_PREFIX_LEN_HEX = "src_preflen_hex"
F_PRIMARY_KEY = "primary_key"
F_RT6I_METRIC = "rt6i_metric"
F_DEST_REFCOUNT = "dest_ref_count"
F_DEST_USE = "dest_use"
F_RT6I_FLAGS = "rt6i_flags"
F_DEST_PREFIX_LEN = "dest_preflen"
F_SRCE_PREFIX_LEN = "src_preflen"

# -- fields added to support "psched"
F_NSEC_PER_USEC = "nsec_per_usec"
F_PSCHED_TICKS = "psched_ticks_per_nsec"
F_UNKNOWN_FIELD = "unknown_field"
F_NSEC_PER_HRTIME = "nsec_per_hrtimer_unit"

# -- fields added to support "rt6_stats" data
F_FIB_NODES = "fib_nodes"
F_FIB_ROUTE_NODES = "fib_route_nodes"
F_FIB_ROUTE_ALLOC = "fib_route_alloc"
F_FIB_ROUTE_ENTRIES = "fib_route_entries"
F_FIB_ROUTE_CACHE = "fib_route_cache"
F_FIB_DEST_OPS = "dest_ops"
F_FIB_DISC_ROUTES = "fib_discarded_routes"

# -- fields added to support "softnet_stat"
F_PROCESSED = "processed"
F_DROPPED = "dropped"
F_TIME_SQUEEZE = "time_squeeze"
F_ZERO1 = "zero1"
F_ZERO2 = "zero2"
F_ZERO3 = "zero3"
F_ZERO4 = "zero4"
F_ZERO5 = "zero5"
F_CPU_COLL = "cpu_collision"
F_RECEIVED_RPS = "received_rps"

# -- fields added to support the "protocols" data
F_SIZE = "size"
F_SOCKETS = "sockets"
F_MEMORY = "memory"
F_PRESURE = "pressure"
F_MAX_HEADER = "max_header"
F_SLAB = "slab"
F_MODULE = "module"
F_CLOSE = "close"
F_CONNECT = "connect"
F_DISCONNECT = "disconnect"
F_ACCEPT = "accept"
F_IOCTL = "ioctl"
F_INIT = "init"
F_SHUTDOWN = "shutdown"
F_SETSOCKOPT = "setsockopt"
F_GETSOCKOPT = "getsockopt"
F_SENDMSG = "sendmsg"
F_RECVMSG = "recvmsg"
F_SENDPAGE = "sendpage"
F_BIND = "bind"
F_BACKLOG_RCV = "backlog_rcv"
F_HASH = "hash"
F_UNHASH = "unhash"
F_GET_PORT = "get_port"
F_ENTER_PRESSURE = "enter_memory_pressure"

# -- fields added to support the "packet" data
F_SOCKET_POINTER = "socket_pointer"
F_RUNNING = "running"
F_RMEM_ALLOC = "rmem_alloc"
F_UID = "uid"

# -- fields added to support the "connector" data
F_NAME = "name"
F_ID_IDX = "id_idx"
F_ID_VAL = "id_val"

# -- fields added to support the "netlink" data
F_PID = "pid"
F_GROUPS = "groups"
F_WMEM_ALLOC = "wmem_alloc"
F_DUMP = "dump"
F_LOCKS = "locks"
F_DROPS = "drops"

# -- fields added to support the "netfilter/nf_log" data
F_INDEX = "index"
F_LOGGER_LIST = "logger_list"

# -- fields added to support "igmp" data
F_COUNT = "count"
F_QUERIER = "querier"
F_GROUP = "group"
F_USERS = "users"
F_REPORTER = "reporter"

# -- fields added to support "ip_conntrack" data
F_PROTOCOL_NUM = "protocol_number"
F_OR_SRC_IP = "original_source_ip"
F_OR_DST_IP = "original_destination_ip"
F_OR_SRC_PORT = "original_source_port"
F_OR_DST_PORT = "original_destination_port"
F_UNREPLIED = "unreplied"
F_OR_PACKETS = "original_packets"
F_OR_BYTES = "original_bytes"
F_RE_SRC_IP = "reply_source_ip"
F_RE_DST_IP = "reply_destination_ip"
F_RE_SRC_PORT = "reply_source_port"
F_RE_DST_PORT = "reply_destination_port"
F_RE_PACKETS = "reply_packets"
F_RE_BYTES = "reply_bytes"
F_ASSURED = "assured"
F_MARK = "mark"
F_SECCTX = "secctx"
F_USE = "use"

# -- fields added to support "nf_conntrack" data
F_L3_PROTOCOL = "l3_protocol"
F_L3_PROTOCOL_NUM = "l3_protocol_num"
F_ZONE = "zone"
F_DELTA_TIME = "delta_time"

# -- fields added to support "sockstat" data
F_SOCK_TCP = "TCP:"
F_SOCK_UDP = "UDP:"
F_SOCK_UDPLITE = "UDPLITE:"
F_SOCK_RAW = "RAW:"
F_SOCK_FRAG = "FRAG:"
F_SOCK_SOCKETS = "sockets:"

class ProcNetDEV_SNMP6:
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


    def __init__(self, *opts):
        if len(opts) > 0:
            if opts[0] == "":
                self.__infile = "/proc/net/dev_snmp6/lo"
            else:
                self.__infile = "/proc/net/dev_snmp6/" + opts[0]
        else:
            self.__infile = "/proc/net/dev_snmp6/lo"
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, self.__infile)

    def __iter__(self):
        return(self)

    def next(self):

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

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration
        else:
            for self.__keyval in self.__lines:
                self.__words = self.__keyval.split()
                if len(self.__words) == 2:
                    self.field[self.__words[0]] = self.__words[1]

        return(self.field)



class ProcNetSNMP6:
    """Pull records from /proc/net/snmp6"""
# DCHK: 11/25/12
# source: net/ipv6/proc.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/snmp6")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file a series of key/value entries, one per line.
# Ip6InReceives                   	1159
# Ip6InHdrErrors                  	0
# Ip6InTooBigErrors               	0
# Ip6InNoRoutes                   	0
# Ip6InAddrErrors                 	0
# Ip6InUnknownProtos              	0

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration
        else:
            for self.__keyval in self.__lines:
                self.__words = self.__keyval.split()
                if len(self.__words) == 2:
                    self.field[self.__words[0]] = self.__words[1]

        return(self.field)



class ProcNetNF_CONNTRACK:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/nf_conntrack", 14)

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

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records, there is no header line and the fields presented can very from record to record, only the
# -- first 3 are guaranteed to always the protocol name, protocol number, and timeout. The rest will always
# -- be in the same order, but a number of fields may or may not be there.
# ipv4     2 tcp      6 14 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55894 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55894 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 9 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55890 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55890 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 21 TIME_WAIT src=192.168.1.14 dst=192.168.1.1 sport=55900 dport=80 src=192.168.1.1 dst=192.168.1.14 sport=80 dport=55900 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431934 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=33934 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=33934 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431964 ESTABLISHED src=192.168.1.14 dst=173.201.192.71 sport=35348 dport=993 src=173.201.192.71 dst=192.168.1.14 sport=993 dport=35348 [ASSURED] mark=0 zone=0 use=2
# ipv4     2 tcp      6 431798 ESTABLISHED src=192.168.1.14 dst=72.167.218.187 sport=53880 dport=993 src=72.167.218.187 dst=192.168.1.14 sport=993 dport=53880 [ASSURED] mark=0 zone=0 use=2

        self.__sio.read_line(self)

        if self.buff == "":

            self.l3_protocol = ""
            self.protocol = ""
            self.timeout = 0
            self.state = unknown_state
            self.src_ip = ANY_IP_ADDR
            self.src_port = 0
            self.dst_ip = ANY_IP_ADDR
            self.dst_port = 0
           
            self.field = dict()

            self.field[F_L3_PROTOCOL] = ""
            self.field[F_L3_PROTOCOL_NUM] = 0
            self.field[F_PROTOCOL] = ""
            self.field[F_PROTOCOL_NUM] = 0
            self.field[F_TIMEOUT] = 0
            self.field[F_STATE] = unknown_state
            self.field[F_OR_SRC_IP] = ANY_IP_ADDR
            self.field[F_OR_DST_IP] = ANY_IP_ADDR
            self.field[F_OR_SRC_PORT] = 0
            self.field[F_OR_DST_PORT] = 0
            self.field[F_UNREPLIED] = ""
            self.field[F_OR_PACKETS] = 0
            self.field[F_OR_BYTES] = 0
            self.field[F_RE_SRC_IP] = ANY_IP_ADDR
            self.field[F_RE_DST_IP] = ANY_IP_ADDR
            self.field[F_RE_SRC_PORT] = 0
            self.field[F_RE_DST_PORT] = 0
            self.field[F_RE_PACKETS] = 0
            self.field[F_RE_BYTES] = 0
            self.field[F_ASSURED] = ""
            self.field[F_MARK] = 0
            self.field[F_SECCTX] = 0
            self.field[F_ZONE] = 0
            self.field[F_DELTA_TIME] = 0
            self.field[F_USE] = 0

        else:
            self.field[F_L3_PROTOCOL] = ""
            self.field[F_L3_PROTOCOL_NUM] = 0
            self.field[F_PROTOCOL] = ""
            self.field[F_PROTOCOL_NUM] = 0
            self.field[F_TIMEOUT] = 0
            self.field[F_STATE] = unknown_state
            self.field[F_OR_SRC_IP] = ANY_IP_ADDR
            self.field[F_OR_DST_IP] = ANY_IP_ADDR
            self.field[F_OR_SRC_PORT] = 0
            self.field[F_OR_DST_PORT] = 0
            self.field[F_UNREPLIED] = ""
            self.field[F_OR_PACKETS] = 0
            self.field[F_OR_BYTES] = 0
            self.field[F_RE_SRC_IP] = ANY_IP_ADDR
            self.field[F_RE_DST_IP] = ANY_IP_ADDR
            self.field[F_RE_SRC_PORT] = 0
            self.field[F_RE_DST_PORT] = 0
            self.field[F_RE_PACKETS] = 0
            self.field[F_RE_BYTES] = 0
            self.field[F_ASSURED] = ""
            self.field[F_MARK] = 0
            self.field[F_SECCTX] = 0
            self.field[F_ZONE] = 0
            self.field[F_DELTA_TIME] = 0
            self.field[F_USE] = 0

	    self.field[F_L3_PROTOCOL] = str(self.lineparts[0])
            self.field[F_L3_PROTOCOL_NUM] = long(self.lineparts[1])
	    self.field[F_PROTOCOL] = str(self.lineparts[2])
            self.field[F_PROTOCOL_NUM] = long(self.lineparts[3])
            self.field[F_TIMEOUT] = long(self.lineparts[4])

            self.__off = 5

            if self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__TUPLE_PREF)] != self.__TUPLE_PREF:
                self.field[F_STATE] = str(self.lineparts[self.__off])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_OR_SRC_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_DST_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_SRC_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_DST_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__UNREPLIED_PREF)] == self.__UNREPLIED_PREF:
                self.field[F_UNREPLIED] = str(self.lineparts[self.__off])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[F_OR_PACKETS] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[F_OR_BYTES] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_RE_SRC_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_DST_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_SRC_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_DST_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[F_RE_PACKETS] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[F_RE_BYTES] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__ASSURED_PREF)] == self.__ASSURED_PREF:
                self.field[F_ASSURED] = str(self.lineparts[self.__off])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__MARK_PREF)] == self.__MARK_PREF:
                self.field[F_MARK] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__SECCTX_PREF)] == self.__SECCTX_PREF:
                self.field[F_SECCTX] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__ZONE_PREF)] == self.__ZONE_PREF:
                self.field[F_ZONE] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__DELTA_TIME_PREF)] == self.__DELTA_TIME_PREF:
                self.field[F_DELTA_TIME] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_USE] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
           
            self.l3_protocol = self.field[F_L3_PROTOCOL]
            self.protocol = self.field[F_PROTOCOL]
            self.timeout = self.field[F_TIMEOUT]
            self.state = self.field[F_STATE]
            self.src_ip = self.field[F_OR_SRC_IP]
            self.src_port = self.field[F_OR_SRC_PORT]
            self.dst_ip = self.field[F_OR_DST_IP]
            self.dst_port = self.field[F_OR_DST_PORT]

        return( self.l3_protocol, self.protocol, self.timeout, self.state, self.src_ip, self.src_port, self.dst_ip, self.dst_port)




class ProcNetIP_CONNTRACK:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip_conntrack", 12)

        self.__TUPLE_PREF = "src="
        self.__UNREPLIED_PREF = "["
        self.__PACKETS_PREF = "packets="
        self.__BYTES_PREF = "bytes="
        self.__USE_PREF = "use="
        self.__ASSURED_PREF = "["
        self.__MARK_PREF = "mark="
        self.__SECCTX_PREF = "secctx="
        self.__Val_Delim = "="

    def __iter__(self):
        return(self)

    def next(self):

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

        self.__sio.read_line(self)

        if self.buff == "":

            self.protocol = ""
            self.timeout = 0
            self.state = unknown_state
            self.src_ip = ANY_IP_ADDR
            self.src_port = 0
            self.dst_ip = ANY_IP_ADDR
            self.dst_port = 0
           
            self.field = dict()

            self.field[F_PROTOCOL] = ""
            self.field[F_PROTOCOL_NUM] = 0
            self.field[F_TIMEOUT] = 0
            self.field[F_STATE] = unknown_state
            self.field[F_OR_SRC_IP] = ANY_IP_ADDR
            self.field[F_OR_DST_IP] = ANY_IP_ADDR
            self.field[F_OR_SRC_PORT] = 0
            self.field[F_OR_DST_PORT] = 0
            self.field[F_UNREPLIED] = ""
            self.field[F_OR_PACKETS] = 0
            self.field[F_OR_BYTES] = 0
            self.field[F_RE_SRC_IP] = ANY_IP_ADDR
            self.field[F_RE_DST_IP] = ANY_IP_ADDR
            self.field[F_RE_SRC_PORT] = 0
            self.field[F_RE_DST_PORT] = 0
            self.field[F_RE_PACKETS] = 0
            self.field[F_RE_BYTES] = 0
            self.field[F_ASSURED] = ""
            self.field[F_MARK] = 0
            self.field[F_SECCTX] = 0
            self.field[F_USE] = 0

        else:
            self.field[F_PROTOCOL] = ""
            self.field[F_PROTOCOL_NUM] = 0
            self.field[F_TIMEOUT] = 0
            self.field[F_STATE] = unknown_state
            self.field[F_OR_SRC_IP] = ANY_IP_ADDR
            self.field[F_OR_DST_IP] = ANY_IP_ADDR
            self.field[F_OR_SRC_PORT] = 0
            self.field[F_OR_DST_PORT] = 0
            self.field[F_UNREPLIED] = ""
            self.field[F_OR_PACKETS] = 0
            self.field[F_OR_BYTES] = 0
            self.field[F_RE_SRC_IP] = ANY_IP_ADDR
            self.field[F_RE_DST_IP] = ANY_IP_ADDR
            self.field[F_RE_SRC_PORT] = 0
            self.field[F_RE_DST_PORT] = 0
            self.field[F_RE_PACKETS] = 0
            self.field[F_RE_BYTES] = 0
            self.field[F_ASSURED] = ""
            self.field[F_MARK] = 0
            self.field[F_SECCTX] = 0
            self.field[F_USE] = 0

	    self.field[F_PROTOCOL] = str(self.lineparts[0])
            self.field[F_PROTOCOL_NUM] = long(self.lineparts[1])
            self.field[F_TIMEOUT] = long(self.lineparts[2])

            self.__off = 3

            if self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__TUPLE_PREF)] != self.__TUPLE_PREF:
                self.field[F_STATE] = str(self.lineparts[self.__off])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_OR_SRC_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_DST_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_SRC_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_OR_DST_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__UNREPLIED_PREF)] == self.__UNREPLIED_PREF:
                self.field[F_UNREPLIED] = str(self.lineparts[self.__off])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[F_OR_PACKETS] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[F_OR_BYTES] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_RE_SRC_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_DST_IP] = str(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_SRC_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1
            if self.__off < self.linewords:
                self.field[F_RE_DST_PORT] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__PACKETS_PREF)] == self.__PACKETS_PREF:
                self.field[F_RE_PACKETS] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__BYTES_PREF)] == self.__BYTES_PREF:
                self.field[F_RE_BYTES] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__ASSURED_PREF)] == self.__ASSURED_PREF:
                self.field[F_ASSURED] = str(self.lineparts[self.__off])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__MARK_PREF)] == self.__MARK_PREF:
                self.field[F_MARK] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if  self.__off < self.linewords and self.lineparts[self.__off][0:len(self.__SECCTX_PREF)] == self.__SECCTX_PREF:
                self.field[F_SECCTX] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
                self.__off += 1

            if self.__off < self.linewords:
                self.field[F_USE] = long(self.lineparts[self.__off].partition(self.__Val_Delim)[2])
           
            self.protocol = self.field[F_PROTOCOL]
            self.timeout = self.field[F_TIMEOUT]
            self.state = self.field[F_STATE]
            self.src_ip = self.field[F_OR_SRC_IP]
            self.src_port = self.field[F_OR_SRC_PORT]
            self.dst_ip = self.field[F_OR_DST_IP]
            self.dst_port = self.field[F_OR_DST_PORT]

        return( self.protocol, self.timeout, self.state, self.src_ip, self.src_port, self.dst_ip, self.dst_port)



class ProcNetIP_TABLES_TARGETS:
    """Pull records from /proc/net/ip_tables_targets"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip_tables_targets")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# REJECT
# LOG
# ERROR

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIP_TABLES_NAMES:
    """Pull records from /proc/net/ip_tables_names"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip_tables_names")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIP_TABLES_MATCHES:
    """Pull records from /proc/net/ip_tables_matches"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip_tables_matches")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# ttl

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIP6_TABLES_TARGETS:
    """Pull records from /proc/net/ip6_tables_targets"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip6_tables_targets")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# LOG
# ERROR

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIP6_TABLES_NAMES:
    """Pull records from /proc/net/ip6_tables_names"""
# DCHK: 11/24/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip6_tables_names")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# filter

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIP6_TABLES_MATCHES:
    """Pull records from /proc/net/ip6_tables_matches"""
# DCHK: 11/20/12
# source: net/netfilter/x_tables.c

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ip6_tables_matches")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# hl

        self.__lines = self.__sio.read_all_lines(self)

        if len(self.__lines) == 0:
            raise StopIteration

        return( self.__lines)



class ProcNetIGMP:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__MinWords_first = 5
        self.__MinWords_second = 4
        self.__sio.open_file(self, "/proc/net/igmp", self.__MinWords_first, "Idx")
        self.__FieldSplitDelim = ":"

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records, the trick here is that the lines are split in two.
# Idx	Device    : Count Querier	Group    Users Timer	Reporter
# 1	lo        :     1      V3
# 				010000E0     1 0:00000000		0
# 2	eth0      :     1      V3
# 				010000E0     1 0:00000000		0

        self.__sio.read_line(self)

        if self.buff == "":

            self.index = 0
            self.device = ANY_DEVICE
            self.count = 0
            self.querier = ""
            self.group = 0
            self.users = 0
            self.timer = 0
        
            self.field = dict()

            self.field[F_INDEX] = 0
            self.field[F_DEVICE] = ANY_DEVICE
            self.field[F_COUNT] = 0
            self.field[F_QUERIER] = ""
            self.field[F_GROUP] = 0
            self.field[F_USERS] = 0
            self.field[F_TIMER] = 0
            self.field[F_ZERO1] = 0
            self.field[F_REPORTER] = 0

        else:
            self.field[F_INDEX] = long(self.lineparts[0])
            self.field[F_DEVICE] = str(self.lineparts[1])
            self.field[F_COUNT] = long(self.lineparts[3])
            self.field[F_QUERIER] = str(self.lineparts[4])

# ... need to read the next line for the rest.
            self.MinWords = self.__MinWords_second
            self.__sio.read_line(self)
            self.MinWords = self.__MinWords_first

            if self.buff == "":

                self.index = 0
                self.device = ANY_DEVICE
                self.count = 0
                self.querier = ""
                self.group = 0
                self.users = 0
                self.timer = 0

                self.field = dict()

                self.field[F_INDEX] = 0
                self.field[F_DEVICE] = ANY_DEVICE
                self.field[F_COUNT] = 0
                self.field[F_QUERIER] = ""
                self.field[F_GROUP] = 0
                self.field[F_USERS] = 0
                self.field[F_TIMER] = 0
                self.field[F_ZERO1] = 0
                self.field[F_REPORTER] = 0

            else:
                self.field[F_GROUP] = long(self.lineparts[0],16)
                self.field[F_USERS] = long(self.lineparts[1])
                __split = self.lineparts[2].partition(self.__FieldSplitDelim)
                self.field[F_TIMER] = long(__split[0])
                self.field[F_ZERO1] = long(__split[2],16)
                self.field[F_REPORTER] = long(self.lineparts[3])

                self.index = self.field[F_INDEX]
                self.device = self.field[F_DEVICE]
                self.count = self.field[F_COUNT]
                self.querier = self.field[F_QUERIER]
                self.group = self.field[F_GROUP]
                self.users = self.field[F_USERS]
                self.timer = self.field[F_TIMER]

        return( self.index, self.device, self.count, self.querier, self.group, self.users, self.timer)



class ProcNetNetfilterNF_QUEUE:
    """Pull records from /proc/net/netfilter/nf_queue"""
# DCHK: 11/19/12
# source: net/netfilter/nf_queue.c
#  if (!qh)
#          ret = seq_printf(s, "%2lld NONE\n", *pos);
#  else
#          ret = seq_printf(s, "%2lld %s\n", *pos, qh->name);

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/netfilter/nf_queue", 2)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  The column headers are informational only, there is no
# -- header line in the file itself.
# Index Name
# 0 NONE
# 1 NONE
# 2 NONE

        self.__sio.read_line(self)

        if self.buff == "":

            self.index = 0
            self.name = ""
        
            self.field = dict()

            self.field[F_INDEX] = 0
            self.field[F_NAME] = ""

        else:
            self.field[F_INDEX] = long(self.lineparts[0])
            self.field[F_NAME] = str(self.lineparts[1])

            self.index = self.field[F_INDEX]
            self.name = self.field[F_NAME]

        return( self.index, self.name)



class ProcNetNetfilterNF_LOG:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/netfilter/nf_log", 3)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  The column headers are informational only, there is no
# -- header line in the file itself.
# Index Name List_of_Loggers
#  0 NONE ()
#  1 NONE ()
#  2 ipt_LOG (ipt_LOG)

        self.__sio.read_line(self)

        if self.buff == "":

            self.index = 0
            self.name = ""
            self.log_list = ""

            self.field = dict()

            self.field[F_INDEX] = 0
            self.field[F_NAME] = ""
            self.field[F_LOGGER_LIST] = ""

        else:
            self.field[F_INDEX] = long(self.lineparts[0])
            self.field[F_NAME] = str(self.lineparts[1])
            __clean = str(self.lineparts[2])
            if __clean[:1] == "(" and __clean[-1:] == ")":
                __clean = __clean[2:-1]
            self.field[F_LOGGER_LIST] = __clean

            self.index = self.field[F_INDEX]
            self.name = self.field[F_NAME]
            self.log_list = self.field[F_LOGGER_LIST]

        return( self.index, self.name, self.log_list)



class ProcNetNETLINK:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/netlink", 10, "sk")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records
# sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
# 0000000000000000 0   4196011 00000000 0        0        0000000000000000 2        0        11034   
# 0000000000000000 0   0      00000000 0        0        0000000000000000 2        0        8       
# 0000000000000000 0   1707   000a0501 0        0        0000000000000000 2        0        11033   

        self.__sio.read_line(self)

        if self.buff == "":

            self.protocol = 0
            self.pid = 0
            self.groups = 0
            self.dump = 0
            self.locks = 0
            self.drops = 0

            self.field = dict()

            self.field[F_SOCKET_POINTER] = 0
            self.field[F_PROTOCOL] = 0
            self.field[F_PID] = 0
            self.field[F_GROUPS] = 0
            self.field[F_RMEM_ALLOC] = 0
            self.field[F_WMEM_ALLOC] = 0
            self.field[F_DUMP] = 0
            self.field[F_LOCKS] = 0
            self.field[F_DROPS] = 0
            self.field[F_INODE] = 0

        else:
            self.field[F_SOCKET_POINTER] = long(self.lineparts[0],16)
            self.field[F_PROTOCOL] = long(self.lineparts[1])
            self.field[F_PID] = long(self.lineparts[2])
            self.field[F_GROUPS] = long(self.lineparts[3],16)
            self.field[F_RMEM_ALLOC] = long(self.lineparts[4])
            self.field[F_WMEM_ALLOC] = long(self.lineparts[5])
            self.field[F_DUMP] = long(self.lineparts[6],16)
            self.field[F_LOCKS] = long(self.lineparts[7])
            self.field[F_DROPS] = long(self.lineparts[8])
            self.field[F_INODE] = long(self.lineparts[9])

            self.protocol = self.field[F_PROTOCOL]
            self.pid = self.field[F_PID]
            self.groups = self.field[F_GROUPS]
            self.dump = self.field[F_DUMP]
            self.locks = self.field[F_LOCKS]
            self.drops = self.field[F_DROPS]

        return( self.protocol, self.pid, self.groups, self.dump, self.locks, self.drops)



class ProcNetCONNECTOR:
    """Pull records from /proc/net/connector"""
# DCHK: 11/19/12
# source: drivers/connector/connector.c
#  list_for_each_entry(cbq, &dev->queue_list, callback_entry) {
#          seq_printf(m, "%-15s %u:%u\n",
#                     cbq->id.name,
#                     cbq->id.id.idx,
#                     cbq->id.id.val);

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/connector", 2, "Name")
        self.__FieldSplitDelim = ":"

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records
# Name            ID
# cn_proc         1:1

        self.__sio.read_line(self)

        if self.buff == "":

            self.name = ""
            self.id_idx = 0
            self.id_val = 0

            self.field = dict()

            self.field[F_NAME] = ""
            self.field[F_ID_IDX] = 0
            self.field[F_ID_VAL] = 0

        else:
            self.field[F_NAME] = str(self.lineparts[0])
            __split = self.lineparts[1].partition(self.__FieldSplitDelim)
            self.field[F_ID_IDX] = long(__split[0])
            self.field[F_ID_VAL] = long(__split[2])

            self.name = self.field[F_NAME]
            self.id_idx = self.field[F_ID_IDX]
            self.id_val = self.field[F_ID_VAL]

        return( self.name, self.id_idx, self.id_val)



class ProcNetPACKET:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/packet", 9, "sk")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records
# sk       RefCnt Type Proto  Iface R Rmem   User   Inode
# 0000000000000000 3      3    0003   2     1 0      0      36995 

        self.__sio.read_line(self)

        if self.buff == "":

            self.type = 0
            self.protocol = 0
            self.interface_index = 0
            self.running = 0
	    self.rmem_alloc = 0
            self.uid = 0

            self.field = dict()

            self.field[F_SOCKET_POINTER] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_TYPE] = 0
            self.field[F_PROTOCOL] = 0
            self.field[F_INT_INDEX] = 0
            self.field[F_RUNNING] = 0
            self.field[F_RMEM_ALLOC] = 0
            self.field[F_UID] = 0
            self.field[F_INODE] = 0

        else:
            self.field[F_SOCKET_POINTER] = long(self.lineparts[0],16)
            self.field[F_REFCOUNT] = long(self.lineparts[1])
            self.field[F_TYPE] = long(self.lineparts[2])
            self.field[F_PROTOCOL] = long(self.lineparts[3],16)
            self.field[F_INT_INDEX] = long(self.lineparts[4])
            self.field[F_RUNNING] = long(self.lineparts[5])
            self.field[F_RMEM_ALLOC] = long(self.lineparts[6])
            self.field[F_UID] = long(self.lineparts[7])
            self.field[F_INODE] = long(self.lineparts[8])

            self.type = self.field[F_TYPE]
            self.protocol = self.field[F_PROTOCOL]
            self.interface_index = self.field[F_INT_INDEX]
            self.running = self.field[F_RUNNING]
	    self.rmem_alloc = self.field[F_RMEM_ALLOC]
            self.uid = self.field[F_UID]

        return( self.type, self.protocol, self.interface_index, self.running, self.rmem_alloc, self.uid)




class ProcNetPROTOCOLS:
    """Pull records from /proc/net/protocols"""
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/protocols", 27, "protocol")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries
# protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em
# BNEP       664      0      -1   NI       0   no   bnep        n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# RFCOMM     680      0      -1   NI       0   no   rfcomm      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# SCO        680      0      -1   NI       0   no   bluetooth   n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
# PACKET    1344      1      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n

        self.__sio.read_line(self)

        if self.buff == "":

            self.protocol = ""
            self.size = 0
            self.sockets = 0
            self.memory = 0
            self.module = ""

            self.field = dict()

            self.field[F_PROTOCOL] = ""
            self.field[F_SIZE] = 0
            self.field[F_SOCKETS] = 0
            self.field[F_MEMORY] = 0
            self.field[F_PRESURE] = ""
            self.field[F_MAX_HEADER] = 0
            self.field[F_SLAB] = ""
            self.field[F_MODULE] = ""
            self.field[F_CLOSE] = ""
            self.field[F_CONNECT] = ""
            self.field[F_DISCONNECT] = ""
            self.field[F_ACCEPT] = ""
            self.field[F_IOCTL] = ""
            self.field[F_INIT] = ""
            self.field[F_DESTROY] = ""
            self.field[F_SHUTDOWN] = ""
            self.field[F_SETSOCKOPT] = ""
            self.field[F_GETSOCKOPT] = ""
            self.field[F_SENDMSG] = ""
            self.field[F_RECVMSG] = ""
            self.field[F_SENDPAGE] = ""
            self.field[F_BIND] = ""
            self.field[F_BACKLOG_RC] = ""
            self.field[F_HASH] = ""
            self.field[F_UNHASH] = ""
            self.field[F_GET_PORT] = ""
            self.field[F_ENTER_PRESSURE] = ""

        else:
            self.field[F_PROTOCOL] = str(self.lineparts[0])
            self.field[F_SIZE] = long(self.lineparts[1])
            self.field[F_SOCKETS] = long(self.lineparts[2])
            self.field[F_MEMORY] = long(self.lineparts[3])
            self.field[F_PRESURE] = str(self.lineparts[4])
            self.field[F_MAX_HEADER] = long(self.lineparts[5])
            self.field[F_SLAB] = str(self.lineparts[6])
            self.field[F_MODULE] = str(self.lineparts[7])
            self.field[F_CLOSE] = str(self.lineparts[8])
            self.field[F_CONNECT] = str(self.lineparts[9])
            self.field[F_DISCONNECT] = str(self.lineparts[10])
            self.field[F_ACCEPT] = str(self.lineparts[11])
            self.field[F_IOCTL] = str(self.lineparts[12])
            self.field[F_INIT] = str(self.lineparts[13])
            self.field[F_DESTROY] = str(self.lineparts[14])
            self.field[F_SHUTDOWN] = str(self.lineparts[15])
            self.field[F_SETSOCKOPT] = str(self.lineparts[16])
            self.field[F_GETSOCKOPT] = str(self.lineparts[17])
            self.field[F_SENDMSG] = str(self.lineparts[18])
            self.field[F_RECVMSG] = str(self.lineparts[19])
            self.field[F_SENDPAGE] = str(self.lineparts[20])
            self.field[F_BIND] = str(self.lineparts[21])
            self.field[F_BACKLOG_RCV] = str(self.lineparts[22])
            self.field[F_HASH] = str(self.lineparts[23])
            self.field[F_UNHASH] = str(self.lineparts[24])
            self.field[F_GET_PORT] = str(self.lineparts[25])
            self.field[F_ENTER_PRESSURE] = str(self.lineparts[26])

            self.protocol = self.field[F_PROTOCOL]
            self.size = self.field[F_SIZE]
            self.sockets = self.field[F_SOCKETS]
            self.memory = self.field[F_MEMORY]
            self.module = self.field[F_MODULE]

        return( self.protocol, self.size, self.sockets, self.memory, self.module)



class ProcNetSOFTNET_STAT:
    """Pull records from /proc/net/softnet_stat"""
# DCHK: 11/18/12
# source: net/core/dev.c
#         seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
#                   sd->processed, sd->dropped, sd->time_squeeze, 0,
#                   0, 0, 0, 0, /* was fastroute */
#                   sd->cpu_collision, sd->received_rps);

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/softnet_stat", 10)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# Processed Dropped Time_Squeeze Null1 Null2   Null3    Null4    Null5    CPU_Coll Received_RPS
# 001fc1c7 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 00002970 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
# 000041b2 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

        self.__sio.read_line(self)

        if self.buff == "":

            self.processed = 0
            self.dropped = 0
            self.time_squeeze = 0
            self.cpu_coll = 0
            self.received_rps = 0

            self.field = dict()

            self.field[F_PROCESSED] = 0
            self.field[F_DROPPED] = 0
            self.field[F_TIME_SQUEEZE] = 0
            self.field[F_ZERO1] = 0
            self.field[F_ZERO2] = 0
            self.field[F_ZERO3] = 0
            self.field[F_ZERO4] = 0
            self.field[F_ZERO5] = 0
            self.field[F_CPU_COLL] = 0
            self.field[F_RECEIVED_RPS] = 0

        else:
            self.field[F_PROCESSED] = long(self.lineparts[0],16)
            self.field[F_DROPPED] = long(self.lineparts[1],16)
            self.field[F_TIME_SQUEEZE] = long(self.lineparts[2],16)
            self.field[F_ZERO1] = long(self.lineparts[3],16)
            self.field[F_ZERO2] = long(self.lineparts[4],16)
            self.field[F_ZERO3] = long(self.lineparts[5],16)
            self.field[F_ZERO4] = long(self.lineparts[6],16)
            self.field[F_ZERO5] = long(self.lineparts[7],16)
            self.field[F_CPU_COLL] = long(self.lineparts[8],16)
            self.field[F_RECEIVED_RPS] = long(self.lineparts[9],16)

            self.processed = self.field[F_PROCESSED]
            self.dropped = self.field[F_DROPPED]
            self.time_squeeze = self.field[F_TIME_SQUEEZE]
            self.cpu_coll = self.field[F_CPU_COLL]
            self.received_rps = self.field[F_RECEIVED_RPS]

        return( self.processed, self.dropped, self.time_squeeze, self.cpu_coll, self.received_rps)



class ProcNetRT6_STATS:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/rt6_stats", 7)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# Nodes RouteNotes RouteAlloc RouteEntries RouteCache DestOps DiscardRoutes
# 0000 0004 0000 0004 0000 0002 007a

        self.__sio.read_line(self)

        if self.buff == "":
            self.nodes = 0
            self.route_nodes = 0
            self.route_entries = 0
            self.route_cache = 0
            self.discarded = 0

            self.field = dict()

            self.field[F_FIB_NODES] = 0
            self.field[F_FIB_ROUTE_NODES] = 0
            self.field[F_FIB_ROUTE_ALLOC] = 0
            self.field[F_FIB_ROUTE_ENTRIES] = 0
            self.field[F_FIB_ROUTE_CACHE] = 0
            self.field[F_FIB_DEST_OPS] = 0
            self.field[F_FIB_DISC_ROUTES] = 0

        else:
            self.field[F_FIB_NODES] = long(self.lineparts[0],16)
            self.field[F_FIB_ROUTE_NODES] = long(self.lineparts[1],16)
            self.field[F_FIB_ROUTE_ALLOC] = long(self.lineparts[2],16)
            self.field[F_FIB_ROUTE_ENTRIES] = long(self.lineparts[3],16)
            self.field[F_FIB_ROUTE_CACHE] = long(self.lineparts[4],16)
            self.field[F_FIB_DEST_OPS] = long(self.lineparts[5],16)
            self.field[F_FIB_DISC_ROUTES] = long(self.lineparts[6],16)

            self.nodes = self.field[F_FIB_NODES] 
            self.route_nodes = self.field[F_FIB_ROUTE_NODES] 
            self.route_entries = self.field[F_FIB_ROUTE_ENTRIES] 
            self.route_cache = self.field[F_FIB_ROUTE_CACHE] 
            self.discarded = self.field[F_FIB_DISC_ROUTES] 

        return( self.nodes, self.route_nodes, self.route_entries, self.route_cache, self.discarded)


class ProcNetPSCHED:
    """Pull records from /proc/net/psched"""
# DCHK: 11/18/12
# source: net/sched/sch_api.c
#       seq_printf(seq, "%08x %08x %08x %08x\n",
#                  (u32)NSEC_PER_USEC, (u32)PSCHED_TICKS2NS(1),
#                  1000000,
#                  (u32)NSEC_PER_SEC/(u32)ktime_to_ns(timespec_to_ktime(ts)));

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/psched", 4)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# NSec_per_USec PSched_Ticks Unknown_Field NSec_per_HRtimer
# 000003e8 00000040 000f4240 3b9aca00

        self.__sio.read_line(self)

        if self.buff == "":
            self.nsec_per_usec = 0
            self.psched_ticks = 0
            self.nsec_per_hrtime = 0

            self.field = dict()

            self.field[F_NSEC_PER_USEC] = 0
            self.field[F_PSCHED_TICKS] = 0
            self.field[F_UNKNOWN_FIELD] = 0
            self.field[F_NSEC_PER_HRTIME] = 0

        else:
            self.field[F_NSEC_PER_USEC] = long(self.lineparts[0],16)
            self.field[F_PSCHED_TICKS] = long(self.lineparts[1],16)
            self.field[F_UNKNOWN_FIELD] = long(self.lineparts[2],16)
            self.field[F_NSEC_PER_HRTIME] = long(self.lineparts[3],16)

            self.nsec_per_usec = self.field[F_NSEC_PER_USEC] 
            self.psched_ticks = self.field[F_PSCHED_TICKS] 
            self.nsec_per_hrtime = self.field[F_NSEC_PER_HRTIME]

        return( self.nsec_per_usec, self.psched_ticks, self.nsec_per_hrtime)


class ProcNetIPV6_ROUTE:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/ipv6_route", 10)
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# DestAddr                DestPrefLen SrcAddr                 AddrPrefLen PrimaryKey                    RT6I_METRIC DestRefCount DestUse RT6I_FLAGS Device
# fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0
# 00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 000010cf 00200200       lo
# fe80000000000000ca6000fffe01e486 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo
# ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001     eth0

        self.__sio.read_line(self)

        if self.buff == "":
            self.dest_ip = PRESENT_ANY_IPV6_ADDR
            self.dest_pref_len = 0
            self.src_ip = PRESENT_ANY_IPV6_ADDR
            self.src_pref_len = 0
            self.dest_refcount = 0
            self.device = ANY_DEVICE

            self.field = dict()

            self.field[F_DEST_HEXIP] = ANY_IPV6_ADDR_HEX
            self.field[F_DEST_PREFIX_LEN_HEX] = "00"
            self.field[F_SRCE_HEXIP] = ANY_IPV6_ADDR_HEX
            self.field[F_SRCE_PREFIX_LEN_HEX] = "00"
            self.field[F_PRIMARY_KEY] = ANY_IPV6_ADDR_HEX
            self.field[F_RT6I_METRIC] = 0
            self.field[F_DEST_REFCOUNT] = 0
            self.field[F_DEST_USE] = 0
            self.field[F_RT6I_FLAGS] = NULL_MASK_HEX
            self.field[F_DEVICE] = ANY_DEVICE
            self.field[F_DEST_IP] = PRESENT_ANY_IPV6_ADDR
            self.field[F_DEST_PREFIX_LEN] = 0
            self.field[F_SOURCE] = PRESENT_ANY_IPV6_ADDR
            self.field[F_SRCE_PREFIX_LEN] = 0

        else:
            self.field[F_DEST_HEXIP] = str(self.lineparts[0])
            self.field[F_DEST_PREFIX_LEN_HEX] = str(self.lineparts[1])
            self.field[F_SRCE_HEXIP] = str(self.lineparts[2])
            self.field[F_SRCE_PREFIX_LEN_HEX] = str(self.lineparts[3])
            self.field[F_PRIMARY_KEY] = str(self.lineparts[4])
            self.field[F_RT6I_METRIC] = long(self.lineparts[5],16)
            self.field[F_DEST_REFCOUNT] = long(self.lineparts[6],16)
            self.field[F_DEST_USE] = long(self.lineparts[7],16)
            self.field[F_RT6I_FLAGS] = str(self.lineparts[8])
            self.field[F_DEVICE] = str(self.lineparts[9])

            self.field[F_DEST_IP] = self.ipconv.ipv6_hexstring_to_presentation(self.field[F_DEST_HEXIP])
            self.field[F_DEST_PREFIX_LEN] = long(self.field[F_DEST_PREFIX_LEN_HEX],16)
            self.field[F_SOURCE] = self.ipconv.ipv6_hexstring_to_presentation(self.field[F_SRCE_HEXIP])
            self.field[F_SRCE_PREFIX_LEN] = long(self.field[F_SRCE_PREFIX_LEN_HEX],16)

            self.dest_ip = self.field[F_DEST_IP] 
            self.dest_pref_len = self.field[F_DEST_PREFIX_LEN]
            self.src_ip = self.field[F_SOURCE]
            self.src_pref_len = self.field[F_SRCE_PREFIX_LEN]
            self.dest_refcount = self.field[F_DEST_REFCOUNT]
            self.device = self.field[F_DEVICE]

        return( self.dest_ip, self.dest_pref_len, self.src_ip, self.src_pref_len, self.dest_refcount, self.device)


class ProcNetIGMP6:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/igmp6", 6)
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# IntFaceIndex DeviceName MCastAddress             MCastUsers MCastFlags TimerExp 
# 1    lo              ff020000000000000000000000000001     1 0000000C 0
# 2    eth0            ff0200000000000000000001ff01e486     1 00000004 0
# 2    eth0            ff020000000000000000000000000001     1 0000000C 0

        self.__sio.read_line(self)

        if self.buff == "":
            self.device = ANY_DEVICE
            self.mcast_addr = PRESENT_ANY_IPV6_ADDR
            self.mcast_users = 0
            self.mcast_flags = NULL_MASK_HEX
       
            self.field = dict()

            self.field[F_INT_INDEX] = 0
            self.field[F_DEVICE] = ANY_DEVICE
            self.field[F_MCAST_ADDR_HEX] = ANY_IPV6_ADDR_HEX
            self.field[F_MCAST_ADDR] = PRESENT_ANY_IPV6_ADDR
            self.field[F_MCAST_USERS] = 0
            self.field[F_MCAST_FLAGS] = NULL_MASK_HEX
            self.field[F_TIMER_EXPIRE] = 0

        else:
            self.field[F_INT_INDEX] = long(self.lineparts[0])
            self.field[F_DEVICE] = str(self.lineparts[1])
            self.field[F_MCAST_ADDR_HEX] = str(self.lineparts[2])
            self.field[F_MCAST_USERS] = long(self.lineparts[3])
            self.field[F_MCAST_FLAGS] = str(self.lineparts[4])
            self.field[F_TIMER_EXPIRE] = long(self.lineparts[5])
            self.field[F_MCAST_ADDR] = self.ipconv.ipv6_hexstring_to_presentation(str(self.lineparts[2]))

            self.device = self.field[F_DEVICE]
            self.mcast_addr = self.field[F_MCAST_ADDR]
            self.mcast_users = self.field[F_MCAST_USERS]
            self.mcast_flags = self.field[F_MCAST_FLAGS]

        return( self.device, self.mcast_addr, self.mcast_users, self.mcast_flags)


class ProcNetDEV_MCAST:
    """Pull records from /proc/net/dev_mcast"""
# DCHK: 11/17/12
# source: net/core/dev_addr_lists.ca
#                seq_printf(seq, "%-4d %-15s %-5d %-5d ", dev->ifindex,
#                           dev->name, ha->refcount, ha->global_use);
#
#                for (i = 0; i < dev->addr_len; i++)
#                        seq_printf(seq, "%02x", ha->addr[i]);

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/dev_mcast", 5)

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# IFaceIndex Device RefCount GlobalUse DeviceAddress 
# 2    eth0            1     0     01005e000001
# 2    eth0            1     0     333300000001
# 2    eth0            1     0     3333ff01e486

        self.__sio.read_line(self)

        if self.buff == "":
            self.device = ""
            self.ref_count = 0
            self.global_use = 0

            self.field = dict()

            self.field[F_INT_INDEX] = 0
            self.field[F_DEVICE] = ANY_DEVICE
            self.field[F_REFCOUNT] = 0
            self.field[F_GLOBAL_USE] = 0
            self.field[F_DEV_ADDR] = "000000000000"

        else:
            self.field[F_INT_INDEX] = long(self.lineparts[0])
            self.field[F_DEVICE] = str(self.lineparts[1])
            self.field[F_REFCOUNT] = long(self.lineparts[2])
            self.field[F_GLOBAL_USE] = long(self.lineparts[3])
            self.field[F_DEV_ADDR] = str(self.lineparts[4])

            self.device = self.field[F_DEVICE]
            self.ref_count = self.field[F_REFCOUNT]
            self.global_use = self.field[F_GLOBAL_USE]

        return( self.device, self.ref_count, self.global_use)


class ProcNetIF_INET6:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/if_inet6", 6)
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note the header is for informational purposes and
# -- there's no header line in the file itself
# ipv6 interface_index prefix_len scope flags device
# fe80000000000000ca6000fffe01e486 02 40 20 80     eth0
# 00000000000000000000000000000001 01 80 10 80       lo

        self.__sio.read_line(self)

        if self.buff == "":

            self.ipv6 = ANY_IPV6_ADDR
            self.ipv6_hex = ANY_IPV6_ADDR_HEX
            self.scope = 0
            self.device = ANY_DEVICE

            self.field = dict()

            self.field[F_IPV6_HEX] = ANY_IPV6_ADDR_HEX
            self.field[F_INT_INDEX_HEX] = "00"
            self.field[F_PREFIX_LEN_HEX] = "00"
            self.field[F_SCOPE_HEX] = "00"
            self.field[F_FLAGS_HEX] = "00"
            self.field[F_DEVICE] = ANY_DEVICE
            self.field[F_IPV6] = ANY_IPV6_ADDR
            self.field[F_INT_INDEX] = 0
            self.field[F_PREFIX_LEN] = 0
            self.field[F_SCOPE] = 0
            self.field[F_FLAGS] = 0

        else:
            self.field[F_IPV6_HEX] = str(self.lineparts[0])
            self.field[F_INT_INDEX_HEX] = str(self.lineparts[1])
            self.field[F_INT_INDEX] = long(self.lineparts[1],16)
            self.field[F_PREFIX_LEN_HEX] = str(self.lineparts[2])
            self.field[F_PREFIX_LEN_HEX] = long(self.lineparts[2],16)
            self.field[F_SCOPE_HEX] = str(self.lineparts[3])
            self.field[F_SCOPE] = long(self.lineparts[3],16)
            self.field[F_FLAGS_HEX] = str(self.lineparts[4])
            self.field[F_FLAGS] = long(self.lineparts[4],16)
            self.field[F_DEVICE] = self.lineparts[5]
            self.field[F_IPV6] = self.ipconv.ipv6_hexstring_to_presentation(str(self.lineparts[0]))

            self.ipv6 = self.field[F_IPV6]
            self.ipv6_hex = self.field[F_IPV6_HEX]
            self.scope = self.field[F_SCOPE]
            self.device = self.field[F_DEVICE]

        return( self.ipv6, self.ipv6_hex, self.scope, self.device)



class ProcNetUNIX:
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


    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/unix", 7, "Num")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note that each line is for a different CPU
# Num       RefCount Protocol Flags    Type St Inode Path
# 0000000000000000: 00000002 00000000 00010000 0001 01 15807 @/tmp/dbus-HTivHd8Iyv
# 0000000000000000: 00000002 00000000 00010000 0001 01 14531 /tmp/.X11-unix/X0
# 0000000000000000: 00000002 00000000 00010000 0001 01 16649 /tmp/keyring-OUNO20/control

        self.__sio.read_line(self)

        if self.buff == "":
            self.protocol = 0
            self.refcount = 0
            self.flags = 0
            self.type = 0
            self.state = 0
            self.inode = 0
            self.path = ""

            self.field = dict()

            self.field[F_NUM] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_PROTOCOL] = 0
            self.field[F_FLAGS] = "00000000"
            self.field[F_TYPE] = "0001"
            self.field[F_STATE] = 0
            self.field[F_INODE] = 0
            self.field[F_PATH] = ""

        else:
            __seq = self.lineparts[0]
            if __seq[-1:] == ":":
                __seq = __seq[:-1]
            self.field[F_NUM] = long(__seq,16)
            self.field[F_REFCOUNT] = long(self.lineparts[1],16)
            self.field[F_PROTOCOL] = long(self.lineparts[2],16)
            self.field[F_FLAGS] = long(self.lineparts[3],16)
            self.field[F_TYPE] = long(self.lineparts[4],16)
            self.field[F_STATE] = long(self.lineparts[5],16)
            self.field[F_INODE] = long(self.lineparts[6])
            if self.linewords > self.MinWords:
                self.field[F_PATH] = self.lineparts[7]
            else:
                self.field[F_PATH] = ""

            self.protocol = self.field[F_PROTOCOL]
            self.refcount = self.field[F_REFCOUNT]
            self.flags = self.field[F_FLAGS]
            self.type = self.field[F_TYPE]
            self.state = self.field[F_STATE]
            self.inode = self.field[F_INODE]
            self.path = self.field[F_PATH]

        return( self.refcount, self.protocol, self.flags, self.type, self.state, self.inode, self.path)



class ProcNetStatRT_CACHE:
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


    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/stat/rt_cache", 17, "entries")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note that each line is for a different CPU
# entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search
# 000000a4  00579509 0002044f 00000000 00000000 00001e53 00000000 00000018  0006f8ff 00002620 00000001 00000000 00000000 00000000 00000000 0000ba0b 00000092 
# 000000a4  00000000 00000002 00000000 00000000 00000001 00000000 00000000  0006f479 000027b4 00000000 00000000 00000000 00000000 00000000 00000000 00000008 

        self.__sio.read_line(self)

        if self.buff == "":
            self.entries = 0
            self.in_hit = 0
            self.in_slow = 0
            self.out_hit = 0
            self.out_slow = 0
    
            self.field = dict()
    
            self.field[F_ENTRIES] = 0
            self.field[F_IN_HIT] = 0
            self.field[F_IN_SLOW_TOT] = 0
            self.field[F_IN_SLOW_MC] = 0
            self.field[F_IN_NO_ROUTE] = 0
            self.field[F_IN_BRD] = 0
            self.field[F_IN_MARTIAN_DST] = 0
            self.field[F_IN_MARTIAN_SRC] = 0
            self.field[F_OUT_HIT] = 0
            self.field[F_OUT_SLOW_TOT] = 0
            self.field[F_OUT_SLOW_MC] = 0
            self.field[F_GC_TOTAL] = 0
            self.field[F_GC_IGNORED] = 0
            self.field[F_GC_GOAL_MISS] = 0
            self.field[F_GC_DST_OVERFLOW] = 0
            self.field[F_IN_HL_SEARCH] = 0
            self.field[F_OUT_HL_SEARCH] = 0
    
        else:
            self.field[F_ENTRIES] = long(self.lineparts[0],16)
            self.field[F_IN_HIT] = long(self.lineparts[1],16)
            self.field[F_IN_SLOW_TOT] = long(self.lineparts[2],16)
            self.field[F_IN_SLOW_MC] = long(self.lineparts[3],16)
            self.field[F_IN_NO_ROUTE] = long(self.lineparts[4],16)
            self.field[F_IN_BRD] = long(self.lineparts[5],16)
            self.field[F_IN_MARTIAN_DST] = long(self.lineparts[6],16)
            self.field[F_IN_MARTIAN_SRC] = long(self.lineparts[7],16)
            self.field[F_OUT_HIT] = long(self.lineparts[8],16)
            self.field[F_OUT_SLOW_TOT] = long(self.lineparts[9],16)
            self.field[F_OUT_SLOW_MC] = long(self.lineparts[10],16)
            self.field[F_GC_TOTAL] = long(self.lineparts[11],16)
            self.field[F_GC_IGNORED] = long(self.lineparts[12],16)
            self.field[F_GC_GOAL_MISS] = long(self.lineparts[13],16)
            self.field[F_GC_DST_OVERFLOW] = long(self.lineparts[14],16)
            self.field[F_IN_HL_SEARCH] = long(self.lineparts[15],16)
            self.field[F_OUT_HL_SEARCH] = long(self.lineparts[16],16)

            self.entries = self.field[F_ENTRIES]
            self.in_hit = self.field[F_IN_HIT]
            self.in_slow = self.field[F_IN_SLOW_TOT]
            self.out_hit = self.field[F_OUT_HIT]
            self.out_slow = self.field[F_OUT_SLOW_TOT]

        return( self.entries, self.in_hit, self.in_slow, self.out_hit, self.out_slow)



class ProcNetStatNDISC_CACHE:
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


    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/stat/ndisc_cache", 12, "entries")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note that each line is for a different CPU
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000

        self.__sio.read_line(self)

        if self.buff == "":
            self.entries = 0
            self.lookups = 0
            self.hits = 0
    
            self.field = dict()
    
            self.field[F_ARP_ENTRIES] = 0
            self.field[F_ALLOC] = 0
            self.field[F_DESTROY] = 0
            self.field[F_HASH_GROW] = 0
            self.field[F_LOOKUP] = 0
            self.field[F_HIT] = 0
            self.field[F_RES_FAIL] = 0
            self.field[F_RCV_MCAST_PROBE] = 0
            self.field[F_RCV_UCAST_PROBE] = 0
            self.field[F_GC_PERIODIC] = 0
            self.field[F_GC_FORCED] = 0
            self.field[F_UNRES_DISCARD] = 0
    
        else:
            self.field[F_ARP_ENTRIES] = long(self.lineparts[0],16)
            self.field[F_ALLOC] = long(self.lineparts[1],16)
            self.field[F_DESTROY] = long(self.lineparts[2],16)
            self.field[F_HASH_GROW] = long(self.lineparts[3],16)
            self.field[F_LOOKUP] = long(self.lineparts[4],16)
            self.field[F_HIT] = long(self.lineparts[5],16)
            self.field[F_RES_FAIL] = long(self.lineparts[6],16)
            self.field[F_RCV_MCAST_PROBE] = long(self.lineparts[7],16)
            self.field[F_RCV_UCAST_PROBE] = long(self.lineparts[8],16)
            self.field[F_GC_PERIODIC] = long(self.lineparts[9],16)
            self.field[F_GC_FORCED] = long(self.lineparts[10],16)
            self.field[F_UNRES_DISCARD] = long(self.lineparts[11],16)

            self.entries = self.field[F_ARP_ENTRIES]
            self.lookups = self.field[F_LOOKUP]
            self.hits = self.field[F_HIT]

        return( self.entries, self.lookups, self.hits)



class ProcNetStatNF_CONNTRACK:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/stat/nf_conntrack", 17, "entries")

    def __iter__(self):
        return(self)

    def next(self):

# -- sample records, note that there's one line for each CPU on the system
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000085  00003e40 007782a9 00024eab 0000060a 00012c63 0006e7c2 00067e99 0001e5a5 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000085  00000c5f 00053a15 0001ce59 00000041 0000d3b2 000069ca 000069c9 0001ce58 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000

        self.__sio.read_line(self)

        if self.buff == "":
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
    
            self.field[F_ENTRIES] = 0
            self.field[F_SEARCHED] = 0
            self.field[F_FOUND] = 0
            self.field[F_NEW] = 0
            self.field[F_INVALID] = 0
            self.field[F_IGNORE] = 0
            self.field[F_DELETE] = 0
            self.field[F_DELETE_LIST] = 0
            self.field[F_INSERT] = 0
            self.field[F_INSERT_FAILED] = 0
            self.field[F_DROP] = 0
            self.field[F_DROP_EARLY] = 0
            self.field[F_ICMP_ERROR] = 0
            self.field[F_EXP_NEW] = 0
            self.field[F_EXP_CREATE] = 0
            self.field[F_EXP_DELETE] = 0
            self.field[F_SEARCH_RESTART] = 0

        else:
            self.field[F_ENTRIES] = long(self.lineparts[0],16)
            self.field[F_SEARCHED] = long(self.lineparts[1],16)
            self.field[F_FOUND] = long(self.lineparts[2],16)
            self.field[F_NEW] = long(self.lineparts[3],16)
            self.field[F_INVALID] = long(self.lineparts[4],16)
            self.field[F_IGNORE] = long(self.lineparts[5],16)
            self.field[F_DELETE] = long(self.lineparts[6],16)
            self.field[F_DELETE_LIST] = long(self.lineparts[7],16)
            self.field[F_INSERT] = long(self.lineparts[8],16)
            self.field[F_INSERT_FAILED] = long(self.lineparts[9],16)
            self.field[F_DROP] = long(self.lineparts[10],16)
            self.field[F_DROP_EARLY] = long(self.lineparts[11],16)
            self.field[F_ICMP_ERROR] = long(self.lineparts[12],16)
            self.field[F_EXP_NEW] = long(self.lineparts[13],16)
            self.field[F_EXP_CREATE] = long(self.lineparts[14],16)
            self.field[F_EXP_DELETE] = long(self.lineparts[15],16)
            self.field[F_SEARCH_RESTART] = long(self.lineparts[16],16)

            self.entries = self.field[F_ENTRIES]
            self.searched = self.field[F_SEARCHED]
            self.found = self.field[F_FOUND]
            self.new = self.field[F_NEW]
            self.invalid = self.field[F_INVALID]
            self.ignore = self.field[F_IGNORE]
            self.delete = self.field[F_DELETE]
            self.insert = self.field[F_INSERT]
            self.drop = self.field[F_DROP]

        return( self.entries, self.searched, self.found, self.new, self.invalid, self.ignore, self.delete, self.insert, self.drop)


class ProcNetStatIP_CONNTRACK:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/stat/ip_conntrack", 17, "entries")

    def __iter__(self):
        return(self)

    def next(self):

# -- sample records, note that there's one line for each CPU on the system
# entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart
# 00000084  00003e17 00770ce7 00024cc0 0000060a 00012bf0 0006e07e 0006778b 0001e3f0 00000000 00000000 00000000 00000000  00000023 00000001 00000023 00000000
# 00000084  00000c51 00053265 0001cc23 00000041 0000d313 00006987 00006986 0001cc22 00000000 00000000 00000000 00000000  00000000 0000000f 00000000 00000000

        self.__sio.read_line(self)

        if self.buff == "":
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

            self.field[F_ENTRIES] = 0
            self.field[F_SEARCHED] = 0
            self.field[F_FOUND] = 0
            self.field[F_NEW] = 0
            self.field[F_INVALID] = 0
            self.field[F_IGNORE] = 0
            self.field[F_DELETE] = 0
            self.field[F_DELETE_LIST] = 0
            self.field[F_INSERT] = 0
            self.field[F_INSERT_FAILED] = 0
            self.field[F_DROP] = 0
            self.field[F_DROP_EARLY] = 0
            self.field[F_ICMP_ERROR] = 0
            self.field[F_EXP_NEW] = 0
            self.field[F_EXP_CREATE] = 0
            self.field[F_EXP_DELETE] = 0
            self.field[F_SEARCH_RESTART] = 0

        else:
            self.field[F_ENTRIES] = long(self.lineparts[0],16)
            self.field[F_SEARCHED] = long(self.lineparts[1],16)
            self.field[F_FOUND] = long(self.lineparts[2],16)
            self.field[F_NEW] = long(self.lineparts[3],16)
            self.field[F_INVALID] = long(self.lineparts[4],16)
            self.field[F_IGNORE] = long(self.lineparts[5],16)
            self.field[F_DELETE] = long(self.lineparts[6],16)
            self.field[F_DELETE_LIST] = long(self.lineparts[7],16)
            self.field[F_INSERT] = long(self.lineparts[8],16)
            self.field[F_INSERT_FAILED] = long(self.lineparts[9],16)
            self.field[F_DROP] = long(self.lineparts[10],16)
            self.field[F_DROP_EARLY] = long(self.lineparts[11],16)
            self.field[F_ICMP_ERROR] = long(self.lineparts[12],16)
            self.field[F_EXP_NEW] = long(self.lineparts[13],16)
            self.field[F_EXP_CREATE] = long(self.lineparts[14],16)
            self.field[F_EXP_DELETE] = long(self.lineparts[15],16)
            self.field[F_SEARCH_RESTART] = long(self.lineparts[16],16)

            self.entries = self.field[F_ENTRIES]
            self.searched = self.field[F_SEARCHED]
            self.found = self.field[F_FOUND]
            self.new = self.field[F_NEW]
            self.invalid = self.field[F_INVALID]
            self.ignore = self.field[F_IGNORE]
            self.delete = self.field[F_DELETE]
            self.insert = self.field[F_INSERT]
            self.drop = self.field[F_DROP]

        return( self.entries, self.searched, self.found, self.new, self.invalid, self.ignore, self.delete, self.insert, self.drop)



class ProcNetStatARP_CACHE:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/stat/arp_cache", 12, "entries")

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample entries, note that each line is for a different CPU
# entries  allocs destroys hash_grows  lookups hits  res_failed  rcv_probes_mcast rcv_probes_ucast  periodic_gc_runs forced_gc_runs unresolved_discards
# 00000003  0000000f 0000002e 00000000  000186e5 00001172  00000000  00000000 00000000  0000a08c 00000000 00000000
# 00000003  00000005 00000000 00000000  00000002 00000000  00000000  00000000 00000000  00000000 00000000 00000000
# 00000003  00000008 00000000 00000000  00000003 00000001  00000000  00000000 00000000  00000000 00000000 00000000

        self.__sio.read_line(self)

        if self.buff == "":
            self.entries = 0
            self.lookups = 0
            self.hits = 0

            self.field = dict()

            self.field[F_ARP_ENTRIES] = 0
            self.field[F_ALLOC] = 0
            self.field[F_DESTROY] = 0
            self.field[F_HASH_GROW] = 0
            self.field[F_LOOKUP] = 0
            self.field[F_HIT] = 0
            self.field[F_RES_FAIL] = 0
            self.field[F_RCV_MCAST_PROBE] = 0
            self.field[F_RCV_UCAST_PROBE] = 0
            self.field[F_GC_PERIODIC] = 0
            self.field[F_GC_FORCED] = 0
            self.field[F_UNRES_DISCARD] = 0
    
        else:
            self.field[F_ARP_ENTRIES] = long(self.lineparts[0],16)
            self.field[F_ALLOC] = long(self.lineparts[1],16)
            self.field[F_DESTROY] = long(self.lineparts[2],16)
            self.field[F_HASH_GROW] = long(self.lineparts[3],16)
            self.field[F_LOOKUP] = long(self.lineparts[4],16)
            self.field[F_HIT] = long(self.lineparts[5],16)
            self.field[F_RES_FAIL] = long(self.lineparts[6],16)
            self.field[F_RCV_MCAST_PROBE] = long(self.lineparts[7],16)
            self.field[F_RCV_UCAST_PROBE] = long(self.lineparts[8],16)
            self.field[F_GC_PERIODIC] = long(self.lineparts[9],16)
            self.field[F_GC_FORCED] = long(self.lineparts[10],16)
            self.field[F_UNRES_DISCARD] = long(self.lineparts[11],16)

            self.entries = self.field[F_ARP_ENTRIES]
            self.lookups = self.field[F_LOOKUP]
            self.hits = self.field[F_HIT]

        return( self.entries, self.lookups, self.hits)



class ProcNetRT_CACHE:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/rt_cache", 15, "Iface")
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Samples lines.
# Iface	Destination	Gateway 	Flags		RefCnt	Use	Metric	Source		MTU	Window	IRTT	TOS	HHRef	HHUptod	SpecDst
# %s    %08X            %08X            %8X             %d      %u      %d      %08X            %d      %u      %u      %02X    %d      %1d     %08X
# eth0	C1874A61	0101A8C0	       0	0	0	0	0E01A8C0	1500	0	182	00	-1	1	0E01A8C0
# eth0	0101A8C0	0101A8C0	       0	0	375723	0	0E01A8C0	1500	0	113	00	-1	1	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	23	0	2BE07D4A	16436	0	0	00	-1	0	0E01A8C0
# lo	0E01A8C0	0E01A8C0	80000000	0	1	0	28846DD0	16436	0	0	00	-1	0	0E01A8C0

        self.__sio.read_line(self)

        if self.buff == "":
            self.interface = ANY_INTERFACE
            self.destination = ANY_IP_ADDR
            self.gateway = ANY_IP_ADDR
            self.usecount = 0
            self.source = ANY_IP_ADDR
            self.spec_dst = ANY_IP_ADDR

            self.field = dict()

            self.field[F_INTERFACE] = ANY_INTERFACE
            self.field[F_DEST_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_GATE_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_FLAGS] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_USECOUNT] = 0
            self.field[F_METRIC] = 0
            self.field[F_SRCE_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_MTU] = 0
            self.field[F_WINDOW] = 0
            self.field[F_IRTT] = 0
            self.field[F_TOS] = 0
            self.field[F_HHREF] = 0
            self.field[F_HHUPTOD] = 0
            self.field[F_SPEC_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_DEST_IP] = ANY_IP_ADDR
            self.field[F_GATEWAY] = ANY_IP_ADDR
            self.field[F_SOURCE] = ANY_IP_ADDR
            self.field[F_SPEC_DST] = ANY_IP_ADDR

        else:
            self.field[F_INTERFACE] = self.lineparts[0]
            self.field[F_DEST_HEXIP] = str(self.lineparts[1])
            self.field[F_GATE_HEXIP] = str(self.lineparts[2])
            self.field[F_FLAGS] = long(self.lineparts[3],16)
            self.field[F_REFCOUNT] = long(self.lineparts[4])
            self.field[F_USECOUNT] = long(self.lineparts[5])
            self.field[F_METRIC] = long(self.lineparts[6])
            self.field[F_SRCE_HEXIP] = str(self.lineparts[7])
            self.field[F_MTU] = long(self.lineparts[8])
            self.field[F_WINDOW] = long(self.lineparts[9])
            self.field[F_IRTT] = long(self.lineparts[10])
            self.field[F_TOS] = long(self.lineparts[11],16)
            self.field[F_HHREF] = long(self.lineparts[12])
            self.field[F_HHUPTOD] = long(self.lineparts[13])
            self.field[F_SPEC_HEXIP] = str(self.lineparts[14])

            __hexip = self.field[F_DEST_HEXIP]
            self.field[F_DEST_IP] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            __hexip = self.field[F_GATE_HEXIP]
            self.field[F_GATEWAY] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            __hexip = self.field[F_SRCE_HEXIP]
            self.field[F_SOURCE] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            __hexip = self.field[F_SPEC_HEXIP]
            self.field[F_SPEC_DST] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            self.interface = self.field[F_INTERFACE]
            self.destination = self.field[F_DEST_IP]
            self.gateway = self.field[F_GATEWAY]
            self.usecount = self.field[F_USECOUNT]
            self.source = self.field[F_SOURCE]
            self.spec_dst = self.field[F_SPEC_DST]

        return( self.interface, self.destination, self.gateway, self.usecount, self.source, self.spec_dst)



class ProcNetROUTE:
    """Pull records from /proc/net/route"""
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/route", 11, "Iface")

    def __iter__(self):
        return(self)

    def next(self):

# -- Samples lines.
# Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT                                                       
# eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0                                                                               
# eth0	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0                                                                            
# eth0	0001A8C0	00000000	0001	0	0	1	00FFFFFF	0	0	0                                                                               

        self.__sio.read_line(self)

        if self.buff == "":
            self.interface = ANY_INTERFACE
            self.destination = ANY_IP_ADDR
            self.gateway = ANY_IP_ADDR
            self.netmask = ANY_IP_ADDR

            self.field = dict()

            self.field[F_INTERFACE] = ANY_INTERFACE
            self.field[F_DEST_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_GATE_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_FLAGS] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_USECOUNT] = 0
            self.field[F_METRIC] = 0
            self.field[F_MASK_HEXIP] = str(ANY_IP_ADDR_HEX)
            self.field[F_MTU] = 0
            self.field[F_WINDOW] = 0
            self.field[F_IRTT] = 0
            self.field[F_DEST_IP] = ANY_IP_ADDR
            self.field[F_GATEWAY] = ANY_IP_ADDR
            self.field[F_NETMASK] = ANY_IP_ADDR
    
        else:
            self.field[F_INTERFACE] = self.lineparts[0]
            self.field[F_DEST_HEXIP] = str(self.lineparts[1])
            self.field[F_GATE_HEXIP] = str(self.lineparts[2])
            self.field[F_FLAGS] = long(self.lineparts[3],16)
            self.field[F_REFCOUNT] = long(self.lineparts[4])
            self.field[F_USECOUNT] = long(self.lineparts[5])
            self.field[F_METRIC] = long(self.lineparts[6])
            self.field[F_MASK_HEXIP] = str(self.lineparts[7])
            self.field[F_MTU] = long(self.lineparts[8])
            self.field[F_WINDOW] = long(self.lineparts[9])
            self.field[F_IRTT] = long(self.lineparts[10])

            __hexip = self.field[F_DEST_HEXIP]
            self.field[F_DEST_IP] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            __hexip = self.field[F_GATE_HEXIP]
            self.field[F_GATEWAY] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            __hexip = self.field[F_MASK_HEXIP]
            self.field[F_NETMASK] = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(__hexip,16)))))

            self.interface = self.field[F_INTERFACE]
            self.destination = self.field[F_DEST_IP]
            self.gateway = self.field[F_GATEWAY]
            self.netmask = self.field[F_NETMASK]

        return( self.interface, self.destination, self.gateway, self.netmask)



class ProcNetDEV:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/dev", 17, "face")

    def __iter__(self):
        return(self)

    def next(self):

# -- Samples lines.
# Inter-|   Receive                                                |  Transmit
#  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
#     lo: 102519022  306837    0    0    0     0          0         0 102519022  306837    0    0    0     0       0          0
#   eth0: 1618664727 5080413    0    0    0     0          0    312848 915217483 4396111    0    0    0     0       0          0

        self.__sio.read_line(self)

        if self.buff == "":
            self.device = ANY_INTERFACE
            self.rx_packets = 0
            self.rx_errors = 0
            self.tx_packets = 0
            self.tx_errors = 0

            self.field = dict()

            self.field[F_DEVICE] = ANY_INTERFACE
            self.field[F_RX_BYTES] = 0
            self.field[F_RX_PACKETS] = 0
            self.field[F_RX_ERRORS] = 0
            self.field[F_RX_DROP] =0
            self.field[F_RX_FIFO] = 0
            self.field[F_RX_FRAME] = 0
            self.field[F_RX_COMPRESSED] = 0
            self.field[F_RX_MULTICAST] = 0
            self.field[F_TX_BYTES] = 0
            self.field[F_TX_PACKETS] = 0
            self.field[F_TX_ERRORS] = 0
            self.field[F_TX_DROP] = 0
            self.field[F_TX_FIFO] = 0
            self.field[F_TX_COLLISION] = 0 
            self.field[F_TX_CARRIER] = 0
            self.field[F_TX_COMPRESSED] = 0

        else:
            __dev = self.lineparts[0]
            if __dev[-1:] == ":":
                __dev = __dev[:-1]
            self.field[F_DEVICE] = __dev
            self.field[F_RX_BYTES] = long(self.lineparts[1])
            self.field[F_RX_PACKETS] = long(self.lineparts[2])
            self.field[F_RX_ERRORS] = long(self.lineparts[3])
            self.field[F_RX_DROP] = long(self.lineparts[4])
            self.field[F_RX_FIFO] = long(self.lineparts[5])
            self.field[F_RX_FRAME] = long(self.lineparts[6])
            self.field[F_RX_COMPRESSED] = long(self.lineparts[7])
            self.field[F_RX_MULTICAST] = long(self.lineparts[8])
            self.field[F_TX_BYTES] = long(self.lineparts[9])
            self.field[F_TX_PACKETS] = long(self.lineparts[10])
            self.field[F_TX_ERRORS] = long(self.lineparts[11])
            self.field[F_TX_DROP] = long(self.lineparts[12])
            self.field[F_TX_FIFO] = long(self.lineparts[13])
            self.field[F_TX_COLLISION] = long(self.lineparts[14])
            self.field[F_TX_CARRIER] = long(self.lineparts[15])
            self.field[F_TX_COMPRESSED] = long(self.lineparts[16])

            self.device = self.field[F_DEVICE]
            self.rx_packets = self.field[F_RX_PACKETS]
            self.rx_errors = self.field[F_RX_ERRORS]
            self.tx_packets = self.field[F_TX_PACKETS]
            self.tx_errors = self.field[F_TX_ERRORS]

        return( self.device, self.rx_packets, self.rx_errors, self.tx_packets, self.tx_errors)



class ProcNetARP:
    """Pull records from /proc/net/arp"""
# DCHK: 11/16/12
# source: net/ipv4/arp.c
#        seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
#                   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/arp", 6, "IP")

    def __iter__(self):
        return(self)

    def next(self):

# -- Samples lines.
# IP address       HW type     Flags       HW address            Mask     Device
# 192.168.1.13     0x1         0x2         00:1f:c6:3b:8c:b8     *        eth0
# 192.168.1.252    0x1         0x2         70:56:81:96:ba:a7     *        eth0
# 192.168.1.178    0x1         0x2         3c:07:54:57:bb:a5     *        eth0

        self.__sio.read_line(self)

        if self.buff == "":
            self.ip_addr = ANY_IP_ADDR
            self.hw_addr = ANY_HW_ADDR
            self.device = ANY_INTERFACE

            self.field = dict()

            self.field[F_IP_ADDRESS] = ANY_IP_ADDR
            self.field[F_HW_TYPE] = "0x0"
            self.field[F_FLAGS] = "0x0"
            self.field[F_HW_ADDRESS] = ANY_HW_ADDR
            self.field[F_MASK] = "*"
            self.field[F_DEVICE] = ANY_INTERFACE

        else:
            self.field[F_IP_ADDRESS] = self.lineparts[0]
            self.field[F_HW_TYPE] = long(self.lineparts[1],16)
            self.field[F_FLAGS] = long(self.lineparts[2],16)
            self.field[F_HW_ADDRESS] = self.lineparts[3]
            self.field[F_MASK] = self.lineparts[4]
            self.field[F_DEVICE] = self.lineparts[5]

            self.ip_addr = self.field[F_IP_ADDRESS]
            self.hw_addr = self.field[F_HW_TYPE]
            self.device = self.field[F_DEVICE]

        return( self.ip_addr, self.hw_addr, self.device)



class ProcNetUDP6:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/udp6", 12, "sl")
        self.__FieldSplitDelim = ":"
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
# 1224: 000080FE00000000FF0060CA86E401FE:BBF1 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   500        0 4893942 2 0000000000000000 0
# 2316: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1994 2 0000000000000000 0
# 2777: 00000000000000000000000000000000:0202 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1899 2 0000000000000000 0

        self.__sio.read_line(self)

        if self.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[F_ORIG_HEXPORT] = "0000"
            self.field[F_DEST_HEXPORT] = "0000"
            self.field[F_ORIG_IP] = "::0"
            self.field[F_DEST_IP] = "::0"
            self.field[F_ORIG_PORT] = 0
            self.field[F_DEST_PORT] = 0
            self.field[F_HEXSTATE] = "00"
            self.field[F_STATE] = unknown_state
            self.field[F_TXQUEUE] = 0
            self.field[F_RXQUEUE] = 0
            self.field[F_TIMER] = 0
            self.field[F_TIMER_WHEN] = 0
            self.field[F_RETRANS] = 0
            self.field[F_UID] =0
            self.field[F_TIMEOUT] = 0
            self.field[F_INODE] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_POINTER] = 0
            self.field[F_DROPS] = 0

        else:
            self.orig_hexip = str(self.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(self.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(self.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(self.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = self.ipconv.ipv6_hexstring_to_presentation(self.orig_hexip)
            self.dest_ip = self.ipconv.ipv6_hexstring_to_presentation(self.dest_hexip)

            self.orig_port = long(self.lineparts[1].partition(self.__FieldSplitDelim)[2],16)
            self.dest_port = long(self.lineparts[2].partition(self.__FieldSplitDelim)[2],16)

            if self.lineparts[3] in state_list:
                self.state = state_list[self.lineparts[3]]
            else:
                self.state = unknown_state

            self.field[F_ORIG_HEXIP] = self.orig_hexip
            self.field[F_DEST_HEXIP] = self.dest_hexip
            self.field[F_ORIG_HEXPORT] = self.orig_hexport
            self.field[F_DEST_HEXPORT] = self.dest_hexport
            self.field[F_ORIG_IP] = self.orig_ip
            self.field[F_DEST_IP] = self.dest_ip
            self.field[F_ORIG_PORT] = self.orig_port
            self.field[F_DEST_PORT] = self.dest_port
            self.field[F_HEXSTATE] = str(self.lineparts[3])
            self.field[F_STATE] = self.state
            self.field[F_TXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_RXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_TIMER] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_TIMER_WHEN] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_RETRANS] = long(self.lineparts[6],16)
            self.field[F_UID] = long(self.lineparts[7])
            self.field[F_TIMEOUT] = long(self.lineparts[8])
            self.field[F_INODE] = long(self.lineparts[9])
            self.field[F_REFCOUNT] = long(self.lineparts[10])
            self.field[F_POINTER] = long(self.lineparts[11],16)
            self.field[F_DROPS] = long(self.lineparts[12])

#        print "dbg::(" + self.buff[:-1] + ")"
        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)


class ProcNetUDP:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/udp", 12, "sl")
        self.__FieldSplitDelim = ":"

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops        
# %5d : %08X:%04X     %08X:%04X    %02X %08X:%08X        %02X:%08lX  %08X       %5d      %8d %lu  %d %pK              %d
# 2316: 0E01A8C0:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 15487 2 0000000000000000 0
# 2316: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   118        0 1999 2 0000000000000000 0
# 2777: 00000000:0202 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1898 2 0000000000000000 0

        self.__sio.read_line(self)

        if self.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[F_ORIG_HEXIP] = "00000000"
            self.field[F_DEST_HEXIP] = "00000000"
            self.field[F_ORIG_HEXPORT] = "0000"
            self.field[F_DEST_HEXPORT] = "0000"
            self.field[F_ORIG_IP] = "0.0.0.0"
            self.field[F_DEST_IP] = "0.0.0.0"
            self.field[F_ORIG_PORT] = 0
            self.field[F_DEST_PORT] = 0
            self.field[F_HEXSTATE] = "00"
            self.field[F_STATE] = unknown_state
            self.field[F_TXQUEUE] = 0
            self.field[F_RXQUEUE] = 0
            self.field[F_TIMER] = 0
            self.field[F_TIMER_WHEN] = 0
            self.field[F_RETRANS] = 0
            self.field[F_UID] =0
            self.field[F_TIMEOUT] = 0
            self.field[F_INODE] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_POINTER] = 0
            self.field[F_DROPS] = 0

        else:
            self.orig_hexip = str(self.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(self.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(self.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(self.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.orig_hexip,16)))))
            self.dest_ip = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.dest_hexip,16)))))

            self.orig_port = long(self.lineparts[1].partition(self.__FieldSplitDelim)[2],16)
            self.dest_port = long(self.lineparts[2].partition(self.__FieldSplitDelim)[2],16)

            if self.lineparts[3] in state_list:
                self.state = state_list[self.lineparts[3]]
            else:
                self.state = unknown_state

            self.field[F_ORIG_HEXIP] = self.orig_hexip
            self.field[F_DEST_HEXIP] = self.dest_hexip
            self.field[F_ORIG_HEXPORT] = self.orig_hexport
            self.field[F_DEST_HEXPORT] = self.dest_hexport
            self.field[F_ORIG_IP] = self.orig_ip
            self.field[F_DEST_IP] = self.dest_ip
            self.field[F_ORIG_PORT] = self.orig_port
            self.field[F_DEST_PORT] = self.dest_port
            self.field[F_HEXSTATE] = str(self.lineparts[3])
            self.field[F_STATE] = self.state
            self.field[F_TXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_RXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_TIMER] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_TIMER_WHEN] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_RETRANS] = long(self.lineparts[6],16)
            self.field[F_UID] = long(self.lineparts[7])
            self.field[F_TIMEOUT] = long(self.lineparts[8])
            self.field[F_INODE] = long(self.lineparts[9])
            self.field[F_REFCOUNT] = long(self.lineparts[10])
            self.field[F_POINTER] = long(self.lineparts[11],16)
            self.field[F_DROPS] = long(self.lineparts[12])


#        print "dbg::(" + self.buff[:-1] + ")"
        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)


class ProcNetTCP:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/tcp", 12, "sl")
        self.__FieldSplitDelim = ":"

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
#  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
#   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 8633 1 0000000000000000 100 0 0 10 -1                     
#   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24865 1 0000000000000000 100 0 0 10 -1                    
#   2: 00000000:4E70 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 69682 1 0000000000000000 100 0 0 10 -1                    
#   3: 0E01A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 15488 1 0000000000000000 100 0 0 10 -1                    

        self.__sio.read_line(self)

        if self.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[F_ORIG_HEXIP] = "00000000"
            self.field[F_DEST_HEXIP] = "00000000"
            self.field[F_ORIG_HEXPORT] = "0000"
            self.field[F_DEST_HEXPORT] = "0000"
            self.field[F_ORIG_IP] = "0.0.0.0"
            self.field[F_DEST_IP] = "0.0.0.0"
            self.field[F_ORIG_PORT] = 0
            self.field[F_DEST_PORT] = 0
            self.field[F_HEXSTATE] = "00"
            self.field[F_STATE] = unknown_state
            self.field[F_TXQUEUE] = 0
            self.field[F_RXQUEUE] = 0
            self.field[F_TIMER] = 0
            self.field[F_TIMER_WHEN] = 0
            self.field[F_RETRANS] = 0
            self.field[F_UID] =0
            self.field[F_TIMEOUT] = 0
            self.field[F_INODE] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_POINTER] = 0
            self.field[F_RETRY_TIMEOUT] = 0
            self.field[F_ACK_TIMEOUT] = 0
            self.field[F_QUICK_OR_PPONG] = 0
            self.field[F_CONGEST_WINDOW] = 0
            self.field[F_SSTART_THRESH] = 0

        else:
            self.orig_hexip = str(self.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(self.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(self.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(self.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.orig_hexip,16)))))
            self.dest_ip = socket.inet_ntop(socket.AF_INET,binascii.unhexlify('{0:08x}'.format(socket.htonl(long(self.dest_hexip,16)))))

            self.orig_port = long(self.lineparts[1].partition(self.__FieldSplitDelim)[2],16)
            self.dest_port = long(self.lineparts[2].partition(self.__FieldSplitDelim)[2],16)

            if self.lineparts[3] in state_list:
                self.state = state_list[self.lineparts[3]]
            else:
                self.state = unknown_state

            self.field[F_ORIG_HEXIP] = self.orig_hexip
            self.field[F_DEST_HEXIP] = self.dest_hexip
            self.field[F_ORIG_HEXPORT] = self.orig_hexport
            self.field[F_DEST_HEXPORT] = self.dest_hexport
            self.field[F_ORIG_IP] = self.orig_ip
            self.field[F_DEST_IP] = self.dest_ip
            self.field[F_ORIG_PORT] = self.orig_port
            self.field[F_DEST_PORT] = self.dest_port
            self.field[F_HEXSTATE] = str(self.lineparts[3])
            self.field[F_STATE] = self.state
            self.field[F_TXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_RXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_TIMER] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_TIMER_WHEN] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_RETRANS] = long(self.lineparts[6],16)
            self.field[F_UID] = long(self.lineparts[7])
            self.field[F_TIMEOUT] = long(self.lineparts[8])
            self.field[F_INODE] = long(self.lineparts[9])
            self.field[F_REFCOUNT] = long(self.lineparts[10])
            self.field[F_POINTER] = long(self.lineparts[11],16)

            if self.linewords == 17:
                self.field[F_RETRY_TIMEOUT] = long(self.lineparts[12])
                self.field[F_ACK_TIMEOUT] = long(self.lineparts[13])
                self.field[F_QUICK_OR_PPONG] = long(self.lineparts[14])
                self.field[F_CONGEST_WINDOW] = long(self.lineparts[15])
                self.field[F_SSTART_THRESH] = long(self.lineparts[16])

#        print "dbg::(" + self.buff[:-1] + ")"
        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)

class ProcNetTCP6:
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

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/tcp6", 12, "sl")
        self.__FieldSplitDelim = ":"
        self.ipconv = IPAddressConv()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
#  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
#   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   118        0 1995 1 0000000000000000 100 0 0 2 -1
#   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1892 1 0000000000000000 100 0 0 2 -1

        self.__sio.read_line(self)

        if self.buff == "":
            self.orig_hexip = self.dest_hexip = self.orig_ip = self.dest_ip = self.state = ""
            self.orig_port = self.dest_port = 0

            self.field = dict()
            self.field[F_ORIG_HEXIP] = "00000000000000000000000000000000"
            self.field[F_DEST_HEXIP] = "00000000000000000000000000000000"
            self.field[F_ORIG_HEXPORT] = "0000"
            self.field[F_DEST_HEXPORT] = "0000"
            self.field[F_ORIG_IP] = "::0"
            self.field[F_DEST_IP] = "::0"
            self.field[F_ORIG_PORT] = 0
            self.field[F_DEST_PORT] = 0
            self.field[F_HEXSTATE] = "00"
            self.field[F_STATE] = unknown_state
            self.field[F_TXQUEUE] = 0
            self.field[F_RXQUEUE] = 0
            self.field[F_TIMER] = 0
            self.field[F_TIMER_WHEN] = 0
            self.field[F_RETRANS] = 0
            self.field[F_UID] =0
            self.field[F_TIMEOUT] = 0
            self.field[F_INODE] = 0
            self.field[F_REFCOUNT] = 0
            self.field[F_POINTER] = 0
            self.field[F_RETRY_TIMEOUT] = 0
            self.field[F_ACK_TIMEOUT] = 0
            self.field[F_QUICK_OR_PPONG] = 0
            self.field[F_CONGEST_WINDOW] = 0
            self.field[F_SSTART_THRESH] = 0

        else:
            self.orig_hexip = str(self.lineparts[1].partition(self.__FieldSplitDelim)[0])
            self.dest_hexip = str(self.lineparts[2].partition(self.__FieldSplitDelim)[0])

            self.orig_hexport = str(self.lineparts[1].partition(self.__FieldSplitDelim)[2])
            self.dest_hexport = str(self.lineparts[2].partition(self.__FieldSplitDelim)[2])

            self.orig_ip = self.ipconv.ipv6_hexstring_to_presentation(self.orig_hexip)
            self.dest_ip = self.ipconv.ipv6_hexstring_to_presentation(self.dest_hexip)

            self.orig_port = long(self.lineparts[1].partition(self.__FieldSplitDelim)[2],16)
            self.dest_port = long(self.lineparts[2].partition(self.__FieldSplitDelim)[2],16)

            if self.lineparts[3] in state_list:
                self.state = state_list[self.lineparts[3]]
            else:
                self.state = unknown_state

            self.field[F_ORIG_HEXIP] = self.orig_hexip
            self.field[F_DEST_HEXIP] = self.dest_hexip
            self.field[F_ORIG_HEXPORT] = self.orig_hexport
            self.field[F_DEST_HEXPORT] = self.dest_hexport
            self.field[F_ORIG_IP] = self.orig_ip
            self.field[F_DEST_IP] = self.dest_ip
            self.field[F_ORIG_PORT] = self.orig_port
            self.field[F_DEST_PORT] = self.dest_port
            self.field[F_HEXSTATE] = str(self.lineparts[3])
            self.field[F_STATE] = self.state
            self.field[F_TXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_RXQUEUE] = long(self.lineparts[4].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_TIMER] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[0],16)
            self.field[F_TIMER_WHEN] = long(self.lineparts[5].partition(self.__FieldSplitDelim)[2],16)
            self.field[F_RETRANS] = long(self.lineparts[6],16)
            self.field[F_UID] = long(self.lineparts[7])
            self.field[F_TIMEOUT] = long(self.lineparts[8])
            self.field[F_INODE] = long(self.lineparts[9])
            self.field[F_REFCOUNT] = long(self.lineparts[10])
            self.field[F_POINTER] = long(self.lineparts[11],16)

            if self.linewords == 17:
                self.field[F_RETRY_TIMEOUT] = long(self.lineparts[12])
                self.field[F_ACK_TIMEOUT] = long(self.lineparts[13])
                self.field[F_QUICK_OR_PPONG] = long(self.lineparts[14])
                self.field[F_CONGEST_WINDOW] = long(self.lineparts[15])
                self.field[F_SSTART_THRESH] = long(self.lineparts[16])

#        print "dbg::(" + self.buff[:-1] + ")"
        return( self.orig_hexip, self.dest_hexip, self.orig_ip, self.orig_port, self.dest_ip, self.dest_port, self.state)

class ProcNetSOCKSTAT:
    """Abstraction layer to pull records from /proc/net/sockstat"""
# DCHK: ...
# source: ...
# Note: ...
#

    def __init__(self):
        self.field = dict()
        self.__sio = SeqFileIO()
        self.__sio.open_file(self, "/proc/net/sockstat", 1)
        self.__sock_type_list = ([ F_SOCK_TCP, F_SOCK_UDP, F_SOCK_UDPLITE, F_SOCK_RAW, F_SOCK_FRAG, F_SOCK_SOCKETS ])
        self.__sock_type = ""
        self.__result = set()

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
# TCP: inuse 26 orphan 0 tw 1 alloc 30 mem 2
# UDP: inuse 3 mem 3
# UDPLITE: inuse 0
# RAW: inuse 0
# FRAG: inuse 0 memory 0

        if not self.open:
            raise StopIteration

        try:
            while self.__sio.read_line(self):
                self.__sock_type = str(self.lineparts[0])
                if self.__sock_type in self.__sock_type_list:
                    self.__result.add(self.__sock_type)
                    self.field[self.__sock_type] = self.__sio.pair_list_to_dictionary(self.buff, 2)
        except StopIteration:
            self.open = 0;

        if self.__sock_type == "":
            self.__result = set()
            self.field = dict()
            self.field[F_SOCK_TCP] = dict()
            self.field[F_SOCK_UDP] = dict()
            self.field[F_SOCK_UDPLITE] = dict()
            self.field[F_SOCK_RAW] = dict()
            self.field[F_SOCK_FRAG] = dict()

        return( self.__result)
	

class IPAddressConv:
    """Utlities for converting IP address to/from various formats."""

    def __init__(self):
        self.__DelimIPV6 = ":"

    def ipv6_hexdelimited_to_presentation(self, hexdelim):
        return socket.inet_ntop(socket.AF_INET6,socket.inet_pton(socket.AF_INET6,hexdelim))

    def ipv6_hexstring_to_presentation(self, hexip):
        __pres = socket.inet_ntop(socket.AF_INET6,socket.inet_pton(socket.AF_INET6,self.ipv6_hexstring_to_hexdelimited(hexip)))
        if __pres == ANY_IPV6_ADDR:
            __pres = PRESENT_ANY_IPV6_ADDR
        return __pres

    def ipv6_hexstring_to_hexdelimited(self, hexip):
        __delim = hexip[0:4]
        for __off in range(4,len(hexip),4):
            __delim = __delim + self.__DelimIPV6 + hexip[__off:__off+4]
        return __delim


class SeqFileIO:
    """Utility routines to handle I/O to proc file system files"""

    def __init__(self):
        pass


    def open_file(self, proc_file_session, file, *options):
        try:
            proc_file_session.pnt_fd = open( file)
            proc_file_session.open = 1
        except IOError:
            proc_file_session.open = 0

        if len(options) > 0:
           proc_file_session.MinWords = options[0]
           if len(options) > 1:
               proc_file_session.SkipLine = options[1]


    def read_line(self, proc_file_session):

        if proc_file_session.open == 0:
            proc_file_session.buff = ""
            raise StopIteration

	else:
            proc_file_session.buff = proc_file_session.pnt_fd.readline()

            try:
               __MinWords = proc_file_session.MinWords
            except AttributeError:
               __MinWords = 0

            try:
               __SkipLine = proc_file_session.SkipLine 
            except AttributeError:
               __SkipLine = ""

            if proc_file_session.buff == "":
                proc_file_session.pnt_fd.close()
                proc_file_session.open = 0
                raise StopIteration

            else:
                proc_file_session.lineparts = proc_file_session.buff.split()
                proc_file_session.linewords = len(proc_file_session.lineparts)
                if proc_file_session.linewords < __MinWords:
                    self.read_line(proc_file_session)
                elif __SkipLine != "":
                    if proc_file_session.lineparts[0] == __SkipLine:
                        self.read_line(proc_file_session)

	return(proc_file_session.open)


    def read_all_lines(self, proc_file_session):

        __lines = ()

        if proc_file_session.open != 0:
            __lines = proc_file_session.pnt_fd.readlines()

            try:
               __SkipPref = proc_file_session.SkipLine 
            except AttributeError:
               __SkipPref = ""

            if __lines != "":
                __SkipPrefLen = len(__SkipPref) + 1

                for __off in range(len(__lines)-1,-1,-1):
                    if __lines[__off][-1:] == "\n":
                        __lines[__off] = __lines[__off][:-1]
                    if __SkipPrefLen > 1:
                        if __lines[__off][1:__SkipPrefLen] == __SkipPref:
                            __lines[__off:__off+1] = []

        return __lines


    def pair_list_to_dictionary(self, line, start_pos):

        __pairs = dict()

        __word_list = line.split()
        __word_count = len(__word_list)

        for __key_pos in range(start_pos - 1, __word_count, 2):
            __pairs[__word_list[__key_pos]] = __word_list[__key_pos+1]

        return __pairs
        

class CachedDNS:
    """Map IP's to hostnames using local cache where possible, using lookups otherwise"""

    def __init__(self):
        self.__hostname_cache = dict()
        self.__DEF_HOSTNAME = "-unknown-"
        self.__hostname_cache["0.0.0.0"] = self.__DEF_HOSTNAME


    def get_cached_hostname(self, ip):

        if ip in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip]
        else:
            try:
                (__ip2host, __ip2alias, __ip2iplist) = socket.gethostbyaddr( ip)
            except (socket.error, socket.herror, socket.timeout):
                __ip2host = ""

            if __ip2host == "":
                __ip2host = self.__DEF_HOSTNAME
            self.__hostname_cache[ip] = __ip2host

        return __ip2host

    def get_cache_entry(self, ip):

        if ip in self.__hostname_cache:
            __ip2host = self.__hostname_cache[ip]
        else:
            __ip2host = self.__DEF_HOSTNAME

        return __ip2host

    
class ProcessInfo:

    def __init__(self):
        self.__NO_CONN_PID = -1
        self.__NO_PROCESS_SUMMARY = "n/a"
        self.__ps_returncode = None

    def map_connection_to_PID(self, loc_port, rem_ip, rem_port, net_protocol):
        __rip = rem_ip
        if __rip == ANY_IPV6_ADDR or __rip == ANY_IP_ADDR or __rip == PRESENT_ANY_IPV6_ADDR or __rip == PRESENT_ANY_IP_ADDR:
           __rip = ""

        __rpo = str(rem_port)
        if __rpo == "0":
           __rpo = ""

        __prot = net_protocol
        if __prot == "udp6" or __prot == "tcp6":
           __prot = __prot[:-1]
           __ipv = "-6"
        else:
           __ipv = "-4"

        __fuser_arg = "{0:d},{1:s},{2:s}/{3:s}".format( loc_port, __rip, __rpo, __prot)
#        print '::dbg', __prot, __fuser_arg, __ipv


        try:
            __fufd = Popen( ["fuser", __fuser_arg, __ipv], stdout=PIPE, stderr=PIPE)

            __sout_buff, __serr_buff = __fufd.communicate()
#            print '::dbg ({0:s})'.format(__sout_buff)
            if __sout_buff != "":
                __pid = long( __sout_buff.split()[0], 10)
            else:
                __pid = self.__NO_CONN_PID

        except:
            __pid = self.__NO_CONN_PID

        return __pid

    def map_PID_to_process_summary(self, pid):
        __psumm = self.__NO_PROCESS_SUMMARY
        self.__ps_retcode = None

        if pid != self.__NO_CONN_PID:
            __ps_arg = "{0:d}".format(pid)
            try:
                __ps_fd = Popen( ["ps", "--no-headers", "-o", "user,pid,cmd", "-p", __ps_arg], stdout=PIPE, stderr=PIPE)

                __sout_buff, __serr_buff = __ps_fd.communicate()
                if __sout_buff != "":
                    __psumm = __sout_buff[:-1]

            except:
                self.__ps_returncode = __ps_fd.returncode

        return __psumm
 

    def get_PID_err_value(self):
        return self.__NO_CONN_PID

    def get_process_summary_err_value(self):
        return self.__NO_PROCESS_SUMMARY

    def get_ps_returncode(self):
        return self.__ps_returncode


if __name__ == "__main__":

    __sep = "-----------------------------------------------------------------------"

    if len(sys.argv) > 1:
        which = sys.argv[1]
    else:
        which = "conn"

    if len(sys.argv) > 2:
        qualify = sys.argv[2]
    else:
        qualify = ""

    iplookup = CachedDNS()
    procinfo = ProcessInfo()

    NO_SESSION_PID = procinfo.get_PID_err_value()
    NO_PROCESS_SUMMARY = procinfo.get_process_summary_err_value()

    if which == "all" or which == "conn" or which == "udp6":
        if which == "all":
            print __sep, "udp6"

        socklist = ProcNetUDP6()

        for parse_slist in socklist:

            orig_hexip = socklist.field[F_ORIG_HEXIP]
            dest_hexip = socklist.field[F_DEST_HEXIP]
            orig_ip = socklist.field[F_ORIG_IP]
            dest_ip = socklist.field[F_DEST_IP]
            orig_port = socklist.field[F_ORIG_PORT]
            dest_port = socklist.field[F_DEST_PORT]
            sock_stat = socklist.field[F_STATE]

            dest_host = iplookup.get_cached_hostname(dest_ip)
            pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "udp6")
            psumm = procinfo.map_PID_to_process_summary(pid)

            print "udp6 {0:s} {1:s}:{2:d} -> {3:s}:{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm)

    if which == "all" or which == "conn" or which == "udp":
        if which == "all":
            print __sep, "udp"

        socklist = ProcNetUDP()

        for parse_slist in socklist:

            orig_hexip = socklist.field[F_ORIG_HEXIP]
            dest_hexip = socklist.field[F_DEST_HEXIP]
            orig_ip = socklist.field[F_ORIG_IP]
            dest_ip = socklist.field[F_DEST_IP]
            orig_port = socklist.field[F_ORIG_PORT]
            dest_port = socklist.field[F_DEST_PORT]
            sock_stat = socklist.field[F_STATE]

            dest_host = iplookup.get_cached_hostname(dest_ip)
            pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "udp")
            psumm = procinfo.map_PID_to_process_summary(pid)

            print "udp {0:s} {1:s}:{2:d} -> {3:s}:{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm)

    if which == "all" or which == "conn" or which == "tcp6":
        if which == "all":
            print __sep, "tcp6"

        socklist = ProcNetTCP6()

        for parse_slist in socklist:

            orig_hexip = socklist.field[F_ORIG_HEXIP]
            dest_hexip = socklist.field[F_DEST_HEXIP]
            orig_ip = socklist.field[F_ORIG_IP]
            dest_ip = socklist.field[F_DEST_IP]
            orig_port = socklist.field[F_ORIG_PORT]
            dest_port = socklist.field[F_DEST_PORT]
            sock_stat = socklist.field[F_STATE]

            dest_host = iplookup.get_cached_hostname(dest_ip)
            pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp6")
            psumm = procinfo.map_PID_to_process_summary(pid)

            print "tcp6 {0:s} {1:s}:{2:d} -> {3:s}:{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm)

    if which == "all" or which == "conn" or which == "tcp":
        if which == "all":
            print __sep, "tcp"

        socklist = ProcNetTCP()

        for parse_slist in socklist:

            orig_hexip = socklist.field[F_ORIG_HEXIP]
            dest_hexip = socklist.field[F_DEST_HEXIP]
            orig_ip = socklist.field[F_ORIG_IP]
            dest_ip = socklist.field[F_DEST_IP]
            orig_port = socklist.field[F_ORIG_PORT]
            dest_port = socklist.field[F_DEST_PORT]
            sock_stat = socklist.field[F_STATE]

            dest_host = iplookup.get_cached_hostname(dest_ip)
            pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp")
            psumm = procinfo.map_PID_to_process_summary(pid)

            print "tcp {0:s} {1:s}/{2:d} -> {3:s}/{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm)

    if which == "all" or which == "arp":
        if which == "all":
            print __sep, "arp"

        arp = ProcNetARP()

        for list in arp:
            print list

    if which == "all" or which == "dev":
        if which == "all":
            print __sep, "dev"

        dev = ProcNetDEV()

        for list in dev:
            print list

    if which == "all" or which == "route":
        if which == "all":
            print __sep, "route"

        route = ProcNetROUTE()

        for list in route:
            print list

    if which == "all" or which == "rt_cache":
        if which == "all":
            print __sep, "rt_cache"

        rtc = ProcNetRT_CACHE()

        for list in rtc:
            print list

    if which == "all" or which == "stat/arp_cache":
        if which == "all":
            print __sep, "stat/arp_cache"

        sac = ProcNetStatARP_CACHE()

        for list in sac:
            print list


    if which == "all" or which == "stat/ip_conntrack":
        if which == "all":
            print __sep, "stat/ip_conntrack"

        sic = ProcNetStatIP_CONNTRACK()

        for list in sic:
            print list


    if which == "all" or which == "stat/nf_conntrack":
        if which == "all":
            print __sep, "stat/nf_conntrack"

        snc = ProcNetStatNF_CONNTRACK()

        for list in snc:
            print list


    if which == "all" or which == "stat/ndisc_cache":
        if which == "all":
            print __sep, "stat/ndisc_cache"

        snc = ProcNetStatNDISC_CACHE()

        for list in snc:
            print list


    if which == "all" or which == "stat/rt_cache":
        if which == "all":
            print __sep, "stat/rt_cache"

        snc = ProcNetStatRT_CACHE()

        for list in snc:
            print list


    if which == "all" or which == "unix":
        if which == "all":
            print __sep, "unix"

        snc = ProcNetUNIX()

        for list in snc:
            print list


    if which == "all" or which == "if_inet6":
        if which == "all":
            print __sep, "if_inet6"

        snc = ProcNetIF_INET6()

        for list in snc:
            print list


    if which == "all" or which == "dev_mcast":
        if which == "all":
            print __sep, "dev_mcast"

        snc = ProcNetDEV_MCAST()

        for list in snc:
            print list


    if which == "all" or which == "igmp6":
        if which == "all":
            print __sep, "igmp6"

        snc = ProcNetIGMP6()

        for list in snc:
            print list


    if which == "all" or which == "ipv6_route":
        if which == "all":
            print __sep, "ipv6_route"

        snc = ProcNetIPV6_ROUTE()

        for list in snc:
            print list


    if which == "all" or which == "psched":
        if which == "all":
            print __sep, "psched"

        snc = ProcNetPSCHED()

        for list in snc:
            print list


    if which == "all" or which == "rt6_stats":
        if which == "all":
            print __sep, "rt6_stats"

        snc = ProcNetRT6_STATS()

        for list in snc:
            print list


    if which == "all" or which == "softnet_stat":
        if which == "all":
            print __sep, "softnet_stat"

        snc = ProcNetSOFTNET_STAT()

        for list in snc:
            print list


    if which == "all" or which == "protocols":
        if which == "all":
            print __sep, "protocols"

        snc = ProcNetPROTOCOLS()

        for list in snc:
            print list


    if which == "all" or which == "packet":
        if which == "all":
            print __sep, "packet"

        snc = ProcNetPACKET()

        for list in snc:
            print list


    if which == "all" or which == "connector":
        if which == "all":
            print __sep, "connector"

        snc = ProcNetCONNECTOR()

        for list in snc:
            print list


    if which == "all" or which == "netlink":
        if which == "all":
            print __sep, "netlink"

        snc = ProcNetNETLINK()

        for list in snc:
            print list


    if which == "all" or which == "netfilter/nf_log":
        if which == "all":
            print __sep, "netfilter/nf_log"

        snc = ProcNetNetfilterNF_LOG()

        for list in snc:
            print list


    if which == "all" or which == "netfilter/nf_queue":
        if which == "all":
            print __sep, "netfilter/nf_queue"

        snc = ProcNetNetfilterNF_QUEUE()

        for list in snc:
            print list


    if which == "all" or which == "igmp":
        if which == "all":
            print __sep, "igmp"

        snc = ProcNetIGMP()

        for list in snc:
            print list
            print snc.field


    if which == "all" or which == "ip6_tables_matches":
        if which == "all":
            print __sep, "ip6_tables_matches"

        snc = ProcNetIP6_TABLES_MATCHES()

        for list in snc:
            print list


    if which == "all" or which == "ip6_tables_names":
        if which == "all":
            print __sep, "ip6_tables_names"

        snc = ProcNetIP6_TABLES_NAMES()

        for list in snc:
            print list


    if which == "all" or which == "ip6_tables_targets":
        if which == "all":
            print __sep, "ip6_tables_targets"

        snc = ProcNetIP6_TABLES_TARGETS()

        for list in snc:
            print list


    if which == "all" or which == "ip_tables_matches":
        if which == "all":
            print __sep, "ip_tables_matches"

        snc = ProcNetIP_TABLES_MATCHES()

        for list in snc:
            print list


    if which == "all" or which == "ip_tables_names":
        if which == "all":
            print __sep, "ip_tables_names"

        snc = ProcNetIP_TABLES_NAMES()

        for list in snc:
            print list


    if which == "all" or which == "ip_tables_targets":
        if which == "all":
            print __sep, "ip_tables_targets"

        snc = ProcNetIP_TABLES_TARGETS()

        for list in snc:
            print list


    if which == "all" or which == "ip_conntrack":
        if which == "all":
            print __sep, "ip_conntrack"

        snc = ProcNetIP_CONNTRACK()

        for list in snc:
            print list
#            print snc.field


    if which == "all" or which == "nf_conntrack":
        if which == "all":
            print __sep, "nf_conntrack"

        snc = ProcNetNF_CONNTRACK()

        for list in snc:
            print list
#            print snc.field


    if which == "all" or which == "snmp6":
        if which == "all":
            print __sep, "snmp6"

        snc = ProcNetSNMP6()

        for keyvals in snc:
            for key in keyvals:
                print "{0:s} {1:s}".format(key,keyvals[key])


    if which == "all" or which == "dev_snmp6":
        print __sep, "dev_snmp6", qualify

        snc = ProcNetDEV_SNMP6(qualify)

        for keyvals in snc:
            for key in keyvals:
                print "{0:s} {1:s}".format(key,keyvals[key])


    if which == "all" or which == "sockstat":
        print __sep, "sockstat"

        pss = ProcNetSOCKSTAT()

        for socktypelist in pss:
            for socktype in socktypelist:
                print socktype
                keyvals = pss.field[socktype]
                for key in keyvals:
                    print "-- {0:s} {1:s}".format(str(key),str(keyvals[key]))
