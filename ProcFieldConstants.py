#!/usr/bin/env python
"""Field name constants shared by several modules, no code here"""

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
F_PRESSURE = "pressure"
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

# -- fields added to support "sockstat6" data
F_SOCK_TCP6 = "TCP6:"
F_SOCK_UDP6 = "UDP6:"
F_SOCK_UDPLITE6 = "UDPLITE6:"
F_SOCK_RAW6 = "RAW6:"
F_SOCK_FRAG6 = "FRAG6:"

# -- fields added to support "ptype" data
F_DEVICE_TYPE = "dev_type"
F_DEVICE_NAME = "dev_name"
F_DEVICE_FUNC = "dev_function"

# -- name used by "ip_tables_*" and "ip6_tables_*" handlers
F_TERM_LIST = "list_of_terms"

# --
F_NULL_HANDLER = "/dev/null"

# -- addition fields added for "/proc/execdomains"
F_PERSONALITY_LOW = "pers-low"
F_PERSONALITY_HIGH = "pers-high"
F_EXDOM_NAME = "exec-domain-name"
F_EXDOM_MODULE = "exec-domain-module"

# -- added for "/proc/cgroups"
F_SUBSYSTEM = "subsystem"
F_HIERARCHY = "hierarchy"
F_NUM_CGROUPS = "num-groups"
F_ENABLED = "enabled"

# -- added for "/proc/mtrr"
F_BASE_MEMORY = "base-memory-address"

# -- added for "/proc/modules"
F_SOURCE_LIST = "source-list"
F_STATUS = "status"
F_MODULE_CORE = "module-core"
F_TAINTS = "taints"

# -- added for "/proc/buddyinfo"
F_NODE = "node"
F_FRBL_AREA_1 = "area1-freebl"
F_FRBL_AREA_2 = "area2-freebl"
F_FRBL_AREA_3 = "area3-freebl"
F_FRBL_AREA_4 = "area4-freebl"
F_FRBL_AREA_5 = "area5-freebl"
F_FRBL_AREA_6 = "area6-freebl"
F_FRBL_AREA_7 = "area7-freebl"
F_FRBL_AREA_8 = "area8-freebl"
F_FRBL_AREA_9 = "area9-freebl"
F_FRBL_AREA_10 = "area10-freebl"
F_FRBL_AREA_11 = "area11-freebl"

# -- added for "/proc/swaps"
F_FILENAME = "filename"
F_USED = "used"
F_PRIORITY = "priority"

# -- added for "/proc/locks"
F_LOCK_TYPE = "lock-type"
F_LOCK_SUBTYPE = "lock-subtype"
F_LOCK_IO = "lock-io-op"
F_LOCK_INODE = "inode-info"
F_START = "start-addr"
F_END = "end-addr"
F_END_STRING = "end-addr-string"

# -- added for "/proc/diskstats"
F_MAJOR_DEV = "major-dev-num"
F_MINOR_DEV = "minor-dev-num"
F_DISK_NAME = "disk-name"
F_READ_IOS = "read-ios"
F_READ_MERGES = "read-merges"
F_READ_SECTORS = "read-sectors"
F_READ_MSECS = "read-msecs"
F_WRITE_IOS = "write-ios"
F_WRITE_MERGES = "write-merges"
F_WRITE_SECTORS = "write-sectors"
F_WRITE_MSECS = "write-msecs"
F_PART_IN_FLIGHT = "part-in-flight"
F_IO_MSECS = "io-msecs"
F_QUEUE_TIME_MSECS = "queue-time-msecs"

# -- added for "/proc/vmstat"
F_CATEGORY = "category"

# -- added for "/proc/meminfo"
F_UNITS = "units"

# -- added for "/proc/partitions"
F_BLOCKS = "blocks"
F_PARTITION_NAME = "partition-name"

# -- added for "/proc/kallsyms"
F_ADDRESS = "address"
F_SYMBOL = "symbol"

# -- added for "/proc/filesystems"
F_DEV_FLAG = "requires-device"
F_FILESYSTEM = "filesystem"

# -- added for "/proc/dma"
F_CHANNEL = "channel"

# -- added for "/proc/fb"
F_ID_LIST = "id-list"

# -- added for "/proc/consoles"
F_DEVICE_NUMBER = "device-number"
F_IO_TYPE = "io-type"

# -- added for "/proc/key-users"
F_USAGE = "usage"
F_NKEYS = "num-keys"
F_NIKEYS = "num-keys-inst"
F_QNKEYS = "num-user-keys"
F_QNBYTES = "num-user-bytes"
F_MAXKEYS = "max-keys"
F_MAXBYTES = "max-bytes"

# -- added for "/proc/version_string"
F_VERSION_STRING = "version-string"

# -- added for "/proc/version"
F_SYSNAME = "sysname"
F_RELEASE = "release"
F_VERSION = "version"

# -- added for "/proc/uptime"
F_UPTIME = "uptime"
F_IDLE = "idle"

# -- added for "/proc/loadavg"
F_LOAD_AV0 = "load-average0"
F_LOAD_AV1 = "load-average1"
F_LOAD_AV2 = "load-average2"
F_NUM_TASKS = "running-tasks"
F_NUM_THREADS = "running-threads"
F_LAST_PID = "last-pid"

# -- added for "/proc/cmdline"
F_CMDLINE = "command-line"

# -- added for "/proc/slabinfo"
F_SLAB_NAME = "slab-name"
F_ACTIVE_OBJS = "active-objs"
F_NUM_OBJS = "num-objects"
F_OBJ_SIZE = "obj-size"
F_OBJ_PER_SLAB = "objs-per-slab"
F_PAGES_PER_SLAB = "pages-per-slab"
F_LIMIT = "limit"
F_BATCHCOUNT = "batchcount"
F_SHARED = "shared"
F_ACTIVE_SLABS = "active-slabs"
F_NUM_SLABS = "num-slabs"
F_SHARED_AVAIL = "shared-avail"
F_LIST_ALLOCS = "list-allocs"
F_MAX_OBJS = "max-objs"
F_GROWN = "grown"
F_REAPED = "reaped"
F_ERROR = "error"
F_MAX_FREEABLE = "max-freeable"
F_NODE_ALLOCS = "node-allocs"
F_REMOTE_FREES = "remote-frees"
F_ALIEN_OVERFLOW = "alien-overflow"
F_ALLOC_HIT = "alloc-hit"
F_ALLOC_MISS = "alloc-miss"
F_FREE_HIT = "free-hit"
F_FREE_MISS = "free-miss"

# -- added for "/proc/vmallocinfo"
F_CALLER = "caller"
F_PAGES = "pages"
F_PHYS_ADDR = "physical-address"
F_IOREMAP = "I/O-remapped"
F_VM_ALLOC = "vm-alloc"
F_VM_MAP = "vm-map"
F_USER_MAP = "user-map"
F_VM_PAGES = "vm-pages"
F_NUMA_INFO = "numa-info"

# -- added for "/proc/mdstat"
F_REC_TYPE = "rec-type"
F_DEVICE_LIST = "device-list"
F_PERSONALITIES = "personalities"
F_ACTIVE_STAT = "active-status"
F_PERS_NAME = "pers-name"
F_PARTITION_LIST = "partition-list"
F_WRMOSTLY_LIST = "wrmostly-list"
F_FAULTY_LIST = "faulty-list"
F_SPARE_LIST = "spare-list"
F_READONLY = "read-only"
F_SUPER = "super"
F_CHUNK = "chunk"
F_NEAR_COPY = "near-copy"
F_OFFSET_COPY = "offset-copy"
F_FAR_COPY = "far-copy"
F_ACTIVE_PARTS = "active-partitions"
F_TOTAL_PARTS = "total-partitions"
F_PART_USEMAP = "partition-use-map"
F_REBUILD_PROG = "rebuild-progress"
F_RESYNC_STAT = "resync-status"
F_REBUILD_ACTION = "rebuild-action"
F_PERCENT = "percent"
F_REBUILD_DONE = "rebuilt-blocks"
F_REBUILD_TOTAL = "rebuilt-total"
F_FIN_TIME = "finish-time"
F_SPEED = "speed"
F_PAGES_NOMISS = "non-miss-pages"
F_PAGES_TOTAL = "total-pages"
F_PAGES_NOMISS_KB = "non-miss-pages-kb"
F_BITMAP_CHUNK = "bitmap-chunksize"
F_FILEPATH = "filepath"
