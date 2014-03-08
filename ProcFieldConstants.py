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

# -- added for "/proc/self/limits"
F_SOFT_LIMIT = "soft-limit"
F_HARD_LIMIT = "hard-limit"

# -- added for "/proc/self/maps"
F_PAGE_OFFSET = "page-offset"

# -- added for "/proc/self/stack"
F_STACK_ENTRY = "stack-entry"

# -- added for "/proc/self/numa_maps"
F_BUFFNAME = "buffer-name"
F_HEAP = "heap"
F_STACK = "stack"
F_HUGE = "huge"
F_ANON = "anon"
F_DIRTY = "dirty"
F_MAPPED = "mapped"
F_MAPMAX = "mapmax"
F_SWAPCACHE = "swapcache"
F_ACTIVE_PAGES = "active-pages"
F_WRITEBACK = "writeback"
F_NODE_LIST = "node-list"

# -- added for "/proc/self/mountinfo"
F_MOUNT_ID = "mount-id"
F_PARENT_MOUNT_ID = "parent-mount-id"
F_MOUNT_FS = "mount-point"
F_MOUNT_REL = "relative-mount-point"
F_MOUNT_OPTS = "mount-options"
F_EXTRA_OPTS = "extra-options"
F_FS_TYPE = "filesystem"
F_MOUNT_SRC = "mount-source"
F_SUPER_OPTS = "superblock-options"

# -- added for "/proc/self/mountstats"
F_MOUNTPOINT = "mountpoint"
F_FSTYPE = "fstype"
F_STATSVERS = "stats-vers"
F_AGE = "age"
F_CAPS = "caps"
F_WTMULT = "wtmult"
F_DTSIZE = "dtsize"
F_BSIZE = "bsize"
F_NAMELEN = "namlen"
F_EVENT_LIST = "event-list"
F_BYTES_LIST = "bytes-list"
F_FSCACHE_LIST = "fscache-list"
F_FLAVOR = "flavor"
F_PSEUDOFLAVOR = "pseudoflavor"
F_ACDIRMAX = "acdirmax"
F_ACDIRMIN = "acdirman"
F_ACREGMAX = "acregmax"
F_ACREGMIN = "acregmin"
F_CLIENTADDR = "clientaddr"
F_FSCACHE = "fsc"
F_LOCKLOCAL = "local_lock"
F_LOOKUPCACHE = "lookupcache"
F_MINORVERS = "minorversion"
F_MOUNTADDR = "mountaddr"
F_MOUNTPORT = "mountport"
F_MOUNTPROTO = "mountproto"
F_MOUNT_TYPE = "mount-type"
F_MOUNTVERS = "mountvers"
F_NFSV4_ACL = "acl"
F_NFSV4_BM0 = "bm0"
F_NFSV4_BM1 = "bm1"
F_NOAC = "noac"
F_NOACL = "noacl"
F_NOATIME = "noatime"
F_NOCTO = "nocto"
F_NODIRATIME = "nodiratime"
F_NOLOCK = "nolock"
F_TIMEO = "timeo"
F_MOUNTSTATS_RETRANS = "retrans"
F_PROTO = "proto"
F_VERS = "vers"
F_NORDIRPLUS = "nodirplus"
F_NORESVPORT = "noresvport"
F_PNFS = "pnfs"
F_PORT = "port"
F_POSIX = "posix"
F_RPC_PROG = "client-prog"
F_RPC_VERS = "client-vers"
F_RSIZE = "rsize"
F_SECURITYNAME = "sec"
F_SESSIONS = "sessions"
F_SYNC = "sync"
F_UNSHARED = "nosharecache"
F_WRITE_STATUS = "write-status"
F_WSIZE = "wsize"
F_NAMLEN = "namlen"
F_IOSTATS_VERS = "iostats-vers"
F_PER_OP_STATS = "per-op-stats"
F_OM_OPS = "ops"
F_OM_NTRANS = "trans"
F_OM_TIMEOUTS = "timeouts"
F_OM_SENT = "bytes-sent"
F_OM_RECV = "bytes-recv"
F_OM_QUEUE = "queue"
F_OM_RTT = "rtt"
F_OM_EXEC = "execute"
F_XPRT_STATS = "xprt-stats"
F_XPR_BIND_COUNT = "bind-count"
F_XPR_CONN_COUNT = "conn-count"
F_XPR_CONN_TIME = "conn-time"
F_XPR_IDLE_TIME = "idle-time"
F_XPR_SEND = "send"
F_XPR_RECV = "recv"
F_XPR_BAD_XIDS = "bad-xids"
F_XPR_REQ = "req-u"
F_XPR_BACKLOG = "backlog-u"
F_XPR_SRC_PORT = "source-port"

# -- added for "/proc/self/smaps"
F_RSS = "rss-size"
F_PSS = "prop-share"
F_SH_CLEAN = "shared-clean"
F_SH_DIRTY = "shared-dirty"
F_PR_CLEAN = "private-clean"
F_PR_DIRTY = "private-dirty"
F_REFERENCED = "referenced"
F_ANONYMOUS = "anonymous"
F_ANON_HUGE_PAGES = "anon-huge-pages"
F_SWAP = "swap"
F_KERNEL_PGSZ = "kernel-page-size"
F_MMU_PGSZ = "mmu-page-size"
F_LOCKED = "locked"
F_FL_READ = "flag-read"
F_FL_WRITE = "flag-write"
F_FL_EXEC = "flag-exec"
F_FL_MAYSHARE = "flag-may-share"

# -- added to support "SymLinkFile" base class
F_SYMLINK = "symlink-target"

# -- added for /proc/self/status
F_PROG_NAME = "prog-name"
F_RUNSTATUS = "run-status"
F_THREAD_GID = "thread-gid"
F_PPID = "ppid"
F_TRACER_PID = "tracer-pid"
F_UID_SET = "uid-set"
F_EUID = "eff-uid"
F_SUID = "set-uid" 
F_FSUID = "filesys-uid"
F_GID_SET = "gid-set"
F_GID = "gid"
F_EGID = "eff-gid"
F_SGID = "set-gid"
F_FSGID = "filesys-gid"
F_FDSIZE = "fdsize"
F_VM_PEAK = "vm-peak"
F_VM_SIZE = "vm-size"
F_VM_LOCK = "vm-lock"
F_VM_PIN = "vm-pin"
F_VM_HWM = "vm-hi-water-mark"
F_VM_RSS = "vm-rss"
F_VM_DATA = "vm-data"
F_VM_STACK = "vm-stack"
F_VM_EXE = "vm-exe"
F_VM_LIB = "vm-shared-lib"
F_VM_PTE = "vm-page-table"
F_VM_SWAP = "vm-swap"
F_THREADS = "threads"
F_SIG_QUEUE = "sig-queue-size"
F_SIG_PEND = "sig-pending"
F_SIG_SH_PEND = "sig-shared-pending"
F_SIG_BLOCK = "sig-blocked"
F_SIG_IGN = "sig-ignored"
F_SIG_CAUGHT = "sig-caught"
F_CAP_INHERIT = "cap-inheritable"
F_CAP_PERM = "cap-permitted"
F_CAP_EFF = "cap-effective"
F_CAP_BSET = "cap-bounding-set"
F_CPU_ALLOW_MASK = "cpu-allow-mask"
F_CPU_ALLOW_LIST = "cpu-allow-list"
F_MEM_ALLOW_MASK = "mem-allow-mask"
F_MEM_ALLOW_LIST = "mem-allow-list"
F_CSWITCH_VOL = "vol-ctx-switch"
F_CSWITCH_NONVOL = "nonvol-ctx-switch"

# -- added for "/proc/self/sched"
F_PROGRAM = "program-name"
F_EXEC_START = "exec-start"
F_RUNTIME = "runtime"
F_EXEC_RUNTIME = "exec-runtime"
F_ST_WAIT_START = "stat-wait-start"
F_ST_SLEEP_START = "stat-sleep-start"
F_ST_BLOCK_START = "stat-block-start"
F_ST_SLEEP_MAX = "stat-sleep-max"
F_ST_BLOCK_MAX = "stat-block-max"
F_ST_EXEC_MAX = "stat-exec-max"
F_ST_SLICE_MAX = "stat-slice-max"
F_ST_WAIT_MAX = "stat-wait-max"
F_ST_WAIT_SUM = "stat-wait-sum"
F_ST_WAIT_COUNT = "stat-wait-count"
F_ST_IOWAIT_SUM = "stat-iowait-sum"
F_ST_IOWAIT_COUNT = "stat-iowait-count"
F_NR_MIGR = "nr-migrate"
F_ST_NR_MIGR_COLD = "stat-nr-migrate-cold"
F_ST_NR_FAIL_MIGR_AFF = "stat-nr-failed-migrate-aff"
F_ST_NR_FAIL_MIGR_RUN = "stat-nr-failed-migrate-run"
F_ST_NR_FAIL_MIGR_HOT = "stat-nr-failed-migrate-hot"
F_ST_NR_FORCED_MIGR = "stat-nr-forced-migrate"
F_ST_NR_WAKE = "stat-nr-wakeups"
F_ST_NR_WAKE_SYNC = "stat-nr-wake-sync"
F_ST_NR_WAKE_MIGR = "stat-nr-wake-migrate"
F_ST_NR_WAKE_LOC = "stat-nr-wake-local"
F_ST_NR_WAKE_REM = "stat-nr-wake-remote"
F_ST_NR_WAKE_AFF = "stat-nr-wake-aff"
F_ST_NR_WAKE_AFF_ATT = "stat-nr-wake-att-attempt"
F_ST_NR_WAKE_PASS = "stat-nr-wake-passive"
F_ST_NR_WAKE_IDLE = "stat-nr-wake-idle"
F_AVG_ATOM = "avg-atom"
F_AVG_PER_CPU = "avg-per-cpu"
F_NR_SWITCH = "nr-switches"
F_NR_VOL_SWITCH = "nr-voluntary-switches"
F_NR_INVOL_SWITCH = "nr-involutary-switches"
F_LOAD_WEIGHT = "load-weight"
F_POLICY = "policy"
F_CLOCK_DELTA = "clock-delta"

# -- added to support /proc/self/personality
F_PERSONALITY = "personality"

# -- added for /proc/stat
F_SS_CPU = "cpu-summ-stats"
F_SS_INTR = "interrupt-stats"
F_SS_CTXT = "cswitch-stats"
F_SS_BTIME = "btime-stats"
F_SS_PROCS_TOT = "fork-stats"
F_SS_PROCS_RUN = "running-stats"
F_SS_PROCS_BLOCK = "blocked-stats"
F_SS_SOFTIRQ = "softirq-stats"

# -- added for /proc/interrupts
F_INTERRUPT = "interrupt"
F_INTERRUPT_DESC = "interrupt-decription"
F_TOT_COUNT = "total-count"

# -- added for /proc/zoneinfo
F_NR_FREE_PAGES = "nr-free-pages"
F_NR_INACTIVE_ANON = "nr-inactive-anon"
F_NR_ACTIVE_ANON = "nr-active-anon"
F_NR_INACTIVE_FILE = "nr-inactive-file"
F_NR_ACTIVE_FILE = "nr-active-file"
F_NR_UNEVICTABLE = "nr-unevictable"
F_NR_MLOCK = "nr-mlock"
F_NR_ANON_PAGES = "nr-anon-pages"
F_NR_MAPPED = "nr-mapped"
F_NR_FILE_PAGES = "nr-file-pages"
F_NR_DIRTY = "nr-dirty"
F_NR_WRITEBACK = "nr-writeback"
F_NR_SLAB_RECLAIM = "nr-slab-reclaimable"
F_NR_SLAB_UNRECLAIM = "nr-slab-unreclaimable"
F_NR_PAGE_TABLE_PAGES = "nr-page-table-pages"
F_NR_KERNEL_STACK = "nr-kernel-stack"
F_NR_UNSTABLE = "nr-unstable"
F_NR_BOUNCE = "nr-bounce"
F_NR_VMSCAN_WRITE = "nr-vmscan-write"
F_NR_VMSCAN_IMM_RECLAIM = "nr-vmscan-immediate-reclaim"
F_NR_WRITEBACK_TEMP = "nr-writeback-temp"
F_NR_ISOLATED_ANON = "nr-isolated-anon"
F_NR_ISOLATED_FILE = "nr-isolated-file"
F_NR_SHMEM = "nr-shmem"
F_NR_DIRTIED = "nr-dirtied"
F_NR_WRITTEN = "nr-written"
F_NUMA_HIT = "numa-hit"
F_NUMA_MISS = "numa-miss"
F_NUMA_FOREIGN = "numa-foreign"
F_NUMA_INTERLEAVE = "numa-interleave"
F_NUMA_LOCAL = "numa-local"
F_NUMA_OTHER = "numa-other"
F_NR_ANON_TRANS_HUGE = "nr-anon-transparent-hugepages"
F_PROTECTION = "protection"
F_ALL_UNRECLAIM = "all-unreclaimed"
F_START_PFN = "start-pfn"
F_INACTIVE_RATIO = "inactive-ratio"
F_PAGES_FREE = "pages-free"
F_PAGES_MIN = "pages-min"
F_PAGES_LOW = "pages-low"
F_PAGES_HIGH = "pages-high"
F_PAGES_SCANNED = "pages-scanned"
F_PAGES_SPANNED = "pages-spanned"
F_PAGES_PRESENT = "pages-present"
F_CPU_PAGESETS = "pagesets-per-cpu"
F_CPU_ID = "cpu-id"

# -- added for /proc/schedstat
F_SCH_YIELD = "sched-yield"
F_SCH_SW_EXP_Q = "switch-expired-queue"
F_SCH_CALLS = "sched-called"
F_SCH_IDLE = "sched-idle"
F_WUP_CALLS = "try-wakeup"
F_WUP_LOC_CPU = "try-wakeup-local-cpu"
F_RUNNING = "running-sum"
F_WAITING = "waiting-sum"
F_SLICES = "timeslices"
F_CPU_MASK = "cpu-mask"
F_TIMESTAMP = "timestamp"
F_IDLE_LB = "lb-calls-idle"
F_IDLE_LB_PASS = "lb-no-action-idle"
F_IDLE_LB_FAIL = "lb-move-fail-idle"
F_IDLE_LB_IMBAL = "lb-imbalance-idle"
F_IDLE_PT = "pull-task-calls-idle"
F_IDLE_PT_CACHE_HOT = "pull-task-cache-hot-idle"
F_IDLE_LB_NO_QUEUE = "lb-no-busier-queue-idle"
F_IDLE_LB_NO_GROUP = "lb-no-busier-group-idle"
F_BUSY_LB = "lb-calls-busy"
F_BUSY_LB_PASS = "lb-no-action-busy"
F_BUSY_LB_FAIL = "lb-move-fail-busy"
F_BUSY_LB_IMBAL = "lb-imbalance-busy"
F_BUSY_PT = "pull-task-calls-busy"
F_BUSY_PT_CACHE_HOT = "pull-task-cache-hot-busy"
F_BUSY_LB_NO_QUEUE = "lb-no-busier-queue-busy"
F_BUSY_LB_NO_GROUP = "lb-no-busier-group-busy"
F_JBEI_LB = "lb-calls-turn-idle"
F_JBEI_LB_PASS = "lb-no-action-turn-idle"
F_JBEI_LB_FAIL = "lb-move-fail-turn-idle"
F_JBEI_LB_IMBAL = "lb-imbalance-turn-idle"
F_JBEI_PT = "pull-task-calls-turn-idle"
F_JBEI_PT_CACHE_HOT = "pull-task-cache-hot-turn-idle"
F_JBEI_LB_NO_QUEUE = "lb-no-busier-queue-turn-idle"
F_JBEI_LB_NO_GROUP = "lb-no-busier-group-turn-idle"
F_ACT_LB = "active-lb-calls"
F_ACT_LB_FAIL = "active-lb-move-failed"
F_ACT_LB_MOVED = "active-lb-move-worked"
F_SBE_COUNT = "sch-bal-exec-count"
F_SBE_BALANCED = "sch-bal-exec-balanced"
F_SBE_PUSHED = "sch-bal-exec-pushed"
F_SBF_COUNT = "sch-bal-fork-count"
F_SBF_BALANCED = "sch-bal-fork-balanced"
F_SBF_PUSHED = "sch-bal-fork-pushed"
F_TRWUP_AWOKE_DIFF_CPU = "try-wake-diff-cpu"
F_TRWUP_MOVE_CACHE_COLD = "try-wake-cache-cold"
F_TRWUP_PASSIVE_BAL = "try-wake-pass-bal"

# -- added for /proc/crypto
F_DRIVER = "driver"
F_REF_COUNT = "ref-count"
F_SELFTEST = "selftest"
F_DIGEST_SIZE = "digest-size"
F_MAX_AUTH_SIZE = "max-auth-size"
F_MAX_KEYSIZE = "max-keysize"
F_MIN_KEYSIZE = "min-keysize"
F_ASYNC = "async"
F_GENIV = "geniv"
F_IVSIZE = "ivsize"
F_BLOCKSIZE = "blocksize"

# -- added for /proc/self/autogroup
F_ID = "id"
F_NICE = "nice"

# -- added for /proc/self/comm
F_COMM = "command"

# -- added for base class SingleTextField
F_DATA = "data"

# -- added for /proc/self/cpuset
F_CPU_SET = "cpu-set"

# -- added for /proc/self/syscall
F_SYSCALL = "syscall-summary"

# -- added for /proc/self/wchan
F_WCHAN = "wchan"

# -- added for /proc/self/sessionid
F_SESSIONID = "session-id"

# -- added for /proc/self/loginuid
F_LOGINUID = "login-uid"

# -- added for /proc/self/statm
F_RESIDENT_SIZE = "resident-size"
F_SHARED_SIZE = "shared-size"
F_TEXT_SIZE = "text-size"
F_DATA_SIZE = "data-size"

# -- added for /proc/self/stat
F_PID_NR = "pid-nr"
F_PGID = "pgid"
F_SID = "sid"
F_TTY_NR = "tty-nr"
F_TTY_PGRP = "tty-pgrp"
F_MIN_FLT = "min-flt"
F_CMIN_FLT = "cmin-flt"
F_MAJ_FLT = "maj-flt"
F_CMAJ_FLT = "cmaj-flt"
F_UTIME = "user-time"
F_STIME = "sys-time"
F_CUTIME = "cu-user-time"
F_CSTIME = "cu-sys-time"
F_START_TIME = "start-time"
F_VSIZE = "vsize"
F_RSS_SIZE = "rss-size"
F_RSS_LIM = "rss-limit"
F_START_CODE = "start-code"
F_END_CODE = "end-code"
F_START_STACK = "start-stack"
F_ESP = "esp"
F_EIP = "eip"
F_SIG_IGNORE = "signal-ignore"
F_SIG_CATCH = "signal-catch"
F_EXIT_SIG = "exit-signal"
F_TASK = "task"
F_RT_PRIORITY = "rt-priority"
F_IO_TICKS = "io-ticks"
F_GTIME = "gtime"
F_CGTIME = "cu-gtime"
