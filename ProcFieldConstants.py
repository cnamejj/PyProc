#!/usr/bin/env python
"""Field name constants shared by several modules, no code here"""

# -- fields used for tcp, tcp6, udp and udp6
F_BUCKET = "bucket"
F_ORIG_HEXIP = "orig-hexip"
F_DEST_HEXIP = "dest-hexip"
F_ORIG_HEXPORT = "orig-hexport"
F_DEST_HEXPORT = "dest-hexport"
F_ORIG_IP = "orig-ip"
F_DEST_IP = "dest-ip"
F_ORIG_PORT = "orig-port"
F_DEST_PORT = "dest-port"
F_HEXSTATE = "hexstate"
F_STATE = "state"
F_TXQUEUE = "tx-queue"
F_RXQUEUE = "rx-queue"
F_TIMER = "timer"
F_TIMER_WHEN = "tm-when"
F_RETRANS = "retrnsmt"
F_UID = "uid"
F_TIMEOUT = "timeout"
F_INODE = "inode"
F_REFCOUNT = "ref-count"
F_POINTER = "pointer"
F_DROPS = "drops"
F_RETRY_TIMEOUT = "retry-timeout"
F_ACK_TIMEOUT = "ack-timeout"
F_QUICK_OR_PPONG = "quick-pingpong"
F_CONGEST_WINDOW = "congest-window"
F_SSTART_THRESH = "slow-start-thresh"

# -- fields used for "arp" data
F_IP_ADDRESS = "ip-address"
F_HW_TYPE = "hw-type"
F_FLAGS = "flags"
F_HW_ADDRESS = "hw-address"
F_MASK = "mask"
F_DEVICE = "device"

# -- fields added by "dev" data
F_RX_BYTES = "rx-bytes"
F_RX_PACKETS = "rx-packets"
F_RX_ERRORS = "rx-errors"
F_RX_DROP = "rx-drop"
F_RX_FIFO = "rx-fifo"
F_RX_FRAME = "rx-frame"
F_RX_COMPRESSED = "rx-compressed"
F_RX_MULTICAST = "rx-multicast"
F_TX_BYTES = "tx-bytes"
F_TX_PACKETS = "tx-packets"
F_TX_ERRORS = "tx-errors"
F_TX_DROP = "tx-drop"
F_TX_FIFO = "tx-fifo"
F_TX_COLLISION = "tx-colls"
F_TX_CARRIER = "tx-carrier"
F_TX_COMPRESSED = "tx-compressed"

# -- fields added by "route" data
F_INTERFACE = "iface"
F_GATEWAY = "gateway"
F_USECOUNT = "use-count"
F_METRIC = "metric"
F_MTU = "mtu"
F_WINDOW = "window"
F_IRTT = "irtt"
F_NETMASK = "netmask"
F_GATE_HEXIP = "gateway-hex"
F_MASK_HEXIP = "netmask-hex"

# -- fields added by "rt_cache" data
F_SRCE_HEXIP = "source-hex"
F_SOURCE = "source-ip"
F_TOS = "tos"
F_HHREF = "hhref"
F_HHUPTOD = "hhuptod"
F_SPEC_HEXIP = "spec-dst-hexip"
F_SPEC_DST = "spec-dst"

# -- fields added to support "stat/arp_cache" data
F_ARP_ENTRIES = "arp-entries"
F_ALLOC = "alloc-count"
F_DESTROY = "destroy-count"
F_HASH_GROW = "hash-grow-count"
F_LOOKUP = "lookup-count"
F_HIT = "hit-count"
F_RES_FAIL = "res-fail-count"
F_RCV_MCAST_PROBE = "rx-mcast-count"
F_RCV_UCAST_PROBE = "rx-ucast-count"
F_GC_PERIODIC = "gc-peri-count"
F_GC_FORCED = "gc-forc-count"
F_UNRES_DISCARD = "unres-dis-count"

# -- fields added to support "stat/ip_conntrack" data
F_ENTRIES = "entries"
F_SEARCHED = "searched"
F_FOUND = "found"
F_NEW = "new"
F_INVALID = "invalid"
F_IGNORE = "ignore"
F_DELETE = "delete"
F_DELETE_LIST = "delete-list"
F_INSERT = "insert"
F_INSERT_FAILED = "insert-failed"
F_DROP = "drop"
F_DROP_EARLY = "early-drop"
F_ICMP_ERROR = "icmp-err"
F_EXP_NEW = "expect-new"
F_EXP_CREATE = "expect-create"
F_EXP_DELETE = "expect-delete"
F_SEARCH_RESTART = "search-restart"

# -- fields added to support "stat/rt_cache" data
F_IN_HIT = "in-hit"
F_IN_SLOW_TOT = "in-slow-tot"
F_IN_SLOW_MC = "in-slow-mc"
F_IN_NO_ROUTE = "in-no-route"
F_IN_BRD = "in-brd"
F_IN_MARTIAN_DST = "in-martian-dst"
F_IN_MARTIAN_SRC = "in-martian-src"
F_OUT_HIT = "out-hit"
F_OUT_SLOW_TOT = "out-slow-tot"
F_OUT_SLOW_MC = "out-slow-mc"
F_GC_TOTAL = "gc-total"
F_GC_IGNORED = "gc-ignored"
F_GC_GOAL_MISS = "gc-goal-miss"
F_GC_DST_OVERFLOW = "gc-dst-overflow"
F_IN_HL_SEARCH = "in-hlist-search"
F_OUT_HL_SEARCH = "out-hlist-search"

# -- fields added to support "unix" data
F_NUM = "num"
F_PROTOCOL = "protocol"
F_TYPE = "type"
F_PATH = "path"

# -- fields added to support "if_inet6" data
F_IPV6_HEX = "ipv6-hex"
F_INT_INDEX_HEX = "int-index-hex"
F_PREFIX_LEN_HEX = "prefix-len-hex"
F_FLAGS_HEX = "flags-hex"
F_SCOPE_HEX = "scope-hex"
F_INT_INDEX = "int-index"
F_PREFIX_LEN = "prefix-len"
F_SCOPE = "scope"
F_IPV6 = "ipv6"

# -- fields added to support "dev_mcast" data
F_GLOBAL_USE = "global-use"
F_DEV_ADDR = "device-address"

# -- fields added to support "igmp6" data
F_MCAST_ADDR = "mcast-addr"
F_MCAST_USERS = "mcast-users"
F_MCAST_FLAGS = "mcast-flags"
F_TIMER_EXPIRE = "timer-expiration"
F_MCAST_ADDR_HEX = "mcast-addr-hex"

# -- fields added to support "ipv6_route"
F_DEST_PREFIX_LEN_HEX = "dest-preflen-hex"
F_SRCE_PREFIX_LEN_HEX = "src-preflen-hex"
F_PRIMARY_KEY = "primary-key"
F_RT6I_METRIC = "rt6i-metric"
F_DEST_REFCOUNT = "dest-ref-count"
F_DEST_USE = "dest-use"
F_RT6I_FLAGS = "rt6i-flags"
F_DEST_PREFIX_LEN = "dest-preflen"
F_SRCE_PREFIX_LEN = "src-preflen"

# -- fields added to support "psched"
F_NSEC_PER_USEC = "nsec-per-usec"
F_PSCHED_TICKS = "psched-ticks-per-nsec"
F_UNKNOWN_FIELD = "unknown-field"
F_NSEC_PER_HRTIME = "nsec-per-hrtimer-unit"

# -- fields added to support "rt6_stats" data
F_FIB_NODES = "fib-nodes"
F_FIB_ROUTE_NODES = "fib-route-nodes"
F_FIB_ROUTE_ALLOC = "fib-route-alloc"
F_FIB_ROUTE_ENTRIES = "fib-route-entries"
F_FIB_ROUTE_CACHE = "fib-route-cache"
F_FIB_DEST_OPS = "dest-ops"
F_FIB_DISC_ROUTES = "fib-discarded-routes"

# -- fields added to support "softnet_stat"
F_PROCESSED = "processed"
F_DROPPED = "dropped"
F_TIME_SQUEEZE = "time-squeeze"
F_ZERO1 = "zero1"
F_ZERO2 = "zero2"
F_ZERO3 = "zero3"
F_ZERO4 = "zero4"
F_ZERO5 = "zero5"
F_CPU_COLL = "cpu-collision"
F_RECEIVED_RPS = "received-rps"
F_FLOW_LIM_COUNT = "flow-limit-count"

# -- fields added to support the "protocols" data
F_SIZE = "size"
F_SOCKETS = "sockets"
F_MEMORY = "memory"
F_PRESSURE = "pressure"
F_MAX_HEADER = "max-header"
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
F_BACKLOG_RCV = "backlog-rcv"
F_HASH = "hash"
F_UNHASH = "unhash"
F_GET_PORT = "get-port"
F_ENTER_PRESSURE = "enter-memory-pressure"

# -- fields added to support the "packet" data
F_SOCKET_POINTER = "socket-pointer"
F_RUNNING = "running"
F_RMEM_ALLOC = "rmem-alloc"

# -- fields added to support the "connector" data
F_NAME = "name"
F_ID_IDX = "id-idx"
F_ID_VAL = "id-val"

# -- fields added to support the "netlink" data
F_PID = "pid"
F_GROUPS = "groups"
F_WMEM_ALLOC = "wmem-alloc"
F_DUMP = "dump"
F_LOCKS = "locks"
F_DUMP_STR = "dump-string"

# -- fields added to support the "netfilter/nf_log" data
F_INDEX = "index"
F_LOGGER_LIST = "logger-list"

# -- fields added to support "igmp" data
F_COUNT = "count"
F_QUERIER = "querier"
F_GROUP = "group"
F_USERS = "users"
F_REPORTER = "reporter"

# -- fields added to support "ip_conntrack" data
F_PROTOCOL_NUM = "protocol-number"
F_OR_SRC_IP = "original-source-ip"
F_OR_DST_IP = "original-destination-ip"
F_OR_SRC_PORT = "original-source-port"
F_OR_DST_PORT = "original-destination-port"
F_UNREPLIED = "unreplied"
F_OR_PACKETS = "original-packets"
F_OR_BYTES = "original-bytes"
F_RE_SRC_IP = "reply-source-ip"
F_RE_DST_IP = "reply-destination-ip"
F_RE_SRC_PORT = "reply-source-port"
F_RE_DST_PORT = "reply-destination-port"
F_RE_PACKETS = "reply-packets"
F_RE_BYTES = "reply-bytes"
F_ASSURED = "assured"
F_MARK = "mark"
F_SECCTX = "secctx"
F_USE = "use"

# -- fields added to support "nf_conntrack" data
F_L3_PROTOCOL = "l3-protocol"
F_L3_PROTOCOL_NUM = "l3-protocol-num"
F_ZONE = "zone"
F_DELTA_TIME = "delta-time"

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
F_DEVICE_TYPE = "dev-type"
F_DEVICE_NAME = "dev-name"
F_DEVICE_FUNC = "dev-function"

# -- name used by "ip_tables_*" and "ip6_tables_*" handlers
F_TERM_LIST = "list-of-terms"

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
F_COMP_BY = "compile-by"
F_COMP_HOST = "compile-host"
F_COMPILER = "compiler"

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
F_BITMAP_CHUNK_TUNITS = "bitmap-chunk-text-units"

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
F_NODE_ORDER = "node-order"

# -- added for "/proc/self/mountinfo"
F_MOUNT_ID = "mount-id"
F_PARENT_MOUNT_ID = "parent-mount-id"
F_MOUNT_FS = "mount-point"
F_MOUNT_REL = "relative-mount-point"
F_MOUNT_OPTS = "mount-options"
F_EXTRA_OPTS = "extra-options"
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
F_LOCKLOCAL = "local-lock"
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
F_RSS = "rss"
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
F_VMFLAGS = "vm-flags"

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
F_SEC_COMP = "seccomp"
F_NUMA_GID = "numa-gid"

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
F_RUN_AV_SUM = "runnable-avg-sum"
F_RUN_AV_PERIOD = "runnable-avg-period"
F_LOAD_AV_CONTR = "load-avg-contrib"
F_AV_DECAY_COUNT = "avg-decay-count"
F_HRULE = "horizontal-line"
F_NUMA_SCAN_SEQ = "numa-scan-seq"
F_NUMA_MIGRATE = "numa-migrations"
F_HOME = "home"
F_FAULT = "fault"
F_NUMA_FAULTS = "numa-faults"

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
F_COL1_WIDTH = "column1-precision"

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
F_PAGES_MANAGED = "pages-managed"
F_NR_FREE_CMA = "nr-free-cma"
F_NR_ALLOC_BATCH = "nr-alloc-batch"

# -- added for /proc/schedstat
F_SCH_YIELD = "sched-yield"
F_SCH_SW_EXP_Q = "switch-expired-queue"
F_SCH_CALLS = "sched-called"
F_SCH_IDLE = "sched-idle"
F_WUP_CALLS = "try-wakeup"
F_WUP_LOC_CPU = "try-wakeup-local-cpu"
F_RUNNING_SUM = "running-sum"
F_WAITING_SUM = "waiting-sum"
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
F_DOM_ORDER = "domain-order"

# -- added for /proc/crypto
F_DRIVER = "driver"
F_SELFTEST = "selftest"
F_DIGEST_SIZE = "digest-size"
F_MAX_AUTH_SIZE = "max-auth-size"
F_MAX_KEYSIZE = "max-keysize"
F_MIN_KEYSIZE = "min-keysize"
F_ASYNC = "async"
F_GENIV = "geniv"
F_IVSIZE = "ivsize"
F_BLOCKSIZE = "blocksize"
F_SEEDSIZE = "seedsize"

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
F_START_DATA = "start-data"
F_END_DATA = "end-data"
F_START_BRK = "start-brk"
F_ARG_START = "arg-start"
F_ARG_END = "arg-end"
F_ENV_START = "env-start"
F_ENV_END = "env-end"
F_EXIT_CODE = "exit-code"

# -- added for /proc/self/schedstat
F_RUN_TIME = "run-time"
F_RUNQUEUE_TIME = "queue-wait-time"
F_RUN_TIMESLICES = "timeslices-run"

# -- added for /proc/self/coredump_filter
F_COREDUMP_FILTER = "coredump-filter"

# -- added for /proc/self/oom_score
F_OOM_SCORE = "oom-score"

# -- added for /proc/self/oom_adj
F_OOM_ADJ = "oom-adj"

# -- added for /proc/self/oom_score_adj
F_OOM_SCORE_ADJ = "oom-score-adj"

# -- added for /proc/latency_stats and /proc/self/latency
F_HITS = "hits"
F_ACCUM_LATENCY = "accum-latency-ms"
F_MAX_LATENCY = "max-latency-ms"
F_BACKTRACE = "backtrace"

# -- added for /proc/ioports
F_PORT_NAME = "port-name"
F_LEVEL = "level"

# -- added for /proc/iomem
F_MEM_DESC = "memory-description"

# -- added for /proc/timer_stats
F_CBACK_ROUT = "callback-routine"
F_DEFERRABLE = "deferrable"
F_EVENT_RATE = "event-rate"
F_EVENT_TOTAL = "total-events"
F_INIT_ROUT = "initial-routine"
F_PROC_NAME = "process-name"
F_SAMPLE_PERIOD = "sample-period"
F_OVERFLOW = "overflow"

# -- added for /proc/pagetypeinfo
F_BLOCK_ORDER = "block-order"
F_PAGES_PER_BLOCK = "pages-per-block"
F_MIGR_BRKOUT = "pages-allocated"
F_MIGR_AGG = "total-blocks"

# -- added for /proc/net/fib_trie
F_NETWORK = "network-addr"
F_FIB_TRIE = "fib-trie"
F_FIB_BITS = "fib-bits"
F_FULL_CHILDREN = "fib-full-children"
F_EMPTY_CHILDREN = "fib-empty-children"
F_FIB_LEAF = "fib-leaf"
F_NODE_NAME = "node-name"

# -- added for /proc/net/fib_triestat
F_AVER_DEPTH = "average-depth"
F_BACKTRACKS = "backtracks"
F_GETS = "get-counts"
F_INT_NODE_LIST = "int-node-list"
F_INT_NODES = "internal-nodes"
F_LEAF_SIZE = "leaf-size"
F_LEAVES = "leaves"
F_MAX_DEPTH = "max-depth"
F_NULL_NODE = "null-node-hit"
F_NULL_PTRS = "null-pointers"
F_POINTERS = "pointers"
F_PREFIXES = "prefixes"
F_SEM_MISS = "sem-match-miss"
F_SEM_PASS = "sem-match-pass"
F_SKIPPED = "skipped-node-resize"
F_TNODE_SIZE = "tnode-size"
F_TOTAL_SIZE = "total-size"

# -- added for /proc/timer_list
F_HRT_MAX_CL_BASES = "max-clock-bases"
F_TIME_NOW = "now"
F_CPU = "cpu"
F_NEXT_EXPIRE = "expires-next"
F_HRES_ACTIVE = "hres-active"
F_NR_EVENTS = "nr-events"
F_NR_RETRIES = "nr-retries"
F_NR_HANGS = "nr-hangs"
F_MAX_HANG_TIME = "max-hang-time"
F_NOHZ_MODE = "nohz-mode"
F_LAST_TICK = "last-tick"
F_IDLE_TICK = "idle-tick"
F_TICK_STOP = "tick-stopped"
F_IDLE_JIFFIES = "idle-jiffies"
F_IDLE_CALLS = "idle-calls"
F_IDLE_SLEEPS = "idle-sleeps"
F_IDLE_ENTRY = "idle-entrytime"
F_IDLE_WAKE = "idle-waketime"
F_IDLE_EXIT = "idle-exittime"
F_IDLE_SLEEPTIME = "idle-sleeptime"
F_IOWAIT_SLEEP = "iowait-sleeptime"
F_LAST_JIFFIES = "last-jiffies"
F_NEXT_JIFFIES = "next-jiffies"
F_IDLE_EXPIRES = "idle-expires"
F_JIFFIES = "jiffies"
F_CLOCK_ID = "clock-id"
F_CLOCK_BASE = "clock-base"
F_CLOCK_INDEX = "clock-index"
F_CLOCK_RES = "clock-resolution"
F_CLOCK_GETTIME = "clock-get-time"
F_CLOCK_OFFSET = "clock-offset"
F_CLOCK_LIST = "clock-list"
F_TIMER_NUM = "timer-num"
F_TIMER_ADDR = "timer-address"
F_TIMER_ADDR_TEXT = "timer-address-text"
F_TIMER_FUNC = "timer-function"
F_TIMER_STATE = "timer-state"
F_START_SITE = "start-site"
F_START_COMM = "start-comm"
F_START_PID = "start-pid"
F_SOFT_EXP = "soft-expiration"
F_EXP = "expiration"
F_SOFT_EXP_DIFF = "soft-expiration-delta"
F_EXP_DIFF = "expiration-delta"
F_ACTIVE_TIMERS = "active-timers"
F_TICK_DEV = "tick-device"
F_PER_CPU_DEV = "per-cpu-device"
F_CLOCK_EV_DEV = "clock-event-device"
F_MAX_DELTA = "max-delta-ns"
F_MIN_DELTA = "min-delta-ns"
F_MULT = "mult"
F_SHIFT = "shift"
F_MODE = "mode"
F_NEXT_EVENT = "next-event"
F_SET_NEXT_EVENT = "set-next-event"
F_SET_MODE = "set-mode"
F_EVENT_HANDLER = "event-handler"
F_RETRIES = "retries"
F_TICK_BCAST_MASK = "tick-bcast-mask"
F_TICK_BCAST_ONESHOT = "tick-bcast-oneshot-mask"
F_BCAST_DEVICE = "broadcast-device"

# -- added for /proc/sysvipc/shm
F_KEY = "key"
F_CPID = "current-pid"
F_ATTACH = "attached"
F_ACC_TIME = "access-time"
F_DEST_TIME = "destroy-time"
F_CHAN_TIME = "change-time"
F_CR_UID = "creator-uid"
F_CR_GID = "creator-gid"
F_OW_UID = "owner-uid"
F_OW_GID = "owner-gid"

# -- added for /proc/sysvipc/sems
F_SEMS = "semaphores"
F_UPD_TIME = "update-time"

# -- added for /proc/sysvipc/msg
F_BYTES = "bytes"
F_QUEUES = "num-queued"
F_SEND_PID = "sender-pid"
F_RECV_PID = "receiver-pid"
F_SEND_TIME = "sender-time"
F_RECV_TIME = "receiver-time"

# -- added for /proc/softirqs
F_IRQ_ORDER = "irq-order"
F_CPU_ORDER = "cpu-order"

# -- added for /proc/self/cmdline
F_COMM_ARGS = "command-args"
