#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

# ---

import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

RECREATOR = dict()

__all__ = ["net_tcp", "net_udp", "net_tcp6", "net_udp6", "net_unix",
    "net_connector", "net_netlink", "net_protocols", "net_dev",
    "net_softnet_stat", "net_ptype", "net_dev_mcast", "net_psched", "net_arp",
    "net_route", "net_rt_cache", "net_igmp", "net_sockstat", "net_igmp6",
    "net_sockstat6", "net_packet", "net_ipv6_route", "net_rt6_stats",
    "net_if_inet6", "net_fib_triestat", "root_buddyinfo", "root_cgroups",
    "root_cmdline", "root_consoles", "root_devices", "root_diskstats",
    "root_dma", "root_execdomains", "root_fb", "root_filesystems",
    "root_iomem", "root_ioports", "root_kallsyms", "root_key_users",
    "root_loadavg", "root_locks", "root_meminfo", "root_misc", "root_modules",
    "root_mounts", "root_mtrr", "root_partitions", "root_softirqs",
    "root_swaps", "root_uptime", "root_version_sig", "root_vmstat",
    "self_autogroup", "self_comm", "self_core_filter", "self_cpuset",
    "self_limits", "self_maps", "self_oom_adj", "self_oom_score_adj",
    "self_oom_score", "self_personality", "self_schedstat", "self_statm",
    "self_smaps", "self_stack", "self_stat", "self_syscall", "self_wchan",
    "self_cmdline", "self_loginuid", "self_sessionid", "self_numa_maps",
    "self_status", "net_netfilter_nf_log", "net_netfilter_nf_queue",
    "net_stat_arp_cache", "net_stat_ip_conntrack", "net_stat_nf_conntrack",
    "net_stat_rt_cache", "net_stat_ndisc_cache", "root_stat", "root_interrupts",
    "root_zoneinfo", "net_dev_snmp6", "root_timer_list", "root_timer_stats",
    "root_vmallocinfo", "net_ip_conntrack", "net_nf_conntrack", "sysvipc_shm",
    "sysvipc_msg", "sysvipc_sem", "root_pagetypeinfo", "root_schedstat",
    "self_io", "net_ip6_tables_targets", "net_ip6_tables_matches",
    "net_ip6_tables_names", "net_ip_tables_targets", "net_ip_tables_matches",
    "net_ip_tables_names", "self_sched", "net_snmp", "net_netstat",
    "net_fib_trie", "root_crypto", "self_environ"]

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

# ---

def list_of_terms(inprecs):

    """
    General purpose routine for handling parsed data from handlers that inherit
    from the 'ListOfTerms' base class.
    """

    for __hilit in inprecs:
        print "\n".join(inprecs.field[PFC.F_TERM_LIST])

# ---

def twoline_data_format(inprecs):

    """
    Iterate through parsed records and re-generate data file
    """

    __template = "{acc:s} {val:s}"

    for __hilit in inprecs:
        __ff = inprecs.field
        __hits = inprecs.hit_order

        if len(__ff) == 0:
            continue

        __label = __hits[0]
        __count = __ff[__label]

        for __seq in range(1, len(__hits)):
            __key = __hits[__seq]

            __label = __template.format(acc=__label, val=__key)
            __count = __template.format(acc=__count, val=__ff[__key])

        print __label
        print __count
