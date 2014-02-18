#!/usr/bin/env python
"""
Show all current TCP connections with local ip/port, remote ip/port, remote
hostname, process name and process owner.

Data is pulled from /proc filesystem.
"""

import sys

import ProcHandlers
import ProcFieldConstants
import CachedDNS
import ProcessInfo

GET_HANDLER = ProcHandlers.GET_HANDLER

if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)

IPLOOKUP = CachedDNS.LookupIP()
PSI = ProcessInfo
PFC = ProcFieldConstants

SOCKLIST = GET_HANDLER("/proc/net/tcp")()

for proc_rec in SOCKLIST:

    dest_ip = SOCKLIST.field[PFC.F_DEST_IP]
    dest_port = SOCKLIST.field[PFC.F_DEST_PORT]
    orig_ip = SOCKLIST.field[PFC.F_ORIG_IP]
    orig_port = SOCKLIST.field[PFC.F_ORIG_PORT]
    sock_stat = SOCKLIST.field[PFC.F_STATE]

    ip2host = IPLOOKUP.get_cached_hostname(dest_ip)

    session_pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port, "tcp")
 
    proc_summary, proc_rc = PSI.pid_to_proc_summ(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format(
            orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary,
            sock_stat)

SOCKLIST = GET_HANDLER("/proc/net/tcp6")()

for proc_rec in SOCKLIST:

    dest_ip = SOCKLIST.field[PFC.F_DEST_IP]
    dest_port = SOCKLIST.field[PFC.F_DEST_PORT]
    orig_ip = SOCKLIST.field[PFC.F_ORIG_IP]
    orig_port = SOCKLIST.field[PFC.F_ORIG_PORT]
    sock_stat = SOCKLIST.field[PFC.F_STATE]

    ip2host = IPLOOKUP.get_cached_hostname(dest_ip)

    session_pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port, "tcp6")
 
    proc_summary, proc_rc = PSI.pid_to_proc_summ(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format(
            orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary,
            sock_stat)
