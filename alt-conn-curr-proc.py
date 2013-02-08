#!/usr/bin/env python
"""Show all current TCP connections with local ip/port, remote ip/port, remote hostname, process name and process owner

Data is pulled from /proc filesystem.
"""

import ProcSysInfo
from ProcSysInfo import CachedDNS, ProcessInfo, GetProcFileHandler

iplookup = CachedDNS()
procinfo = ProcessInfo()
psi = ProcSysInfo

socklist = GetProcFileHandler("/proc/net/tcp")()

for proc_rec in socklist:

    dest_ip = socklist.field[psi.F_DEST_IP]
    dest_port = socklist.field[psi.F_DEST_PORT]
    orig_ip = socklist.field[psi.F_ORIG_IP]
    orig_port = socklist.field[psi.F_ORIG_PORT]
    sock_stat = socklist.field[psi.F_STATE]

    ip2host = iplookup.get_cached_hostname(dest_ip)

    session_pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp")
 
    proc_summary = procinfo.map_PID_to_process_summary(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format( orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary, sock_stat)

socklist = GetProcFileHandler("/proc/net/tcp6")()

for proc_rec in socklist:

    dest_ip = socklist.field[psi.F_DEST_IP]
    dest_port = socklist.field[psi.F_DEST_PORT]
    orig_ip = socklist.field[psi.F_ORIG_IP]
    orig_port = socklist.field[psi.F_ORIG_PORT]
    sock_stat = socklist.field[psi.F_STATE]

    ip2host = iplookup.get_cached_hostname(dest_ip)

    session_pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp6")
 
    proc_summary = procinfo.map_PID_to_process_summary(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format( orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary, sock_stat)
