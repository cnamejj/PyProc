#!/usr/bin/env python
"""Show all current TCP connections with local ip/port, remote ip/port, remote hostname, process name and process owner

Data is pulled from /proc filesystem.
"""

import sys

from ProcSysInfo import ProcNetTCP, CachedDNS, ProcessInfo, ProcNetTCP6

if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)

iplookup = CachedDNS()
procinfo = ProcessInfo()
socklist = ProcNetTCP()

for orig_hexip, dest_hexip, orig_ip, orig_port, dest_ip, dest_port, sock_stat in socklist:

    ip2host = iplookup.get_cached_hostname(dest_ip)

    session_pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp")
 
    proc_summary = procinfo.map_PID_to_process_summary(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format( orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary, sock_stat)

socklist = ProcNetTCP6()

for orig_hexip, dest_hexip, orig_ip, orig_port, dest_ip, dest_port, sock_stat in socklist:

    ip2host = iplookup.get_cached_hostname(dest_ip)

    session_pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp6")
 
    proc_summary = procinfo.map_PID_to_process_summary(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format( orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary, sock_stat)
