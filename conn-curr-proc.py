#!/usr/bin/env python
"""
Show all current TCP connections with local ip/port, remote
ip/port, remote hostname, process name and process owner.  Data
is pulled from /proc filesystem.
"""

# pylint: disable=C0103


import sys

import ProcHandlers
import ProcessInfo
import CachedDNS

if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)

IPLOOKUP = CachedDNS.LookupIP()
PSI = ProcessInfo
SOCKLIST = ProcHandlers.GET_HANDLER("tcp")()

for orig_hexip, \
    dest_hexip, \
    orig_ip, \
    orig_port, \
    dest_ip, \
    dest_port, \
    sock_stat in SOCKLIST:

    ip2host = IPLOOKUP.get_cached_hostname(dest_ip)

    session_pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port, "tcp")

    proc_summary, proc_rc = PSI.pid_to_proc_summ(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format(
            orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary,
            sock_stat)

SOCKLIST = ProcHandlers.GET_HANDLER("tcp6")()

for orig_hexip, \
    dest_hexip, \
    orig_ip, \
    orig_port, \
    dest_ip, \
    dest_port, \
    sock_stat in SOCKLIST:

    ip2host = IPLOOKUP.get_cached_hostname(dest_ip)

    session_pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port, "tcp6")

    proc_summary, proc_rc = PSI.pid_to_proc_summ(session_pid)

    print "{0:s}:{1:d} {2:s}:{3:d} {6:s} cmd: {5:s} host: {4:s}".format(
            orig_ip, orig_port, dest_ip, dest_port, ip2host, proc_summary,
            sock_stat)
