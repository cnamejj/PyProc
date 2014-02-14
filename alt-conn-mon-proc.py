#!/usr/bin/env python
"""
Display socket connections as they area created.

Check the contents of /proc/net/tcp for active TCP connections
and print new ones as they are found.  When the user ends the
program by entering ^C the code will print a summary of the
sockets that were found as it was written and the number of
times each was seen.
"""

import time
import sys
import CachedDNS
import ProcessInfo

import ProcHandlers
import ProcFieldConstants

GET_HANDLER = ProcHandlers.GetProcFileHandler

if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)
    
PFC = ProcFieldConstants

IPLOOKUP = CachedDNS.CachedDNS()
PSI = ProcessInfo

NO_SESSION_PID = PSI.NO_CONN_PID
NO_PROCESS_SUMMARY = PSI.NO_PROCESS_SUMMARY

SESSION_PAIR = set()
SEEN_FREQ = dict()

DONE = 0

HANDLE_TCP = GET_HANDLER("/proc/net/tcp")

try:
    while DONE != 1:

        NEW_SESSIONS = set()
        SOCKLIST = HANDLE_TCP()

        for proc_rec in SOCKLIST:
            orig_ip = SOCKLIST.field[PFC.F_ORIG_IP]
            orig_hexip = SOCKLIST.field[PFC.F_ORIG_HEXIP]
            orig_port = SOCKLIST.field[PFC.F_ORIG_PORT]
            dest_ip = SOCKLIST.field[PFC.F_DEST_IP]
            dest_hexip = SOCKLIST.field[PFC.F_DEST_HEXIP]
            dest_port = SOCKLIST.field[PFC.F_DEST_PORT]
            sock_stat = SOCKLIST.field[PFC.F_STATE]

#            print "--> ", dest_ip, dest_port, sock_stat
            if orig_hexip != "" and dest_hexip != "" and sock_stat != "LISTEN":
                key = "{0:s}:{1:d}:{2:s}:{3:d}".format(orig_ip, orig_port,
                          dest_ip, dest_port)
                if key not in SESSION_PAIR:
                    SESSION_PAIR.add(key)
                    NEW_SESSIONS.add((orig_port, dest_ip, dest_port))
                    if not SEEN_FREQ.has_key(dest_ip):
                        SEEN_FREQ[dest_ip] = 1
                    else:
                        SEEN_FREQ[dest_ip] += 1

        del SOCKLIST


        for orig_port, dest_ip, dest_port in NEW_SESSIONS:

            ip2host = IPLOOKUP.get_cached_hostname(dest_ip)

            session_pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port,
                              "tcp")

            proc_summary, proc_rc = PSI.pid_to_proc_summ(session_pid)

            print "{0:s}:{1:d} cmd: {3:s} host: {2:s}".format(dest_ip,
                    dest_port, ip2host, proc_summary)

        time.sleep(5)
        if len(NEW_SESSIONS) > 0:
            print "%s" % time.ctime(), len(NEW_SESSIONS)


except KeyboardInterrupt:
    print "Stopping..."

for ip in SEEN_FREQ:

    ip2host = IPLOOKUP.get_cache_entry(ip) 

    print "{0:d} {1:s} host: {2:s}".format(SEEN_FREQ[ip], ip, ip2host)

sys.stderr.flush()
sys.stdout.flush()
