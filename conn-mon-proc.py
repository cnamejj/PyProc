#!/usr/bin/env python
"""
Display socket connections as they area created.

Check the contents of /proc/net/tcp for active TCP connections
and print new ones as they are found.  When the user ends the
program by entering ^C the code will print a summary of the
sockets that were found as it was written and the number of
times each was seen.
"""


# pylint: disable=C0103

import time
import sys
import operator

import ProcHandlers
import ProcessInfo
import CachedDNS

if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)

IPLOOKUP = CachedDNS.LookupIP()
PSI = ProcessInfo

NO_SESSION_PID = PSI.NO_CONN_PID
NO_PROCESS_SUMMARY = PSI.NO_PROCESS_SUMMARY

SESSION_PAIR = set()
SEEN_FREQ = dict()

DONE = False

while not DONE:

    try:
        NEW_SESSIONS = set()
        SOCKLIST = ProcHandlers.GET_HANDLER("tcp")()

        for orig_hexip, \
            dest_hexip, \
            orig_ip, \
            orig_port, \
            dest_ip, \
            dest_port, \
            sock_stat in SOCKLIST:
#            print "--> ", dest_ip, dest_port, sock_stat
            if orig_hexip != "" and dest_hexip != "" and sock_stat != "LISTEN":
                key = "{0:s}:{1:d}:{2:s}:{3:d}".format(orig_ip, orig_port,
                          dest_ip, dest_port)
                if key not in SESSION_PAIR:
                    SESSION_PAIR.add(key)
                    NEW_SESSIONS.add( (orig_port, dest_ip, dest_port) )
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
        DONE = True

ORDERED_FREQ = sorted(SEEN_FREQ.items(), key=operator.itemgetter(1))

for ip, freq in ORDERED_FREQ:

    ip2host = IPLOOKUP.get_cache_entry(ip)

    print "{0:d} {1:s} host: {2:s}".format(freq, ip, ip2host)

sys.stderr.flush()
sys.stdout.flush()
