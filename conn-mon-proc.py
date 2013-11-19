#!/usr/bin/env python
"""Display socket connections as they area created.

Check the contents of /proc/net/tcp for active TCP connections
and print new ones as they are found.  When the user ends the
program by entering ^C the code will print a summary of the
sockets that were found as it was written and the number of
times each was seen.
"""

import time
import sys

from ProcSysInfo import ProcNetTCP, CachedDNS, ProcessInfo
    
if sys.platform == "darwin":
    print "MacOS doesn't have a '/proc' filesystem, quitting."
    sys.exit(0)

iplookup = CachedDNS()
procinfo = ProcessInfo()

NO_SESSION_PID = procinfo.get_PID_err_value()
NO_PROCESS_SUMMARY = procinfo.get_process_summary_err_value()

session_pair = set()
seen_freq = dict()

done = 0

try:
    while done != 1:

        new_sessions = set()
        socklist = ProcNetTCP()

        for orig_hexip, dest_hexip, orig_ip, orig_port, dest_ip, dest_port, sock_stat in socklist:
#            print "--> ", dest_ip, dest_port, sock_stat
            if orig_hexip != "" and dest_hexip != "" and sock_stat != "LISTEN":
                key = "{0:s}:{1:d}:{2:s}:{3:d}".format( orig_ip, orig_port, dest_ip, dest_port)
                if key not in session_pair:
                    session_pair.add(key)
                    new_sessions.add( (orig_port, dest_ip, dest_port))
                    if not seen_freq.has_key(dest_ip):
                        seen_freq[dest_ip] = 1
                    else:
                        seen_freq[dest_ip] += 1

        del socklist


        for orig_port, dest_ip, dest_port in new_sessions:

            ip2host = iplookup.get_cached_hostname(dest_ip)

            session_pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, "tcp")

            proc_summary = procinfo.map_PID_to_process_summary(session_pid)

            print "{0:s}:{1:d} cmd: {3:s} host: {2:s}".format( dest_ip, dest_port, ip2host, proc_summary)

        time.sleep(5)
        if len( new_sessions) > 0:
            print "%s" % time.ctime(), len(new_sessions)


except KeyboardInterrupt:
    print "Stopping..."

for ip in seen_freq:

    ip2host = iplookup.get_cache_entry( ip) 

    print "{0:d} {1:s} host: {2:s}".format( seen_freq[ip], ip, ip2host)

sys.stderr.flush()
sys.stdout.flush()
