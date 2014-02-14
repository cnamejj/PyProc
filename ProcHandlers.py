#!/usr/bin/env python

# ---
# (C) 2012-2014 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
Main programmatic interface to collected '/proc' file handlers

This is an umbrella module that imports all the classes that 
read/parse file in the '/proc' filesystem.  A registry mapping
specific files (and partial filenames) to handler objects is
created in the process.  And the are lookup routines included
which will let a calling program find and use the right handler
without having to import the other modules.
"""

import sys
import CachedDNS
import ProcessInfo
import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants
import ProcNetHandlers
import ProcRootHandlers
import ProcSelfHandlers

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

RegisterProcFileHandler = PBR.RegisterProcFileHandler
RegisterPartialProcFileHandler = PBR.RegisterPartialProcFileHandler
ShowProcFileHandlers = PBR.ShowProcFileHandlers
GetProcFileHandler = PBR.GetProcFileHandler
GetProcPartialFileRegistry = PBR.GetProcPartialFileRegistry
ShowHandlerFilePath = PBR.ShowHandlerFilePath
ProcFileToPath = PBR.ProcFileToPath

proc_file_handler_registry = PBR.proc_file_handler_registry

# ---
def display_handler_name(filepatt):
    """Display the name of the handler associated with the given file."""


    __hand = GetProcFileHandler(filepatt)()
    print "------------ File {inpfile} via {handler}".format(inpfile=filepatt,
            handler=__hand.__class__.__name__)

    return


# ---

if __name__ == "__main__":

    if sys.platform == "darwin":
        print "MacOS doesn't have a '/proc' filesystem, quitting."
        sys.exit(0)

    FLIST = dict()

    if len(sys.argv) > 1:
        WHICH = sys.argv[1]
        if WHICH == "all":
            FLIST = GetProcPartialFileRegistry()
        else:
            FLIST[WHICH] = GetProcFileHandler(WHICH)
    else:
        WHICH = "show"

    if len(sys.argv) > 2:
        QUALIFY = sys.argv[2]
    else:
        QUALIFY = ""

    IPLOOKUP = CachedDNS.CachedDNS()
    PSI = ProcessInfo

    NO_SESSION_PID = PSI.NO_CONN_PID
    NO_PROCESS_SUMMARY = PSI.NO_PROCESS_SUMMARY

    if WHICH == "show":
        ShowProcFileHandlers()

    else:
        for __file in FLIST:

            display_handler_name(__file)
            if QUALIFY != "":
                __qualified = "{base}/{subfile}".format(base=__file,
                        subfile=QUALIFY)
#                print "::dbg get instance with qualifier'{subfile}' \
#full'{fullname}'".format(subfile=QUALIFY, fullname=__qualified)
                __act = FLIST[__file](__qualified)
            else:
                __act = FLIST[__file]()

            if __file == "udp6" or __file == "udp" or __file == "tcp" \
                    or __file == "tcp6":

                for parse_slist in __act:

                    orig_hexip = __act.field[PFC.F_ORIG_HEXIP]
                    dest_hexip = __act.field[PFC.F_DEST_HEXIP]
                    orig_ip = __act.field[PFC.F_ORIG_IP]
                    dest_ip = __act.field[PFC.F_DEST_IP]
                    orig_port = __act.field[PFC.F_ORIG_PORT]
                    dest_port = __act.field[PFC.F_DEST_PORT]
                    sock_stat = __act.field[PFC.F_STATE]

                    dest_host = IPLOOKUP.get_cached_hostname(dest_ip)
                    pid = PSI.connection_to_pid(orig_port, dest_ip, dest_port,
                            __file)
                    psumm, psrc = PSI.pid_to_proc_summ(pid)

                    __template = "{file} {stat} {orip}:{orport} -> \
{dsip}:{dsport} PTR:{host} psumm'{ps}'"
                    print __template.format(file=__file, stat=sock_stat,
                            orip=orig_ip, orport=orig_port, dsip=dest_ip,
                            dsport=dest_port, host=dest_host, ps=psumm)
#                    print "{7:s} {0:s} {1:s}:{2:d} -> {3:s}:{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm, __file)

            elif __file == "igmp":

                for highlight in __act:
                    print highlight
                    print __act.field

            elif __file == "snmp6" or __file == "dev_snmp6":

                for keyvals in __act:
                    for key in keyvals:
                        print "{0:s} {1:s}".format(key, keyvals[key])

            elif __file == "sockstat" or __file == "sockstat6":

                for socktypelist in __act:
                    for socktype in socktypelist:
                        print socktype
                        keyvals = __act.field[socktype]
                        for key in keyvals:
                            print "-- {0:s} {1:s}".format(str(key),
                                str(keyvals[key]))

            elif __file == "ptype":

                for dev_type, dev_name, dev_func in __act:
                    print '{0:s} {1:s} "{2:s}"'.format(str(dev_type), dev_func,
                            dev_name)

            elif __file == "snmp" or __file == "netstat":

                for summ_results in __act:
                    lrec_prot = summ_results[0]
                    if lrec_prot != "":
                        print '--- protocol {0:s}'.format(lrec_prot)
                    for var_name in __act.field:
                        print '{0:s} : {1:s}'.format(var_name,
                                __act.field[var_name])

            else:

                for highlight in __act:
                    print highlight
