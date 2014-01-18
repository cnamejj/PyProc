#!/usr/bin/env python

# ---
# (C) 2012-2013 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.


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

state_list = PDC.state_list

proc_file_handler_registry = PBR.proc_file_handler_registry

# ---
def DispHandlerSep(filepatt):

    __hand = GetProcFileHandler(filepatt)()
    print "------------ File {inpfile} via {handler}".format(inpfile=filepatt, handler=__hand.__class__.__name__)

    return


# ---

if __name__ == "__main__":

    if sys.platform == "darwin":
        print "MacOS doesn't have a '/proc' filesystem, quitting."
        sys.exit(0)

    flist = dict()

    if len(sys.argv) > 1:
        which = sys.argv[1]
        if which == "all":
            flist = GetProcPartialFileRegistry()
        else:
            flist[which] = GetProcFileHandler(which)
    else:
        which = "show"

    if len(sys.argv) > 2:
        qualify = sys.argv[2]
    else:
        qualify = ""

    iplookup = CachedDNS.CachedDNS()
    procinfo = ProcessInfo.ProcessInfo()

    NO_SESSION_PID = procinfo.get_PID_err_value()
    NO_PROCESS_SUMMARY = procinfo.get_process_summary_err_value()

    if which == "show":
        ShowProcFileHandlers()

    else:
        for __file in flist:

            DispHandlerSep(__file)
            if qualify != "":
                __qualified = "{base}/{subfile}".format(base=__file, subfile=qualify)
#                print "::dbg get instance with qualifier'{subfile}' full'{fullname}'".format(subfile=qualify, fullname=__qualified)
                __act = flist[__file](__qualified)
            else:
                __act = flist[__file]()

            if __file == "udp6" or __file == "udp" or __file == "tcp" or __file == "tcp6":

                for parse_slist in __act:

                    orig_hexip = __act.field[PFC.F_ORIG_HEXIP]
                    dest_hexip = __act.field[PFC.F_DEST_HEXIP]
                    orig_ip = __act.field[PFC.F_ORIG_IP]
                    dest_ip = __act.field[PFC.F_DEST_IP]
                    orig_port = __act.field[PFC.F_ORIG_PORT]
                    dest_port = __act.field[PFC.F_DEST_PORT]
                    sock_stat = __act.field[PFC.F_STATE]

                    dest_host = iplookup.get_cached_hostname(dest_ip)
                    pid = procinfo.map_connection_to_PID(orig_port, dest_ip, dest_port, __file)
                    psumm = procinfo.map_PID_to_process_summary(pid)

                    print "{7:s} {0:s} {1:s}:{2:d} -> {3:s}:{4:d} PTR:{5:s} psumm:'{6:s}'".format(sock_stat, orig_ip, orig_port, dest_ip, dest_port, dest_host, psumm, __file)

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
                            print "-- {0:s} {1:s}".format(str(key), str(keyvals[key]))

            elif __file == "ptype":

                for dev_type, dev_name, dev_func in __act:
                    print '{0:s} {1:s} "{2:s}"'.format(str(dev_type), dev_func, dev_name)

            elif __file == "snmp" or __file == "netstat":

                for summ_results in __act:
                    lrec_prot = summ_results[0]
                    if lrec_prot != "":
                        print '--- protocol {0:s}'.format(lrec_prot)
                    for var_name in __act.field:
                        print '{0:s} : {1:s}'.format(var_name, __act.field[var_name])

            else:

                for highlight in __act:
                    print highlight
