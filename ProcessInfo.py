#!/usr/bin/env python
"""Get process related info from ip/port unique socket info"""
    
from subprocess import Popen, PIPE
import pwd

import ProcHandlers
PH = ProcHandlers
PFC = PH.ProcFieldConstants

ANY_IPV6_ADDR = "::"
ANY_IP_ADDR = "0.0.0.0"
PRESENT_ANY_IPV6_ADDR = "::0"
PRESENT_ANY_IP_ADDR = "0.0.0.0"
NO_PROCESS_SUMMARY = "n/a"
NO_CONN_PID = -1
NO_RETURNCODE = None
NO_UID = -1
NO_COMMAND = "unknown"
NO_USER = "unknown"

def pid_to_process_summ(targetpid = "self"):
    """Lookup username, uid, pid and comm of the indicated process"""

    __uid = NO_UID
    __pid = NO_CONN_PID
    __comm = NO_COMMAND
    __user = NO_USER

    __stat_file = "/proc/{pid}/status".format(pid=targetpid)

    __act = PH.GET_HANDLER(__stat_file)(__stat_file)

    for __hilit in __act:
        if __uid == NO_UID:
            __uid = __act.field[PFC.F_UID]
            __pid = __act.field[PFC.F_PID]
            __comm = __act.field[PFC.F_PROG_NAME]
            try:
                __uinfo = pwd.getpwuid(__uid)
                __user = __uinfo.pw_name
            except KeyError:
                pass

    return(__user, __uid, __pid, __comm)


def pid_to_proc_summ(targetpid):
    """Return basic process info associated with the given PID"""

    __ps_summ = NO_PROCESS_SUMMARY
    __ps_returncode = None

    try:
        __ps_arg = '{pid:d}'.format(pid=targetpid)
    except ValueError:
        __ps_arg = NO_CONN_PID

    if __ps_arg != NO_CONN_PID:
        try:
            __ps_comm = ["ps", "--no-headers", "-o", "user,pid,cmd", \
                    "-p", __ps_arg]
            __ps_fd = Popen(__ps_comm, stdout=PIPE, stderr=PIPE)

            __sout_buff, __serr_buff = __ps_fd.communicate()
            if __sout_buff != "":
                __ps_summ = __sout_buff[:-1]
            __ps_returncode = __ps_fd.returncode

        except ValueError:
            __ps_summ = NO_PROCESS_SUMMARY
            __ps_returncode = -999

        except OSError:
            __ps_summ = NO_PROCESS_SUMMARY
            __ps_returncode = -999

    return __ps_summ, __ps_returncode
 

def connection_to_pid(loc_port, rem_ip, rem_port, net_protocol):
    """Return the PID that has the given socket connections open."""

    __rip = rem_ip

    if  __rip == PRESENT_ANY_IPV6_ADDR or __rip == PRESENT_ANY_IP_ADDR:
        __rip = ""
    elif __rip == ANY_IPV6_ADDR or __rip == ANY_IP_ADDR:
        __rip = ""

    __rpo = str(rem_port)
    if __rpo == "0":
        __rpo = ""

    __prot = net_protocol
    if __prot == "udp6" or __prot == "tcp6":
        __prot = __prot[:-1]
        __ipv = "-6"
    else:
        __ipv = "-4"

    __fuser_arg = "{lport:d},{rip:s},{rport:s}/{prot:s}".format(lport=loc_port,
            rip=__rip, rport=__rpo, prot=__prot)
#    print '::dbg', __prot, __fuser_arg, __ipv


    try:
        __fufd = Popen(["fuser", __fuser_arg, __ipv], stdout=PIPE, stderr=PIPE)

        __sout_buff, __serr_buff = __fufd.communicate()
#        print '::dbg ({0:s})'.format(__sout_buff)
        if __sout_buff != "":
#            Trying to make "pylint" happy here...
            __pid = long(str(__sout_buff).split()[0])
        else:
            __pid = NO_CONN_PID

    except ValueError:
        __pid = NO_CONN_PID

    except OSError:
        __pid = NO_CONN_PID

    return __pid


if __name__ == "__main__":

    print "This is a library of routines to get info about running processes."
