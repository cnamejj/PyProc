#!/usr/bin/env python
"""Get process related info from ip/port unique socket info

Describe what's in this module and put that info here...
"""
    
from subprocess import Popen, PIPE

ANY_IPV6_ADDR = "::"
ANY_IP_ADDR = "0.0.0.0"
PRESENT_ANY_IPV6_ADDR = "::0"
PRESENT_ANY_IP_ADDR = "0.0.0.0"

class ProcessInfo:

    def __init__(self):
        self.__NO_CONN_PID = -1
        self.__NO_PROCESS_SUMMARY = "n/a"
        self.__ps_returncode = None

#       Lines for 'pylint'
        self.__ps_retcode = None

    def map_connection_to_PID(self, loc_port, rem_ip, rem_port, net_protocol):
        __rip = rem_ip
        if __rip == ANY_IPV6_ADDR or __rip == ANY_IP_ADDR or __rip == PRESENT_ANY_IPV6_ADDR or __rip == PRESENT_ANY_IP_ADDR:
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

        __fuser_arg = "{0:d},{1:s},{2:s}/{3:s}".format( loc_port, __rip, __rpo, __prot)
#        print '::dbg', __prot, __fuser_arg, __ipv


        try:
            __fufd = Popen( ["fuser", __fuser_arg, __ipv], stdout=PIPE, stderr=PIPE)

            __sout_buff, __serr_buff = __fufd.communicate()
#            print '::dbg ({0:s})'.format(__sout_buff)
            if __sout_buff != "":
#                Trying to make "pylint" happy here...
                __pid = long( str(__sout_buff).split()[0], 10)
            else:
                __pid = self.__NO_CONN_PID

        except:
            __pid = self.__NO_CONN_PID

        return __pid

    def map_PID_to_process_summary(self, targetpid):
        __psumm = self.__NO_PROCESS_SUMMARY
        self.__ps_retcode = None

        if targetpid != self.__NO_CONN_PID:
            __ps_arg = "{0:d}".format(targetpid)
            try:
                __ps_fd = Popen( ["ps", "--no-headers", "-o", "user,pid,cmd", "-p", __ps_arg], stdout=PIPE, stderr=PIPE)

                __sout_buff, __serr_buff = __ps_fd.communicate()
                if __sout_buff != "":
                    __psumm = __sout_buff[:-1]

            except:
                self.__ps_returncode = __ps_fd.returncode

        return __psumm
 

    def get_PID_err_value(self):
        return self.__NO_CONN_PID

    def get_process_summary_err_value(self):
        return self.__NO_PROCESS_SUMMARY

    def get_ps_returncode(self):
        return self.__ps_returncode



if __name__ == "__main__":

    print "This is a library of routines to get info about running processes."
