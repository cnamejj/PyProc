#!/usr/bin/env python

import ProcessInfo
import sys

if len(sys.argv) > 1:
    target = sys.argv[1]
else:
    target = "1"

res = ProcessInfo.PID_to_proc_summ(int(target))

print "pid:{pid:d} info({info})".format(pid=int(target), info=res)

