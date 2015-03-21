#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

# pylint: disable=W0614,W0401

import ProcHandlers as PH
import sys
from regentest import *
import regentest as RG


# ---

PFC = PH.ProcFieldConstants

# ---

if __name__ == "__main__":

    NOFUNC = 0

    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = "/proc/net/tcp6"

    if len(sys.argv) > 2:
        CNAME = sys.argv[2]
    else:
        CNAME = TARGET

    HANDLER = PH.GET_HANDLER(CNAME)
    try:
        RECREATE = RG.RECREATOR[HANDLER]
    except KeyError:
        RECREATE = NOFUNC

    if type(NOFUNC) == type(RECREATE):
        print "There's no recreator code available for file '{inp}' yet".\
format(inp=TARGET)

    else:
        ACTIVE = HANDLER(TARGET)
        RECREATE(ACTIVE)

# ---

# pylint: disable=W0702

try:
    sys.stdout.close()

except:
    pass

try:
    sys.stderr.close()

except:
    pass
