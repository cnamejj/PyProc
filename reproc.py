#!/usr/bin/env python

"""Code to re-create /proc data files from parsed records"""

import ProcHandlers as PH
import sys
from regentest import *
import regentest as RG

# ---

PFC = PH.ProcFieldConstants

# ---

if __name__ == "__main__":

    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = "/proc/net/tcp6"

    if len(sys.argv) > 2:
        CNAME = sys.argv[2]
    else:
        CNAME = TARGET

    handler = PH.GET_HANDLER(CNAME)
    recreate = RG.RECREATOR[handler]
    active = handler(TARGET)

    recreate(active)

