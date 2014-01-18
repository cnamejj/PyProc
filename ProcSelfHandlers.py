#!/usr/bin/env python

# ---
# (C) 2012-2013 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

import numpy
import ProcBaseRoutines
import ProcFieldConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants

RegisterProcFileHandler = PBR.RegisterProcFileHandler
RegisterPartialProcFileHandler = PBR.RegisterPartialProcFileHandler


# --- !!! move to the end once all the handlers are added !!!
if __name__ == "__main__":

    print "Collection of handlers to parse file in the root /proc/self and /proc/[0-9]* directories"

# ---

def number_or_unlimited(buffer):

    if buffer.strip() == "unlimited":
        result = numpy.inf
    else:
        try:
            result = long(buffer)
        except:
            result = numpy.nan

    return result

# ---
class ProcSelfLIMITS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/limits"""
# source: fs/proc/base.c
#
#        count += sprintf(&bufptr[count], "%-25s %-20s %-20s %-10s\n",
#                        "Limit", "Soft Limit", "Hard Limit", "Units");
#
#        for (i = 0; i < RLIM_NLIMITS; i++) {
#                if (rlim[i].rlim_cur == RLIM_INFINITY)
#                        count += sprintf(&bufptr[count], "%-25s %-20s ",
#                                         lnames[i].name, "unlimited");
#                else
#                        count += sprintf(&bufptr[count], "%-25s %-20lu ",
#                                         lnames[i].name, rlim[i].rlim_cur);
#
#                if (rlim[i].rlim_max == RLIM_INFINITY)
#                        count += sprintf(&bufptr[count], "%-20s ", "unlimited");
#                else
#                        count += sprintf(&bufptr[count], "%-20lu ",
#                                         rlim[i].rlim_max);
#
#                if (lnames[i].unit)
#                        count += sprintf(&bufptr[count], "%-10s\n",
#                                         lnames[i].unit);
#                else
#                        count += sprintf(&bufptr[count], "\n");
#        }

    def extra_init(self, *opts):
        self.minfields = 4
        self.skipped = "Limit"

        self.__fixed = { PFC.F_LIMIT: (0, 25), PFC.F_SOFT_LIMIT: (26, 46), PFC.F_HARD_LIMIT: (47, 67), PFC.F_UNITS: (68, -1) }

        self.limit = ""
        self.soft_limit = 0
        self.hard_limit = 0
        self.units = ""
        return

    def extra_next(self, sio):

# -- Sample records
#

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_LIMIT] = ""
            self.field[PFC.F_SOFT_LIMIT] = 0
            self.field[PFC.F_HARD_LIMIT] = 0
            self.field[PFC.F_UNITS] = ""

        else:
            __fc = self.__fixed[PFC.F_LIMIT]
            self.field[PFC.F_LIMIT] = sio.buff[__fc[0]:__fc[1]]
            __fc = self.__fixed[PFC.F_SOFT_LIMIT]
            self.field[PFC.F_SOFT_LIMIT] = number_or_unlimited(sio.buff[__fc[0]:__fc[1]])
            __fc = self.__fixed[PFC.F_HARD_LIMIT]
            self.field[PFC.F_HARD_LIMIT] = number_or_unlimited(sio.buff[__fc[0]:__fc[1]])
            __fc = self.__fixed[PFC.F_UNITS]
            self.field[PFC.F_UNITS] = sio.buff[__fc[0]:__fc[1]]

        self.limit = self.field[PFC.F_LIMIT]
        self.soft_limit = self.field[PFC.F_SOFT_LIMIT]
        self.hard_limit = self.field[PFC.F_HARD_LIMIT]
        self.units = self.field[PFC.F_UNITS]

        return(self.limit, self.soft_limit, self.hard_limit, self.units)

#
RegisterProcFileHandler("/proc/self/limits", ProcSelfLIMITS)
RegisterPartialProcFileHandler("limits", ProcSelfLIMITS)
