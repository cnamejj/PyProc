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

def number_or_unlimited(buff):

    if buff.strip() == "unlimited":
        result = numpy.inf
    else:
        try:
            result = long(buff)
        except:
            result = numpy.nan

    return result

# ---
class ProcSelfLIMITS(PBR.fixed_column_field_recs):
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

        self.fixedcols[PFC.F_LIMIT] = (0, 25)
        self.fixedcols[PFC.F_SOFT_LIMIT] = (26, 46)
        self.fixedcols[PFC.F_HARD_LIMIT] = (47, 67)
        self.fixedcols[PFC.F_UNITS] = (68, -1)


        self.limit = ""
        self.soft_limit = 0
        self.hard_limit = 0
        self.units = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# Limit                     Soft Limit           Hard Limit           Units     
# Max cpu time              unlimited            unlimited            seconds   
# Max file size             unlimited            unlimited            bytes     
# Max stack size            8388608              unlimited            bytes     

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_LIMIT] = ""
            self.field[PFC.F_SOFT_LIMIT] = 0
            self.field[PFC.F_HARD_LIMIT] = 0
            self.field[PFC.F_UNITS] = ""

        else:
            self.field[PFC.F_LIMIT] = self.field[PFC.F_LIMIT].strip()
            self.field[PFC.F_SOFT_LIMIT] = number_or_unlimited(self.field[PFC.F_SOFT_LIMIT])
            self.field[PFC.F_HARD_LIMIT] = number_or_unlimited(self.field[PFC.F_HARD_LIMIT])
            self.field[PFC.F_UNITS] = self.field[PFC.F_UNITS].strip()

        self.limit = self.field[PFC.F_LIMIT]
        self.soft_limit = self.field[PFC.F_SOFT_LIMIT]
        self.hard_limit = self.field[PFC.F_HARD_LIMIT]
        self.units = self.field[PFC.F_UNITS]

        return(self.limit, self.soft_limit, self.hard_limit, self.units)

#
RegisterProcFileHandler("/proc/self/limits", ProcSelfLIMITS)
RegisterPartialProcFileHandler("limits", ProcSelfLIMITS)



# ---
class ProcSelfMAPS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/maps"""
# source: fs/proc/nommu.c
#
#    seq_printf(m,
#               "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu %n",
#               region->vm_start,
#               region->vm_end,
#               flags & VM_READ ? 'r' : '-',
#               flags & VM_WRITE ? 'w' : '-',
#               flags & VM_EXEC ? 'x' : '-',
#               flags & VM_MAYSHARE ? flags & VM_SHARED ? 'S' : 's' : 'p',
#               ((loff_t)region->vm_pgoff) << PAGE_SHIFT,
#               MAJOR(dev), MINOR(dev), ino, &len);
#
#    if (file) {
#            len = 25 + sizeof(void *) * 6 - len;
#            if (len < 1)
#                    len = 1;
#            seq_printf(m, "%*c", len, ' ');
#            seq_path(m, &file->f_path, "");
#    }
#
#    seq_putc(m, '\n');

    def extra_init(self, *opts):
        self.minfields = 5

        self.__AddrSplitDelim = "-"
        self.__DevSplitDelim = ":"

        self.vm_start = 0
        self.vm_end = 0
        self.flags = ""
        self.vm_page = 0
        self.major = 0
        self.minor = 0
        self.inode = 0
        self.path = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 00400000-0041e000 r-xp 00000000 09:01 149422083                          /bin/cp
# 0061d000-0061e000 r--p 0001d000 09:01 149422083                          /bin/cp
# 0061f000-00620000 rw-p 00000000 00:00 0 
# 00be3000-00c04000 rw-p 00000000 00:00 0                                  [heap]
# 7facdda3a000-7facddd03000 r--p 00000000 09:01 29890584                   /usr/lib/locale/locale-archive
# 7facddd03000-7facddd1b000 r-xp 00000000 09:01 75238943                   /lib/x86_64-linux-gnu/libpthread-2.15.so
# 7facddd1b000-7facddf1a000 ---p 00018000 09:01 75238943                   /lib/x86_64-linux-gnu/libpthread-2.15.so

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_START] = 0
            self.field[PFC.F_END] = 0
            self.field[PFC.F_FLAGS] = ""
            self.field[PFC.F_PAGE_OFFSET] = 0
            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_PATH] = ""

        else:
            __split = sio.lineparts[0].partition(self.__AddrSplitDelim)
            self.field[PFC.F_START] = long(__split[0], 16)
            self.field[PFC.F_END] = long(__split[2], 16)

            self.field[PFC.F_FLAGS] = sio.lineparts[1]

            self.field[PFC.F_PAGE_OFFSET] = long(sio.lineparts[2], 16)

            __split = sio.lineparts[3].partition(self.__DevSplitDelim)
            self.field[PFC.F_MAJOR_DEV] = long(__split[0], 16)
            self.field[PFC.F_MINOR_DEV] = long(__split[2], 16)

            self.field[PFC.F_INODE] = long(sio.lineparts[4])

            if sio.linewords > 5:
                self.field[PFC.F_PATH] = sio.lineparts[5]
            else:
                self.field[PFC.F_PATH] = ""

        self.vm_start = self.field[PFC.F_START]
        self.vm_end = self.field[PFC.F_END]
        self.flags = self.field[PFC.F_FLAGS]
        self.vm_page = self.field[PFC.F_PAGE_OFFSET]
        self.major = self.field[PFC.F_MAJOR_DEV]
        self.minor = self.field[PFC.F_MINOR_DEV]
        self.inode = self.field[PFC.F_INODE]
        self.path = self.field[PFC.F_PATH]

        return(self.vm_start, self.vm_end, self.flags, self.vm_page, self.major, self.minor, self.inode, self.path)

#
RegisterProcFileHandler("/proc/self/maps", ProcSelfMAPS)
RegisterPartialProcFileHandler("maps", ProcSelfMAPS)



# ---
class ProcSelfSTACK(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/stack"""
# source: fs/proc/base.c
#
#            for (i = 0; i < trace.nr_entries; i++) {
#                    seq_printf(m, "[<%pK>] %pS\n",
#                               (void *)entries[i], (void *)entries[i]);
#            }

    def extra_init(self, *opts):
        self.minfields = 2

        self.address_string = ""
        self.address = 0
        self.stack_entry = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# The first field, the address, is '0000000000000000' for everyone but "root"
#
# [<ffffffff81021486>] save_stack_trace_tsk+0x26/0x50
# [<ffffffff811d8ddc>] proc_pid_stack+0xbc/0x110
# [<ffffffff811d9f9c>] proc_single_show+0x5c/0xa0
# [<ffffffff8119a60b>] seq_read+0x12b/0x3d0
# [<ffffffff81177ec0>] vfs_read+0xb0/0x180

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_ADDRESS] = 0
            self.field[PFC.F_STACK_ENTRY] = ""

        else:
            self.field[PFC.F_ADDRESS] = long(sio.lineparts[0][2:-2], 16)
            self.field[PFC.F_STACK_ENTRY] = sio.lineparts[1]

        self.address_string = sio.lineparts[0]
        self.address = self.field[PFC.F_ADDRESS]
        self.stack_entry = self.field[PFC.F_STACK_ENTRY]

        return(self.address_string, self.address, self.stack_entry)

#
RegisterProcFileHandler("/proc/self/stack", ProcSelfSTACK)
RegisterPartialProcFileHandler("stack", ProcSelfSTACK)



# ---
class ProcSelfIO(PBR.single_name_value_list):
    """Pull records from /proc/net/io"""
#
# source: fs/proc/base.c
#
#    result = sprintf(buffer,
#                    "rchar: %llu\n"
#                    "wchar: %llu\n"
#                    "syscr: %llu\n"
#                    "syscw: %llu\n"
#                    "read_bytes: %llu\n"
#                    "write_bytes: %llu\n"
#                    "cancelled_write_bytes: %llu\n",
#                    (unsigned long long)acct.rchar,
#                    (unsigned long long)acct.wchar,
#                    (unsigned long long)acct.syscr,
#                    (unsigned long long)acct.syscw,
#                    (unsigned long long)acct.read_bytes,
#                    (unsigned long long)acct.write_bytes,
#                    (unsigned long long)acct.cancelled_write_bytes);
#
# -- Sample records.  This file a series of key/value entries, one per line.
#
# rchar: 2012
# wchar: 0
# syscr: 7
# syscw: 0
# read_bytes: 0
# write_bytes: 0
# cancelled_write_bytes: 0

    def extra_init(self, *opts):

        self.trim_tail = ":"
#        self.debug_level = 1
        return

RegisterProcFileHandler("/proc/net/io", ProcSelfIO)
RegisterPartialProcFileHandler("io", ProcSelfIO)
