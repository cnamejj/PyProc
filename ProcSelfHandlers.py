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



# ---
class ProcSelfNUMA_MAPS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/numa_maps"""
#
# source: fs/proc/task_mmu.c
#
#    seq_printf(m, "%08lx %s", vma->vm_start, buffer);
#
#    if (file) {
#            seq_printf(m, " file=");
#            seq_path(m, &file->f_path, "\n\t= ");
#    } else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
#            seq_printf(m, " heap");
#    } else if (vma->vm_start <= mm->start_stack &&
#                    vma->vm_end >= mm->start_stack) {
#            seq_printf(m, " stack");
#    }
#
#    if (is_vm_hugetlb_page(vma))
#            seq_printf(m, " huge");
#
#    walk_page_range(vma->vm_start, vma->vm_end, &walk);
#
#    if (!md->pages)
#            goto out;
#
#    if (md->anon)
#            seq_printf(m, " anon=%lu", md->anon);
#
#    if (md->dirty)
#            seq_printf(m, " dirty=%lu", md->dirty);
#
#    if (md->pages != md->anon && md->pages != md->dirty)
#            seq_printf(m, " mapped=%lu", md->pages);
#
#    if (md->mapcount_max > 1)
#            seq_printf(m, " mapmax=%lu", md->mapcount_max);
#
#    if (md->swapcache)
#            seq_printf(m, " swapcache=%lu", md->swapcache);
#
#    if (md->active < md->pages && !is_vm_hugetlb_page(vma))
#            seq_printf(m, " active=%lu", md->active);
#
#    if (md->writeback)
#            seq_printf(m, " writeback=%lu", md->writeback);
#
#    for_each_node_state(n, N_HIGH_MEMORY)
#            if (md->node[n])
#                    seq_printf(m, " N%d=%lu", n, md->node[n]);
# out:
#    seq_putc(m, '\n');

    def extra_init(self, *opts):
        self.minfields = 2

        self.start = 0
        self.buffname = ""
        self.path = ""
        self.heap = 0
        self.stack = 0
        self.huge = 0
        self.anon = 0
        self.dirty = 0
        self.mapped = 0
        self.mapmax = 0
        self.swapcache = 0
        self.activepages = 0
        self.writeback = 0
        self.node_list = dict()

        self.__ASSIGN_DELIM = "="
        self.__PREFIX_PATH = "file="
        self.__PREFIX_ANON = "anon="
        self.__PREFIX_DIRTY = "dirty="
        self.__PREFIX_MAPPED = "mapped="
        self.__PREFIX_MAPMAX = "mapmax="
        self.__PREFIX_SWAPCACHE = "swapcache="
        self.__PREFIX_ACTIVE_PAGES = "active="
        self.__PREFIX_WRITEBACK = "writeback="
        self.__PREFIX_NODE = "N"
        self.__FLAG_HEAP = "heap"
        self.__FLAG_STACK = "stack"
        self.__FLAG_HUGE = "huge"
        return

    def get_long_after_pref(self, sio, offset, prefix, fieldname):
        if sio.linewords > offset:
            if sio.lineparts[offset].startswith(prefix):
                self.field[fieldname] = long(sio.lineparts[offset][len(prefix):])
                offset = offset + 1
        return(offset)

    def extra_next(self, sio):

# -- Sample records
#
# 00400000 default file=/bin/cat mapped=7 mapmax=2 N0=7
# 0060a000 default file=/bin/cat anon=1 dirty=1 N0=1
# 0060b000 default file=/bin/cat anon=1 dirty=1 N0=1
# 01b69000 default heap anon=3 dirty=3 active=0 N0=3
# 7f5935a28000 default file=/usr/lib/locale/locale-archive mapped=11 mapmax=88 N0=11
# 7f5935cf1000 default file=/lib/x86_64-linux-gnu/libc-2.15.so mapped=82 mapmax=167 N0=82

        self.field = dict()

        self.field[PFC.F_START] = 0
        self.field[PFC.F_BUFFNAME] = ""
        self.field[PFC.F_FILEPATH] = ""
        self.field[PFC.F_HEAP] = 0
        self.field[PFC.F_STACK] = 0
        self.field[PFC.F_HUGE] = 0
        self.field[PFC.F_ANON] = 0
        self.field[PFC.F_DIRTY] = 0
        self.field[PFC.F_MAPPED] = 0
        self.field[PFC.F_MAPMAX] = 0
        self.field[PFC.F_SWAPCACHE] = 0
        self.field[PFC.F_ACTIVE_PAGES] = 0
        self.field[PFC.F_WRITEBACK] = 0
        self.field[PFC.F_NODE_LIST] = dict()

        if sio.buff != "":

            self.field[PFC.F_START] = long(sio.lineparts[0], 16)
            self.field[PFC.F_BUFFNAME] = sio.lineparts[1]

            __off = 2
            if sio.linewords > __off:
                __curr = sio.lineparts[__off]
                if __curr.startswith(self.__PREFIX_PATH):
                    self.field[PFC.F_FILEPATH] = __curr[len(self.__PREFIX_PATH):]
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FLAG_HEAP:
                    self.field[PFC.F_HEAP] = 1
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FLAG_STACK:
                    self.field[PFC.F_STACK] = 1
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FLAG_HUGE:
                    self.field[PFC.F_HUGE] = 1
                    __off = __off + 1

            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_ANON, PFC.F_ANON)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_DIRTY, PFC.F_DIRTY)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_MAPPED, PFC.F_MAPPED)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_MAPMAX, PFC.F_MAPMAX)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_SWAPCACHE, PFC.F_SWAPCACHE)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_ACTIVE_PAGES, PFC.F_ACTIVE_PAGES)
            __off = self.get_long_after_pref(sio, __off, self.__PREFIX_WRITEBACK, PFC.F_WRITEBACK)

            for __node in range(__off, sio.linewords):
                __split = sio.lineparts[__node].partition(self.__ASSIGN_DELIM)
                if len(__split) == 3:
                    if __split[0][:1] == self.__PREFIX_NODE:
                        self.field[PFC.F_NODE_LIST][__split[0][1:]] = __split[2]
            
        self.start = self.field[PFC.F_START]
        self.buffname = self.field[PFC.F_BUFFNAME]
        self.path = self.field[PFC.F_FILEPATH]
        self.heap = self.field[PFC.F_HEAP]
        self.stack = self.field[PFC.F_STACK]
        self.huge = self.field[PFC.F_HUGE]
        self.anon = self.field[PFC.F_ANON]
        self.dirty = self.field[PFC.F_DIRTY]
        self.mapped = self.field[PFC.F_MAPPED]
        self.mapmax = self.field[PFC.F_MAPMAX]
        self.swapcache = self.field[PFC.F_SWAPCACHE]
        self.activepages =  self.field[PFC.F_ACTIVE_PAGES]
        self.writeback = self.field[PFC.F_WRITEBACK]
        self.node_list = self.field[PFC.F_NODE_LIST]

        return(self.start, self.buffname, self.path, self.heap, self.stack, self.huge, self.anon,
          self.dirty, self.mapped, self.mapmax, self.swapcache, self.activepages, self.writeback,
          self.node_list)
#
RegisterProcFileHandler("/proc/self/numa_maps", ProcSelfNUMA_MAPS)
RegisterPartialProcFileHandler("numa_maps", ProcSelfNUMA_MAPS)
