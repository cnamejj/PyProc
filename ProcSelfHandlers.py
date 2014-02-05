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


import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

FIELD_NAME = PBR.FIELD_NAME
FIELD_NUMBER = PBR.FIELD_NUMBER
CONVERSION = PBR.CONVERSION
ERROR_VAL = PBR.ERROR_VAL
NUM_BASE = PBR.NUM_BASE

RegisterProcFileHandler = PBR.RegisterProcFileHandler
RegisterPartialProcFileHandler = PBR.RegisterPartialProcFileHandler


# --- !!! move to the end once all the handlers are added !!!
if __name__ == "__main__":

    print "Collection of handlers to parse file in the root /proc/self and /proc/[0-9]* directories"


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
            self.field[PFC.F_SOFT_LIMIT] = PBR.number_or_unlimited(self.field[PFC.F_SOFT_LIMIT])
            self.field[PFC.F_HARD_LIMIT] = PBR.number_or_unlimited(self.field[PFC.F_HARD_LIMIT])
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

        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_FLAGS } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_PAGE_OFFSET, CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_INODE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 5, FIELD_NAME: PFC.F_PATH } )

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

            __split = sio.lineparts[3].partition(self.__DevSplitDelim)
            self.field[PFC.F_MAJOR_DEV] = long(__split[0], 16)
            self.field[PFC.F_MINOR_DEV] = long(__split[2], 16)

#            if sio.linewords > 5:
#                self.field[PFC.F_PATH] = sio.lineparts[5]
#            else:
#                self.field[PFC.F_PATH] = ""

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

        self.rules = dict()
        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_ADDRESS } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_STACK_ENTRY } )

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
            self.field[PFC.F_ADDRESS] = long(self.field[PFC.F_ADDRESS][2:-2], 16)

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_START, CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_BUFFNAME } )

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



# ---
class ProcSelfMOUNTINFO(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/mountinfo"""
# source: fs/namespace.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#
# docs: 
#
# 3.5     /proc/<pid>/mountinfo - Information about mounts
# --------------------------------------------------------
# 
# This file contains lines of the form:
# 
# 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
# (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
# 
# (1) mount ID:  unique identifier of the mount (may be reused after umount)
# (2) parent ID:  ID of parent (or of self for the top of the mount tree)
# (3) major:minor:  value of st_dev for files on filesystem
# (4) root:  root of the mount within the filesystem
# (5) mount point:  mount point relative to the process's root
# (6) mount options:  per mount options
# (7) optional fields:  zero or more fields of the form "tag[:value]"
# (8) separator:  marks the end of the optional fields
# (9) filesystem type:  name of filesystem of the form "type[.subtype]"
# (10) mount source:  filesystem specific information or "none"
# (11) super options:  per super block options
# 
# Parsers should ignore all unrecognised optional fields.  Currently the
# possible optional fields are:
# 
# shared:X  mount is shared in peer group X
# master:X  mount is slave to peer group X
# propagate_from:X  mount is slave and receives propagation from peer group X (*)
# unbindable  mount is unbindable
# 
# (*) X is the closest dominant peer group under the process's root.  If
# X is the immediate master of the mount, or if there's no dominant peer
# group under the same root, then only the "master:X" field is present
# and not the "propagate_from:X" field.
#

    def extra_init(self, *opts):
        self.minfields = 10

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_MOUNT_ID } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_PARENT_MOUNT_ID, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_MOUNT_FS } )

        self.__OptionSep = "-"
        self.__DevDelim = ":"

        self.mntid = 0
        self.mntid_parent = 0
        self.major = 0
        self.minor = 0
        self.mount_fs = ""
        self.mount_prel = ""
        self.mnt_options = ""
        self.more_options = ""
        self.fstype = ""
        self.mnt_source = ""
        self.super_options = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 15 20 0:14 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
# 17 20 0:5 / /dev rw,relatime - devtmpfs udev rw,size=16454700k,nr_inodes=4113675,mode=755
# 20 1 9:1 / / rw,relatime - ext4 /dev/disk/by-uuid/a959862a-84b7-4373-b7d6-954ac9005249 rw,errors=remount-ro,user_xattr,barrier=1,stripe=256,data=ordered
# 21 15 0:16 / /sys/fs/fuse/connections rw,relatime - fusectl none rw
# 27 20 9:0 / /boot rw,relatime - ext4 /dev/md0 rw,user_xattr,barrier=1,stripe=128,data=ordered

        self.field[PFC.F_MAJOR_DEV] = 0
        self.field[PFC.F_MINOR_DEV] = 0
        self.field[PFC.F_MOUNT_REL] = ""
        self.field[PFC.F_MOUNT_OPTS] = ""
        self.field[PFC.F_EXTRA_OPTS] = ""
        self.field[PFC.F_FS_TYPE] = ""
        self.field[PFC.F_MOUNT_SRC] = ""
        self.field[PFC.F_SUPER_OPTS] = ""

        if sio.buff != "":
            __split = sio.lineparts[2].partition(self.__DevDelim)
            self.field[PFC.F_MAJOR_DEV] = long(__split[0])
            self.field[PFC.F_MINOR_DEV] = long(__split[2])

            __off = 4
            if sio.linewords > __off:
                self.field[PFC.F_MOUNT_REL] = sio.lineparts[__off]
                __off = __off + 1
            if sio.linewords > __off:
                self.field[PFC.F_MOUNT_OPTS] = sio.lineparts[__off]
                __off = __off + 1

            __endopts = 0
            __extras = ""
            while sio.linewords > __off and not __endopts:
                __curr = sio.lineparts[__off]
                if __curr == self.__OptionSep:
                    __endopts = 1
                else:
                    __extras = "{accum} {next}".format(accum=__extras, next=__curr)
                __off = __off + 1
            self.field[PFC.F_EXTRA_OPTS] = __extras

            if sio.linewords > __off:
                self.field[PFC.F_FS_TYPE] = sio.lineparts[__off]
                __off = __off + 1
            if sio.linewords > __off:
                self.field[PFC.F_MOUNT_SRC] = sio.lineparts[__off]
                __off = __off + 1
            if sio.linewords > __off:
                self.field[PFC.F_SUPER_OPTS] = sio.lineparts[__off]

        self.mntid = self.field[PFC.F_MOUNT_ID]
        self.mntid_parent = self.field[PFC.F_PARENT_MOUNT_ID]
        self.major = self.field[PFC.F_MAJOR_DEV]
        self.minor = self.field[PFC.F_MINOR_DEV]
        self.mount_fs = self.field[PFC.F_MOUNT_FS]
        self.mount_prel = self.field[PFC.F_MOUNT_REL]
        self.mnt_options = self.field[PFC.F_MOUNT_OPTS]
        self.more_options = self.field[PFC.F_EXTRA_OPTS]
        self.fstype = self.field[PFC.F_FS_TYPE]
        self.mnt_source = self.field[PFC.F_MOUNT_SRC]
        self.super_options = self.field[PFC.F_SUPER_OPTS]

        return(self.mntid, self.mntid_parent, self.major, self.minor, self.mount_fs,
          self.mount_prel, self.mnt_options, self.more_options, self.fstype, self.mnt_source,
          self.super_options)
#
RegisterProcFileHandler("/proc/self/mountinfo", ProcSelfMOUNTINFO)
RegisterPartialProcFileHandler("mountinfo", ProcSelfMOUNTINFO)



# ---
class ProcSelfMOUNTSTATS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/self/mountstats"""
#
# source: fs/namespace.c
# --and--
# source: fs/nfs/super.c
# --and--
# source: net/sunrpc/stats.c
# --and--
# source: net/sunrpc/xprtsock.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#
# (A) (1) mounted on !MOUNT! with fstype !FSTYPE! {statvers=!VERSION!}
#     (1) device !DEVICE!|no device
# (B) \topts: (2){,sync}{,noatime}{,nodiratime}(3)(4)(5)(6)(7)(8)(9)
#     (2) ro|rw
#     (3) ,vers=!INT!,rsize=!INT!,wsize=!INT!{,bsize=!INT!},namelen=!INT!
#     (4) {,acregmin=!INT!}{,acregmax=!INT!}{,acdirmin=!INT!}{,acdirmax=!INT!}
#     (5) ,soft|,hard
#     (6) {,posix}{,nocto}{,noac}{,nolock}{,noacl}{,nordirplus}{,nosharecache}{,noresvport}
#     (7) ,proto=!PROTOCOL!{,port=!INT!}{,timeo=!INT!}{,retrans=!INT!}{,sec=!INT!}
#     (8) {,mountaddr=(10){,mountvers=!VERSION!}{,mountport=!INT!},mountproto=(11)|,clientaddr=!IP!,minorversion=!INT!}
#         (10) !IP4!|!IP6!|unspecified
#         (11) !PROTOCOL!|auto
#     (9) {,fsc}{,lookupcache={none|pos}}{,local_lock={none|all|flock|posix}}
# (C) \tage: !INT!
# (D) \tcaps: caps=0x!HEX!,wtmult=!INT!,dtsize=!INT!,bsize=!INT!,namlen=!INT!
# (E) \tnfsv4: bm0=0x!HEX!,bm1=0x!HEX!,acl=0x!HEX!{,sessions}{,pnfs={!NAME!|not configured}}
# (F) \tsec: flavor=!INT!{,pseudoflavor=!INT!}
# (G) \tevents: {!INT! }*
# (H) \tbytes: {!INT! }*
# (I) \ttfsc: {!INT! }*
# (J) \tRPC iostats version: !VERSION! p/v: !INT!/!INT! (!PROTOCOL!)
# (K) \tper-op statistics
# (L) \t(14): !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT!
#     (14)!STATNAME!|!INT!|NULL
# (M) \txprt: (15) !INT! !INT! !INT! !INT! !INT! !INT! !INT!
#     (15) local|udp
# (N) \txprt: tcp !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT!

    def extra_init(self, *opts):
        self.minfields = 2

        self.__ASSIGN_DELIM = "="
        self.__OPTLIST_DELIM = ","
        self.__RPC_DELIM = "/"

        self.__PREFIX_DEV = "device"
        self.__PREFIX_NO = "no"
        self.__PREFIX_OPTS = "opts:"
        self.__PREFIX_AGE = "age:"
        self.__PREFIX_CAPS = "caps:"
        self.__PREFIX_NFSV4 = "nfsv4:"
        self.__PREFIX_SECURITY = "sec:"
        self.__PREFIX_EVENTS = "events:"
        self.__PREFIX_BYTES = "bytes:"
        self.__PREFIX_FSCACHE = "tfsc:"
        self.__PREFIX_IOSTATS = "RPC"
        self.__PREFIX_PER_OP = "per-op"
        self.__PREFIX_XPRT = "xprt:"
        self.__PREFIX_FLAVOR = "flavor"
        self.__PREFIX_PSEUDOFLAVOR = "pseudoflavor"

        self.__FLAG_HARD = "hard"
        self.__FLAG_SOFT = "soft"
        self.__FLAG_XPRT_LOCAL = "local"
        self.__FLAG_XPRT_UDP = "udp"
        self.__FLAG_XPRT_TCP = "tcp"

        self.__is_per_op = 0
        self.__have_partial = 0
        self.__curr_sio = 0
        self.__partial = dict()
        self.__partial[PFC.F_DEVICE] = ""
        self.__partial[PFC.F_MOUNTPOINT] = ""
        self.__partial[PFC.F_FSTYPE] = ""
        self.__partial[PFC.F_STATSVERS] = ""

        self.__NFS_MOUNT_OPTS_FLAG = ( PFC.F_SYNC, PFC.F_NOATIME, PFC.F_NODIRATIME, PFC.F_POSIX, 
          PFC.F_NOCTO, PFC.F_NOAC, PFC.F_NOLOCK, PFC.F_NOACL, PFC.F_NORDIRPLUS, PFC.F_UNSHARED,
          PFC.F_NORESVPORT, PFC.F_FSCACHE, PFC.F_SESSIONS )

        self.__NFS_MOUNT_OPTS_LONG = ( PFC.F_VERS, PFC.F_RSIZE,  PFC.F_WSIZE,  PFC.F_BSIZE,
          PFC.F_NAMELEN, PFC.F_ACREGMIN, PFC.F_ACREGMAX, PFC.F_ACDIRMIN, PFC.F_ACDIRMAX, PFC.F_PORT,
          PFC.F_TIMEO, PFC.F_MOUNTSTATS_RETRANS, PFC.F_MOUNTPORT, PFC.F_MINORVERS, PFC.F_DTSIZE,
          PFC.F_FLAVOR, PFC.F_PSEUDOFLAVOR, PFC.F_RPC_PROG, PFC.F_RPC_VERS, PFC.F_NAMLEN,
          PFC.F_WTMULT )

        self.__NFS_MOUNT_OPTS_HEX = ( PFC.F_CAPS, PFC.F_NFSV4_BM0, PFC.F_NFSV4_BM1, PFC.F_NFSV4_ACL )

        self.__NFS_MOUNT_OPTS_STRING = ( PFC.F_PROTO, PFC.F_SECURITYNAME, PFC.F_MOUNTADDR,
          PFC.F_MOUNTVERS, PFC.F_MOUNTPROTO, PFC.F_CLIENTADDR, PFC.F_LOOKUPCACHE, PFC.F_LOCKLOCAL,
          PFC.F_PNFS, PFC.F_IOSTATS_VERS )

        self.device = ""
        self.mountpoint = ""
        self.fstype = ""
        self.statsvers = ""

        return

    def partial_to_final(self, sio):
        self.__have_partial = 0

        self.field[PFC.F_DEVICE] = self.__partial[PFC.F_DEVICE]
        self.field[PFC.F_MOUNTPOINT] = self.__partial[PFC.F_MOUNTPOINT]
        self.field[PFC.F_FSTYPE] = self.__partial[PFC.F_FSTYPE]
        self.field[PFC.F_STATSVERS] = self.__partial[PFC.F_STATSVERS]

        self.__partial = dict()
        self.__partial[PFC.F_DEVICE] = ""
        self.__partial[PFC.F_MOUNTPOINT] = ""
        self.__partial[PFC.F_FSTYPE] = ""
        self.__partial[PFC.F_STATSVERS] = ""
        return

# (A) (1) mounted on !MOUNT! with fstype !FSTYPE! {statvers=!VERSION!}
#     (1) device !DEVICE!|no device
    def parse_device_line(self, sio):
        self.__have_partial = 1

        if sio.lineparts[0] == self.__PREFIX_DEV:
            self.__partial[PFC.F_DEVICE] = sio.lineparts[1]
        else:
            self.__partial[PFC.F_DEVICE] = PDC.NO_DEVICE
        self.__partial[PFC.F_MOUNTPOINT] = sio.lineparts[4]
        self.__partial[PFC.F_FSTYPE] = sio.lineparts[7]

        if sio.linewords >= 9:
            __split = sio.lineparts[8].partition(self.__ASSIGN_DELIM)
            self.__partial[PFC.F_STATSVERS] = __split[2]
        else:
            self.__partial[PFC.F_STATSVERS] = ""
        return

# (B) \topts: (2){,sync}{,noatime}{,nodiratime}(3)(4)(5)(6)(7)(8)(9)
#     (2) ro|rw
#     (3) ,vers=!INT!,rsize=!INT!,wsize=!INT!{,bsize=!INT!},namelen=!INT!
#     (4) {,acregmin=!INT!}{,acregmax=!INT!}{,acdirmin=!INT!}{,acdirmax=!INT!}
#     (5) ,soft|,hard
#     (6) {,posix}{,nocto}{,noac}{,nolock}{,noacl}{,nordirplus}{,nosharecache}{,noresvport}
#     (7) ,proto=!PROTOCOL!{,port=!INT!}{,timeo=!INT!}{,retrans=!INT!}{,sec=!SECURITYNAME!}
#     (8) {,mountaddr=(10){,mountvers=!VERSION!}{,mountport=!INT!},mountproto=(11)|,clientaddr=!IP!,minorversion=!INT!}
#         (10) !IP4!|!IP6!|unspecified
#         (11) !PROTOCOL!|auto
#     (9) {,fsc}{,lookupcache={none|pos}}{,local_lock={none|all|flock|posix}}
    def parse_options_line(self, sio):
        __opt = PBR.breakout_option_list(sio.lineparts[1])

#        for __key in __opt:
#            print "dbg:: Opts post-BOL key'{key}' val'{val}'".format(key=__key, val=__opt[__key])

        self.field[PFC.F_WRITE_STATUS] = sio.lineparts[1][0:2]

        if __opt.has_key(self.__FLAG_HARD):
            self.field[PFC.F_MOUNT_TYPE] = self.__FLAG_HARD
        elif __opt.has_key(self.__FLAG_SOFT):
            self.field[PFC.F_MOUNT_TYPE] = self.__FLAG_SOFT
        else:
            self.field[PFC.F_MOUNT_TYPE] = PDC.unknown_state

        for __mount_opt in self.__NFS_MOUNT_OPTS_FLAG:
            self.field[__mount_opt] = __opt.has_key(__mount_opt)

        for __mount_opt in self.__NFS_MOUNT_OPTS_LONG:
            try:
                self.field[__mount_opt] = long(__opt[__mount_opt])
            except KeyError:
                self.field[__mount_opt] = 0

        for __mount_opt in self.__NFS_MOUNT_OPTS_HEX:
            try:
                self.field[__mount_opt] = long(__opt[__mount_opt], 16)
            except KeyError:
                self.field[__mount_opt] = 0
        self.__NFS_MOUNT_OPTS_HEX = ( PFC.F_NFSV4_BM0, PFC.F_NFSV4_BM1, PFC.F_NFSV4_ACL )

        for __mount_opt in self.__NFS_MOUNT_OPTS_STRING:
            try:
                self.field[__mount_opt] = __opt.has_key(__mount_opt)
            except KeyError:
                self.field[__mount_opt] = ""

        return

# (C) \tage: !INT!
    def parse_age_line(self, sio):
        self.field[PFC.F_AGE] = long(sio.lineparts[1])
        return

# (D) \tcaps: caps=0x!HEX!,wtmult=!INT!,dtsize=!INT!,bsize=!INT!,namlen=!INT!
    def parse_caps_line(self, sio):
        __caps = PBR.breakout_option_list(sio.lineparts[1])

#        print "dbg:: Caps line'{line}'".format(line=sio.buff[:-1])
#        for __key in __caps:
#            print "dbg:: Caps post-BOL key'{key}' val'{val}'".format(key=__key, val=__caps[__key])

        self.field[PFC.F_CAPS] = long(__caps[PFC.F_CAPS][2:], 16)
        self.field[PFC.F_WTMULT] = long(__caps[PFC.F_WTMULT])
        self.field[PFC.F_DTSIZE] = long(__caps[PFC.F_DTSIZE])
        self.field[PFC.F_BSIZE] = long(__caps[PFC.F_BSIZE])
        self.field[PFC.F_NAMELEN] = long(__caps[PFC.F_NAMELEN])
        return

# (E) \tnfsv4: bm0=0x!HEX!,bm1=0x!HEX!,acl=0x!HEX!{,sessions}{,pnfs={!NAME!|not configured}}
    def parse_nfsv4_line(self, sio):
        __opts = PBR.breakout_option_list(sio.lineparts[1])

        self.field[PFC.F_NFSV4_BM0] = long(__opts[PFC.F_NFSV4_BM0], 16)
        self.field[PFC.F_NFSV4_BM1] = long(__opts[PFC.F_NFSV4_BM1], 16)
        self.field[PFC.F_NFSV4_ACL] = long(__opts[PFC.F_NFSV4_ACL], 16)

        if __opts.has_key(PFC.F_SESSIONS):
            self.field[PFC.F_SESSIONS] = 1
        else:
            self.field[PFC.F_SESSIONS] = 0

        try:
            self.field[PFC.F_PNFS] = __opts[PFC.F_PNFS]
        except KeyError:
            self.field[PFC.F_PNFS] = ""

        return

# (F) \tsec: flavor=!INT!{,pseudoflavor=!INT!}
    def parse_security_line(self, sio):
        __optlist = PBR.breakout_option_list(sio.lineparts[1])
        self.field[PFC.F_FLAVOR] = long(__optlist[self.__PREFIX_FLAVOR])
        try:
            self.field[PFC.F_PSEUDOFLAVOR] = long(__optlist[self.__PREFIX_PSEUDOFLAVOR])
        except KeyError:
            self.field[PFC.F_PSEUDOFLAVOR] = 0
        return

# (G) \tevents: {!INT! }*
    def parse_events_line(self, sio):
        self.field[PFC.F_EVENT_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (H) \tbytes: {!INT! }*
    def parse_bytes_line(self, sio):
        self.field[PFC.F_BYTES_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (I) \ttfsc: {!INT! }*
    def parse_fscache_line(self, sio):
        self.field[PFC.F_FSCACHE_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (J) \tRPC iostats version: !VERSION! p/v: !INT!/!INT! (!PROTOCOL!)
    def parse_iostats_line(self, sio):
        self.field[PFC.F_VERSION] = sio.lineparts[3]

        __part = sio.lineparts[5].partition(self.__RPC_DELIM)
        self.field[PFC.F_RPC_PROG] = __part[0]
        self.field[PFC.F_RPC_VERS] = __part[2]

        self.field[PFC.F_PROTOCOL] = sio.lineparts[6][1:-1]

        return

# (K) \tper-op statistics
# (L) \t(14): !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT!
#     (14)!STATNAME!|!INT!|NULL
    def parse_per_op_line(self, sio):

        __stat = sio.lineparts[0]
        if __stat[-1:] == ":":
            __stat = __stat[:-1]

        __nums = PBR.array_of_longs(sio.lineparts[1:])
        __val = dict()
        __val[PFC.F_OM_OPS] = __nums[0]
        __val[PFC.F_OM_NTRANS] = __nums[1]
        __val[PFC.F_OM_TIMEOUTS] = __nums[2]
        __val[PFC.F_OM_SENT] = __nums[3]
        __val[PFC.F_OM_RECV] = __nums[4]
        __val[PFC.F_OM_QUEUE] = __nums[5]
        __val[PFC.F_OM_RTT] = __nums[6]
        __val[PFC.F_OM_EXEC] = __nums[7]

        self.field[PFC.F_PER_OP_STATS][__stat] = __val

        return

    def parse_xprt_local(self, sio):
        __nums = PBR.array_of_longs(sio.lineparts[2:])

        __val = dict()
        __val[PFC.F_XPR_BIND_COUNT] = __nums[0]
        __val[PFC.F_XPR_CONN_COUNT] = __nums[1]
        __val[PFC.F_XPR_CONN_TIME] = __nums[2]
        __val[PFC.F_XPR_IDLE_TIME] = __nums[3]
        __val[PFC.F_XPR_SEND] = __nums[4]
        __val[PFC.F_XPR_RECV] = __nums[5]
        __val[PFC.F_XPR_BAD_XIDS] = __nums[6]
        __val[PFC.F_XPR_REQ] = __nums[7]
        __val[PFC.F_XPR_BACKLOG] = __nums[8]

        return(__val)

    def parse_xprt_udp(self, sio):
        __nums = PBR.array_of_longs(sio.lineparts[2:])

        __val = dict()
        __val[PFC.F_XPR_SRC_PORT] = __nums[0]
        __val[PFC.F_XPR_BIND_COUNT] = __nums[1]
        __val[PFC.F_XPR_SEND] = __nums[2]
        __val[PFC.F_XPR_RECV] = __nums[3]
        __val[PFC.F_XPR_BAD_XIDS] = __nums[4]
        __val[PFC.F_XPR_REQ] = __nums[5]
        __val[PFC.F_XPR_BACKLOG] = __nums[6]

        return(__val)

    def parse_xprt_tcp(self, sio):
        __nums = PBR.array_of_longs(sio.lineparts[2:])

        __val = dict()
        __val[PFC.F_XPR_SRC_PORT] = __nums[0]
        __val[PFC.F_XPR_BIND_COUNT] = __nums[1]
        __val[PFC.F_XPR_CONN_COUNT] = __nums[2]
        __val[PFC.F_XPR_CONN_TIME] = __nums[3]
        __val[PFC.F_XPR_IDLE_TIME] = __nums[4]
        __val[PFC.F_XPR_SEND] = __nums[5]
        __val[PFC.F_XPR_RECV] = __nums[6]
        __val[PFC.F_XPR_BAD_XIDS] = __nums[7]
        __val[PFC.F_XPR_REQ] = __nums[8]
        __val[PFC.F_XPR_BACKLOG] = __nums[9]

        return(__val)

# (M) \txprt: (15) !INT! !INT! !INT! !INT! !INT! !INT! !INT!
#     (15) local|udp
# (N) \txprt: tcp !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT!
    def parse_xprt_line(self, sio):

        __rectype = sio.lineparts[1]

        if __rectype == self.__FLAG_XPRT_LOCAL:
            __val = self.parse_xprt_local(sio)

        elif __rectype == self.__FLAG_XPRT_UDP:
            __val = self.parse_xprt_udp(sio)

        elif __rectype == self.__FLAG_XPRT_TCP:
            __val = self.parse_xprt_tcp(sio)

        else:
            print "dbg:: xprt mismatch '{line}'".format(line=sio.buff[:-1])

        self.field[PFC.F_XPRT_STATS][__rectype] = __val
        return

    def accumulate_info(self, sio):
        __first = sio.lineparts[0]
        __second = sio.lineparts[1]

        if __first == self.__PREFIX_DEV:
            self.parse_device_line(sio)
        elif __first == self.__PREFIX_NO and __second == self.__PREFIX_DEV:
            self.parse_device_line(sio)
        elif __first == self.__PREFIX_OPTS:
            self.parse_options_line(sio)
        elif __first == self.__PREFIX_AGE:
            self.parse_age_line(sio)
        elif __first == self.__PREFIX_CAPS:
            self.parse_caps_line(sio)
        elif __first == self.__PREFIX_NFSV4:
            self.parse_nfsv4_line(sio)
        elif __first == self.__PREFIX_SECURITY:
            self.parse_security_line(sio)
        elif __first == self.__PREFIX_EVENTS:
            self.parse_events_line(sio)
        elif __first == self.__PREFIX_BYTES:
            self.parse_bytes_line(sio)
        elif __first == self.__PREFIX_FSCACHE:
            self.parse_fscache_line(sio)
        elif __first == self.__PREFIX_IOSTATS:
            self.parse_iostats_line(sio)
        elif __first == self.__PREFIX_XPRT:
            self.parse_xprt_line(sio)
        elif __first == self.__PREFIX_PER_OP:
            self.__is_per_op = 1
        elif self.__is_per_op:
            self.parse_per_op_line(sio)
        else:
            print "dbg:: Ignoring rec '{line}'".format(line=sio.buff[:-1])
        return

    def next(self):
        try:
            result = super(ProcSelfMOUNTSTATS, self).next()
        except StopIteration:
            if self.__have_partial:
                result = self.extra_next(self.__curr_sio)
            else:
                raise StopIteration
        return(result)

    def init_field_values(self):
        self.field = dict()

        self.field[PFC.F_DEVICE] = ""
        self.field[PFC.F_MOUNTPOINT] = ""
        self.field[PFC.F_FSTYPE] = ""
        self.field[PFC.F_STATSVERS] = ""
        self.field[PFC.F_MOUNT_TYPE] = PDC.unknown_state
        self.field[PFC.F_WRITE_STATUS] = PDC.unknown_state
        self.field[PFC.F_AGE] = 0
        self.field[PFC.F_BYTES_LIST] = dict()
        self.field[PFC.F_EVENT_LIST] = dict()
        self.field[PFC.F_FSCACHE_LIST] = dict()
        self.field[PFC.F_PER_OP_STATS] = dict()
        self.field[PFC.F_XPRT_STATS] = dict()
        self.field[PFC.F_PROTOCOL] = ""
        self.field[PFC.F_VERSION] = ""

        for __mount_opt in self.__NFS_MOUNT_OPTS_FLAG:
            self.field[__mount_opt] = False

        for __mount_opt in self.__NFS_MOUNT_OPTS_LONG:
            self.field[__mount_opt] = 0

        for __mount_opt in self.__NFS_MOUNT_OPTS_HEX:
            self.field[__mount_opt] = 0

        for __mount_opt in self.__NFS_MOUNT_OPTS_STRING:
            self.field[__mount_opt] = ""

    def extra_next(self, sio):

# -- Sample records (NFS mounts add all the complex sub-records, no sample available yet)
#
# device udev mounted on /dev with fstype devtmpfs
# device devpts mounted on /dev/pts with fstype devpts
# device tmpfs mounted on /run with fstype tmpfs
# device /dev/disk/by-uuid/a959862a-84b7-4373-b7d6-954ac9005249 mounted on / with fstype ext4
# device none mounted on /sys/fs/fuse/connections with fstype fusectl

#        print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])
        self.__curr_sio = sio
        self.__is_per_op = 0
        self.init_field_values()

        if sio.buff != "" and not self.__have_partial:
            self.accumulate_info(sio)
            sio.read_line()
#            print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])

        self.partial_to_final(sio)

        __complete = 0
        while sio.buff != "" and not __complete:
            self.accumulate_info(sio)

            __first = sio.lineparts[0]
            __second = sio.lineparts[1]
            if __first == self.__PREFIX_DEV or (__first == self.__PREFIX_NO and __second == self.__PREFIX_DEV):
                __complete = 1
            else:
                try:
                    sio.read_line()
#                    print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])
                except StopIteration:
                    __complete = 1

        self.device = self.field[PFC.F_DEVICE]
        self.mountpoint = self.field[PFC.F_MOUNTPOINT]
        self.fstype = self.field[PFC.F_FSTYPE]
        self.statsvers = self.field[PFC.F_STATSVERS]

        return(self.device, self.mountpoint, self.fstype, self.statsvers)

#
RegisterProcFileHandler("/proc/self/mountstats", ProcSelfMOUNTSTATS)
RegisterPartialProcFileHandler("mountstats", ProcSelfMOUNTSTATS)
