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

"""
Handlers for file in the /proc/PID or /proc/self directories
"""

import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

PREFIX = PBR.PREFIX_VAL
SUFFIX = PBR.SUFFIX_VAL
CONV = PBR.CONVERSION
NAME = PBR.FIELD_NAME
POS = PBR.FIELD_NUMBER
BEFORE = PBR.BEFORE_VAL
AFTER = PBR.AFTER_VAL
ERRVAL = PBR.ERROR_VAL
HAS = PBR.HAS_VAL
WORDS = PBR.WORDS_VAL
CONV = PBR.CONVERSION
BASE = PBR.NUM_BASE

REGISTER_FILE = PBR.register_file
REGISTER_PARTIAL_FILE = PBR.register_partial_file



# ---
class ProcSelfLIMITS(PBR.FixedColumnRecs):
    """
    Pull records from /proc/self/limits
    """

# source: fs/proc/base.c
#
#    count += sprintf(&bufptr[count], "%-25s %-20s %-20s %-10s\n",
#                    "Limit", "Soft Limit", "Hard Limit", "Units");
#
#    for (i = 0; i < RLIM_NLIMITS; i++) {
#            if (rlim[i].rlim_cur == RLIM_INFINITY)
#                    count += sprintf(&bufptr[count], "%-25s %-20s ",
#                                     lnames[i].name, "unlimited");
#            else
#                    count += sprintf(&bufptr[count], "%-25s %-20lu ",
#                                     lnames[i].name, rlim[i].rlim_cur);
#
#            if (rlim[i].rlim_max == RLIM_INFINITY)
#                    count += sprintf(&bufptr[count], "%-20s ", "unlimited");
#            else
#                    count += sprintf(&bufptr[count], "%-20lu ",
#                                     rlim[i].rlim_max);
#
#            if (lnames[i].unit)
#                    count += sprintf(&bufptr[count], "%-10s\n",
#                                     lnames[i].unit);
#            else
#                    count += sprintf(&bufptr[count], "\n");
#    }

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
            self.field[PFC.F_SOFT_LIMIT] = PBR.number_or_unlimited(
                    self.field[PFC.F_SOFT_LIMIT])
            self.field[PFC.F_HARD_LIMIT] = PBR.number_or_unlimited(
                    self.field[PFC.F_HARD_LIMIT])
            self.field[PFC.F_UNITS] = self.field[PFC.F_UNITS].strip()

        self.limit = self.field[PFC.F_LIMIT]
        self.soft_limit = self.field[PFC.F_SOFT_LIMIT]
        self.hard_limit = self.field[PFC.F_HARD_LIMIT]
        self.units = self.field[PFC.F_UNITS]

        return(self.limit, self.soft_limit, self.hard_limit, self.units)

#
REGISTER_FILE("/proc/self/limits", ProcSelfLIMITS)
REGISTER_PARTIAL_FILE("limits", ProcSelfLIMITS)



# ---
class ProcSelfMAPS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_START, BEFORE: "-",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_END, AFTER: "-",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_FLAGS } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PAGE_OFFSET, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MAJOR_DEV, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MINOR_DEV, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_PATH } )

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
            self.field[PFC.F_START] = 0
            self.field[PFC.F_END] = 0
            self.field[PFC.F_FLAGS] = ""
            self.field[PFC.F_PAGE_OFFSET] = 0
            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_PATH] = ""

        self.vm_start = self.field[PFC.F_START]
        self.vm_end = self.field[PFC.F_END]
        self.flags = self.field[PFC.F_FLAGS]
        self.vm_page = self.field[PFC.F_PAGE_OFFSET]
        self.major = self.field[PFC.F_MAJOR_DEV]
        self.minor = self.field[PFC.F_MINOR_DEV]
        self.inode = self.field[PFC.F_INODE]
        self.path = self.field[PFC.F_PATH]

        return(self.vm_start, self.vm_end, self.flags, self.vm_page,
                self.major, self.minor, self.inode, self.path)

#
REGISTER_FILE("/proc/self/maps", ProcSelfMAPS)
REGISTER_PARTIAL_FILE("maps", ProcSelfMAPS)



# ---
class ProcSelfSTACK(PBR.FixedWhitespaceDelimRecs):
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
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ADDRESS, PREFIX: "[<",
                SUFFIX: ">]", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_STACK_ENTRY } )

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
            self.field[PFC.F_ADDRESS] = 0
            self.field[PFC.F_STACK_ENTRY] = ""

        self.address_string = sio.get_word(0)
        self.address = self.field[PFC.F_ADDRESS]
        self.stack_entry = self.field[PFC.F_STACK_ENTRY]

        return(self.address_string, self.address, self.stack_entry)

#
REGISTER_FILE("/proc/self/stack", ProcSelfSTACK)
REGISTER_PARTIAL_FILE("stack", ProcSelfSTACK)



# ---
class ProcSelfIO(PBR.SingleNameValueList):
    """Pull records from /proc/self/io"""
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

REGISTER_FILE("/proc/self/io", ProcSelfIO)
REGISTER_PARTIAL_FILE("io", ProcSelfIO)



# ---
class ProcSelfNUMAMAPS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_START, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_BUFFNAME } )
        PBR.add_parse_rule(self, { NAME: PFC.F_FILEPATH, PREFIX: "file=" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ANON, PREFIX: "anon=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_DIRTY, PREFIX: "dirty=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_MAPPED, PREFIX: "mapped=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_MAPMAX, PREFIX: "mapmax=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_SWAPCACHE, PREFIX: "swapcache=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ACTIVE_PAGES, PREFIX: "active=",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_WRITEBACK, PREFIX: "writeback=",
                CONV: long } )

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

        self.__assign_delim = "="
        self.__prefix_node = "N"
        self.__flag_heap = "heap"
        self.__flag_stack = "stack"
        self.__flag_huge = "huge"
        return

    def extra_next(self, sio):

# -- Sample records
#
# 00400000 default file=/bin/cat mapped=7 mapmax=2 N0=7
# 0060a000 default file=/bin/cat anon=1 dirty=1 N0=1
# 0060b000 default file=/bin/cat anon=1 dirty=1 N0=1
# 01b69000 default heap anon=3 dirty=3 active=0 N0=3
# 7f5935a28000 default file=/usr/lib/locale/locale-archive mapped=11 mapmax=88 N0=11
# 7f5935cf1000 default file=/lib/x86_64-linux-gnu/libc-2.15.so mapped=82 mapmax=167 N0=82

        self.field[PFC.F_HEAP] = 0
        self.field[PFC.F_STACK] = 0
        self.field[PFC.F_HUGE] = 0
        self.field[PFC.F_NODE_LIST] = dict()

        if sio.buff != "":

            for __off in range(2, sio.linewords):
                __word = sio.get_word(__off)

                if __word == self.__flag_heap:
                    self.field[PFC.F_HEAP] = 1

                elif __word == self.__flag_stack:
                    self.field[PFC.F_STACK] = 1

                elif __word == self.__flag_huge:
                    self.field[PFC.F_HUGE] = 1

                else:
                    __split = __word.partition(self.__assign_delim)
                    if len(__split) == 3:
                        if __split[0][:1] == self.__prefix_node:
                            self.field[PFC.F_NODE_LIST][__split[0][1:]] = \
                                    __split[2]
            
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

        return(self.start, self.buffname, self.path, self.heap, self.stack,
                self.huge, self.anon, self.dirty, self.mapped, self.mapmax,
                self.swapcache, self.activepages, self.writeback,
                self.node_list)
#
REGISTER_FILE("/proc/self/numa_maps", ProcSelfNUMAMAPS)
REGISTER_PARTIAL_FILE("numa_maps", ProcSelfNUMAMAPS)



# ---
class ProcSelfMOUNTINFO(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/self/mountinfo"""
# source: fs/namespace.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcSelfHandlers" to reduce the size of this module.
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
# propagate_from:X  mount is slave and receives propagation from peer group X(*)
# unbindable  mount is unbindable
# 
# (*) X is the closest dominant peer group under the process's root.  If
# X is the immediate master of the mount, or if there's no dominant peer
# group under the same root, then only the "master:X" field is present
# and not the "propagate_from:X" field.
#

    def extra_init(self, *opts):
        self.minfields = 10

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MOUNT_ID } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_PARENT_MOUNT_ID,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MAJOR_DEV, BEFORE: ":",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MINOR_DEV, AFTER: ":",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MOUNT_FS } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_MOUNT_REL } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_MOUNT_OPTS } )

        self.__option_sep = "-"

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

        self.field[PFC.F_EXTRA_OPTS] = ""
        self.field[PFC.F_FS_TYPE] = ""
        self.field[PFC.F_MOUNT_SRC] = ""
        self.field[PFC.F_SUPER_OPTS] = ""

        if sio.buff != "":

            __off = 6
            __endopts = 0
            __extras = ""
            while sio.linewords > __off and not __endopts:
                __curr = sio.get_word(__off)
                if __curr == self.__option_sep:
                    __endopts = 1
                else:
                    __extras = "{accum} {next}".format(accum=__extras,
                            next=__curr)
                __off += 1
            self.field[PFC.F_EXTRA_OPTS] = __extras

            if sio.linewords > __off:
                self.field[PFC.F_FS_TYPE] = sio.get_word(__off)
                __off += 1
            if sio.linewords > __off:
                self.field[PFC.F_MOUNT_SRC] = sio.get_word(__off)
                __off += 1
            if sio.linewords > __off:
                self.field[PFC.F_SUPER_OPTS] = sio.get_word(__off)

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

        return(self.mntid, self.mntid_parent, self.major, self.minor,
          self.mount_fs, self.mount_prel, self.mnt_options, self.more_options,
          self.fstype, self.mnt_source, self.super_options)
#
REGISTER_FILE("/proc/self/mountinfo", ProcSelfMOUNTINFO)
REGISTER_PARTIAL_FILE("mountinfo", ProcSelfMOUNTINFO)



# ---
class ProcSelfMOUNTSTATS(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/self/mountstats
    """
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
# "README.ProcSelfHandlers" to reduce the size of this module.
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
        """Custom processing for the record just read"""

        self.minfields = 2

        self.__assign_delim = "="
        self.__rpc_delim = "/"

        self.__prefix_dev = "device"
        self.__prefix_no = "no"
        self.__prefix_opts = "opts:"
        self.__prefix_age = "age:"
        self.__prefix_caps = "caps:"
        self.__prefix_nfsv4 = "nfsv4:"
        self.__prefix_security = "sec:"
        self.__prefix_events = "events:"
        self.__prefix_bytes = "bytes:"
        self.__prefix_fscache = "tfsc:"
        self.__prefix_iostats = "RPC"
        self.__prefix_per_op = "per-op"
        self.__prefix_xprt = "xprt:"
        self.__prefix_flavor = "flavor"
        self.__prefix_pseudoflavor = "pseudoflavor"

        self.__flag_hard = "hard"
        self.__flag_soft = "soft"
        self.__flag_xprt_local = "local"
        self.__flag_xprt_udp = "udp"
        self.__flag_xprt_tcp = "tcp"

        self.__is_per_op = False
        self.__have_partial = False
        self.__partial = dict()
        self.__partial[PFC.F_DEVICE] = ""
        self.__partial[PFC.F_MOUNTPOINT] = ""
        self.__partial[PFC.F_FSTYPE] = ""
        self.__partial[PFC.F_STATSVERS] = ""

        self.__nfs_mount_opts_flag = ( PFC.F_SYNC, PFC.F_NOATIME,
                PFC.F_NODIRATIME, PFC.F_POSIX, PFC.F_NOCTO, PFC.F_NOAC,
                PFC.F_NOLOCK, PFC.F_NOACL, PFC.F_NORDIRPLUS, PFC.F_UNSHARED,
                PFC.F_NORESVPORT, PFC.F_FSCACHE, PFC.F_SESSIONS )

        self.__nfs_mount_opts_long = ( PFC.F_VERS, PFC.F_RSIZE,  PFC.F_WSIZE,
                PFC.F_BSIZE, PFC.F_NAMELEN, PFC.F_ACREGMIN, PFC.F_ACREGMAX,
                PFC.F_ACDIRMIN, PFC.F_ACDIRMAX, PFC.F_PORT, PFC.F_TIMEO,
                PFC.F_MOUNTSTATS_RETRANS, PFC.F_MOUNTPORT, PFC.F_MINORVERS,
                PFC.F_DTSIZE, PFC.F_FLAVOR, PFC.F_PSEUDOFLAVOR, PFC.F_RPC_PROG,
                PFC.F_RPC_VERS, PFC.F_NAMLEN, PFC.F_WTMULT )

        self.__nfs_mount_opts_hex = ( PFC.F_CAPS, PFC.F_NFSV4_BM0,
                PFC.F_NFSV4_BM1, PFC.F_NFSV4_ACL )

        self.__nfs_mount_opts_string = ( PFC.F_PROTO, PFC.F_SECURITYNAME,
                PFC.F_MOUNTADDR, PFC.F_MOUNTVERS, PFC.F_MOUNTPROTO,
                PFC.F_CLIENTADDR, PFC.F_LOOKUPCACHE, PFC.F_LOCKLOCAL,
                PFC.F_PNFS, PFC.F_IOSTATS_VERS )

        self.device = ""
        self.mountpoint = ""
        self.fstype = ""
        self.statsvers = ""

        return

    def partial_to_final(self):
        """
        Copy queued data from a previous iteration to the current
        logical record.
        """

        self.__have_partial = False

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
        """Parse device subrecord"""

        self.__have_partial = True

        if sio.get_word(0) == self.__prefix_dev:
            self.__partial[PFC.F_DEVICE] = sio.get_word(1)
        else:
            self.__partial[PFC.F_DEVICE] = PDC.NO_DEVICE
        self.__partial[PFC.F_MOUNTPOINT] = sio.get_word(4)
        self.__partial[PFC.F_FSTYPE] = sio.get_word(7)

        if sio.linewords >= 9:
            __split = sio.get_word(8).partition(self.__assign_delim)
            self.__partial[PFC.F_STATSVERS] = __split[2]
        else:
            self.__partial[PFC.F_STATSVERS] = ""
        return

    def parse_options_line(self, sio):
        """
        Driver for parsing options subrecords
        """

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


        __opt = PBR.breakout_option_list(sio.get_word(1))

#        for __key in __opt:
#            print "dbg:: Opts post-BOL key'{key}' val'{val}'".format(
#                    key=__key, val=__opt[__key])

        self.field[PFC.F_WRITE_STATUS] = sio.get_word(1)[0:2]

        if __opt.has_key(self.__flag_hard):
            self.field[PFC.F_MOUNT_TYPE] = self.__flag_hard
        elif __opt.has_key(self.__flag_soft):
            self.field[PFC.F_MOUNT_TYPE] = self.__flag_soft
        else:
            self.field[PFC.F_MOUNT_TYPE] = PDC.UNKNOWN_STATE

        for __mount_opt in self.__nfs_mount_opts_flag:
            self.field[__mount_opt] = __opt.has_key(__mount_opt)

        for __mount_opt in self.__nfs_mount_opts_long:
            try:
                self.field[__mount_opt] = PBR.conv_by_rules(
                        __opt[__mount_opt],
                        { CONV: long } )
            except KeyError:
                self.field[__mount_opt] = 0

        for __mount_opt in self.__nfs_mount_opts_hex:
            try:
                self.field[__mount_opt] = PBR.conv_by_rules(
                        __opt[__mount_opt],
                        { CONV: long, BASE: 16 } )
            except KeyError:
                self.field[__mount_opt] = 0
        self.__nfs_mount_opts_hex = ( PFC.F_NFSV4_BM0, PFC.F_NFSV4_BM1,
                PFC.F_NFSV4_ACL )

        for __mount_opt in self.__nfs_mount_opts_string:
            try:
                self.field[__mount_opt] = __opt.has_key(__mount_opt)
            except KeyError:
                self.field[__mount_opt] = ""

        return

# (C) \tage: !INT!
    def parse_age_line(self, sio):
        """Parse an 'age' subrecord"""

        self.field[PFC.F_AGE] = PBR.conv_by_rules(sio.get_word(1),
                { CONV: long } )
        return

# (D) \tcaps: caps=0x!HEX!,wtmult=!INT!,dtsize=!INT!,bsize=!INT!,namlen=!INT!
    def parse_caps_line(self, sio):
        """Parse a 'caps' subrecord"""

        __caps = PBR.breakout_option_list(sio.get_word(1))

#        print "dbg:: Caps line'{line}'".format(line=sio.buff[:-1])
#        for __key in __caps:
#            print "dbg:: Caps post-BOL key'{key}' val'{val}'".format(key=__key,
#                    val=__caps[__key])

        self.field[PFC.F_CAPS] = PBR.conv_by_rules(__caps[PFC.F_CAPS],
                { CONV: long, BASE: 16, PREFIX: "0x" } )
        self.field[PFC.F_WTMULT] = PBR.conv_by_rules(__caps[PFC.F_WTMULT],
                { CONV: long } )
        self.field[PFC.F_DTSIZE] = PBR.conv_by_rules(__caps[PFC.F_DTSIZE],
                { CONV: long } )
        self.field[PFC.F_BSIZE] = PBR.conv_by_rules(__caps[PFC.F_BSIZE],
                { CONV: long } )
        self.field[PFC.F_NAMELEN] = PBR.conv_by_rules(__caps[PFC.F_NAMELEN],
                { CONV: long } )
        return

    def parse_nfsv4_line(self, sio):
        """
        Parse a subrecord with NFS v4 info

# (E) \tnfsv4: bm0=0x!HEX!,bm1=0x!HEX!,acl=0x!HEX!{,sessions}{,pnfs={!NAME!|not configured}}
        """
        __opts = PBR.breakout_option_list(sio.get_word(1))

        self.field[PFC.F_NFSV4_BM0] = PBR.conv_by_rules(
                __opts[PFC.F_NFSV4_BM0], { CONV: long, BASE: 16 } )
        self.field[PFC.F_NFSV4_BM1] = PBR.conv_by_rules(
                __opts[PFC.F_NFSV4_BM1], { CONV: long, BASE: 16 } )
        self.field[PFC.F_NFSV4_ACL] = PBR.conv_by_rules(
                __opts[PFC.F_NFSV4_ACL], { CONV: long, BASE: 16 } )

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
        """Parse security subrecord"""

        __optlist = PBR.breakout_option_list(sio.get_word(1))
        self.field[PFC.F_FLAVOR] = PBR.conv_by_rules(
                __optlist[self.__prefix_flavor],
                { CONV: long } )
        try:
            self.field[PFC.F_PSEUDOFLAVOR] = PBR.conv_by_rules(
                    __optlist[self.__prefix_pseudoflavor],
                    { CONV: long } )
        except KeyError:
            self.field[PFC.F_PSEUDOFLAVOR] = 0
        return

# (G) \tevents: {!INT! }*
    def parse_events_line(self, sio):
        """Parse an 'events' subrecord"""

        self.field[PFC.F_EVENT_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (H) \tbytes: {!INT! }*
    def parse_bytes_line(self, sio):
        """Parse a 'bytes' subrecord"""

        self.field[PFC.F_BYTES_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (I) \ttfsc: {!INT! }*
    def parse_fscache_line(self, sio):
        """Parse a list of NFS cache stats numbers"""

        self.field[PFC.F_FSCACHE_LIST] = PBR.array_of_longs(sio.lineparts[1:])
        return

# (J) \tRPC iostats version: !VERSION! p/v: !INT!/!INT! (!PROTOCOL!)
    def parse_iostats_line(self, sio):
        """Parse a subrecord with I/O stats info"""

        self.field[PFC.F_VERSION] = sio.get_word(3)

        __part = sio.get_word(5).partition(self.__rpc_delim)
        self.field[PFC.F_RPC_PROG] = __part[0]
        self.field[PFC.F_RPC_VERS] = __part[2]

        self.field[PFC.F_PROTOCOL] = sio.get_word(6)[1:-1]

        return

# (K) \tper-op statistics
# (L) \t(14): !INT! !INT! !INT! !INT! !INT! !INT! !INT! !INT!
#     (14)!STATNAME!|!INT!|NULL
    def parse_per_op_line(self, sio):
        """Parse line containing and option name followed by a list of vals"""

        __stat = sio.get_word(0)
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
        """Parse a local-network version of an 'xprt' subrecord"""

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
        """Parse a udp version of an 'xprt' subrecord"""

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
        """Parse a tcp version of an 'xprt' subrecord"""

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
        """Parse an 'xprt' subrecord"""

        __rectype = sio.get_word(1)

        if __rectype == self.__flag_xprt_local:
            __val = self.parse_xprt_local(sio)

        elif __rectype == self.__flag_xprt_udp:
            __val = self.parse_xprt_udp(sio)

        elif __rectype == self.__flag_xprt_tcp:
            __val = self.parse_xprt_tcp(sio)

#        else:
#            print "dbg:: xprt mismatch '{line}'".format(line=sio.buff[:-1])

        self.field[PFC.F_XPRT_STATS][__rectype] = __val
        return

    def accumulate_info(self, sio):
        """Add a physical record to the accumulated logical record"""

        __first = sio.get_word(0)
        __second = sio.get_word(1)

        if __first == self.__prefix_dev:
            self.parse_device_line(sio)
        elif __first == self.__prefix_no and __second == self.__prefix_dev:
            self.parse_device_line(sio)
        elif __first == self.__prefix_opts:
            self.parse_options_line(sio)
        elif __first == self.__prefix_age:
            self.parse_age_line(sio)
        elif __first == self.__prefix_caps:
            self.parse_caps_line(sio)
        elif __first == self.__prefix_nfsv4:
            self.parse_nfsv4_line(sio)
        elif __first == self.__prefix_security:
            self.parse_security_line(sio)
        elif __first == self.__prefix_events:
            self.parse_events_line(sio)
        elif __first == self.__prefix_bytes:
            self.parse_bytes_line(sio)
        elif __first == self.__prefix_fscache:
            self.parse_fscache_line(sio)
        elif __first == self.__prefix_iostats:
            self.parse_iostats_line(sio)
        elif __first == self.__prefix_xprt:
            self.parse_xprt_line(sio)
        elif __first == self.__prefix_per_op:
            self.__is_per_op = True
        elif self.__is_per_op:
            self.parse_per_op_line(sio)
#        else:
#            print "dbg:: Ignoring rec '{line}'".format(line=sio.buff[:-1])
        return

    def next(self):
        try:
            result = super(ProcSelfMOUNTSTATS, self).next()
        except StopIteration:
            if self.__have_partial:
                result = self.extra_next(self.curr_sio)
            else:
                raise StopIteration
        return(result)

    def init_field_values(self):
        """Reset field dictionary to startng values"""

        self.field = dict()

        self.field[PFC.F_DEVICE] = ""
        self.field[PFC.F_MOUNTPOINT] = ""
        self.field[PFC.F_FSTYPE] = ""
        self.field[PFC.F_STATSVERS] = ""
        self.field[PFC.F_MOUNT_TYPE] = PDC.UNKNOWN_STATE
        self.field[PFC.F_WRITE_STATUS] = PDC.UNKNOWN_STATE
        self.field[PFC.F_AGE] = 0
        self.field[PFC.F_BYTES_LIST] = dict()
        self.field[PFC.F_EVENT_LIST] = dict()
        self.field[PFC.F_FSCACHE_LIST] = dict()
        self.field[PFC.F_PER_OP_STATS] = dict()
        self.field[PFC.F_XPRT_STATS] = dict()
        self.field[PFC.F_PROTOCOL] = ""
        self.field[PFC.F_VERSION] = ""

        for __mount_opt in self.__nfs_mount_opts_flag:
            self.field[__mount_opt] = False

        for __mount_opt in self.__nfs_mount_opts_long:
            self.field[__mount_opt] = 0

        for __mount_opt in self.__nfs_mount_opts_hex:
            self.field[__mount_opt] = 0

        for __mount_opt in self.__nfs_mount_opts_string:
            self.field[__mount_opt] = ""

    def extra_next(self, sio):

# -- Sample records (NFS mounts add all the complex sub-records, no sample
#    available yet)
#
# device udev mounted on /dev with fstype devtmpfs
# device devpts mounted on /dev/pts with fstype devpts
# device tmpfs mounted on /run with fstype tmpfs
# device /dev/disk/by-uuid/a959862a-84b7-4373-b7d6-954ac9005249 mounted on / with fstype ext4
# device none mounted on /sys/fs/fuse/connections with fstype fusectl

#        print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])
        self.__is_per_op = False
        self.init_field_values()

        if sio.buff != "" and not self.__have_partial:
            self.accumulate_info(sio)
            sio.read_line()
#            print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])

        self.partial_to_final()

        __complete = False
        while sio.buff != "" and not __complete:
            self.accumulate_info(sio)

            __first = sio.get_word(0)
            __second = sio.get_word(1)
            if __first == self.__prefix_dev or \
                    (__first == self.__prefix_no
                    and __second == self.__prefix_dev):
                __complete = True
            else:
                try:
                    sio.read_line()
#                    print "dbg:: readline: '{line}'".format(line=sio.buff[:-1])
                except StopIteration:
                    __complete = True

        self.device = self.field[PFC.F_DEVICE]
        self.mountpoint = self.field[PFC.F_MOUNTPOINT]
        self.fstype = self.field[PFC.F_FSTYPE]
        self.statsvers = self.field[PFC.F_STATSVERS]

        return(self.device, self.mountpoint, self.fstype, self.statsvers)

#
REGISTER_FILE("/proc/self/mountstats", ProcSelfMOUNTSTATS)
REGISTER_PARTIAL_FILE("mountstats", ProcSelfMOUNTSTATS)


# ---
class ProcSelfSMAPS(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/self/smaps"""
# 
# source: fs/proc/task_mmu.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcSelfHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_START, BEFORE: "-",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_END, AFTER: "-",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_FLAGS } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PAGE_OFFSET, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MAJOR_DEV, BEFORE: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MINOR_DEV, AFTER: ":",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_INODE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_PATH } )

        p2n = dict()
        p2n["Size:"] = PFC.F_SIZE
        p2n["Rss:"] = PFC.F_RSS
        p2n["Pss:"] = PFC.F_PSS
        p2n["Shared_Clean:"] = PFC.F_SH_CLEAN
        p2n["Shared_Dirty:"] = PFC.F_SH_DIRTY
        p2n["Private_Clean:"] = PFC.F_PR_CLEAN
        p2n["Private_Dirty:"] = PFC.F_PR_DIRTY
        p2n["Referenced:"] = PFC.F_REFERENCED
        p2n["Anonymous:"] = PFC.F_ANONYMOUS
        p2n["AnonHugePages:"] = PFC.F_ANON_HUGE_PAGES
        p2n["Swap:"] = PFC.F_SWAP
        p2n["KernelPageSize:"] = PFC.F_KERNEL_PGSZ
        p2n["MMUPageSize:"] = PFC.F_MMU_PGSZ
        p2n["Locked:"] = PFC.F_LOCKED
        self.__pref2field = p2n

        self.__eor_pref = "Locked:"

        self.st_addr = 0
        self.en_addr = 0
        self.flags = ""
        self.path = ""
        self.size = 0
        self.rss = 0
        self.pss = 0
        self.referenced = 0
        self.swap = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# 00400000-00420000 r-xp 00000000 09:01 149422156                          /bin/less
# Size:                128 kB
# Rss:                 104 kB
# Pss:                  34 kB
# Shared_Clean:        104 kB
# Shared_Dirty:          0 kB
# Private_Clean:         0 kB
# Private_Dirty:         0 kB
# Referenced:          104 kB
# Anonymous:             0 kB
# AnonHugePages:         0 kB
# Swap:                  0 kB
# KernelPageSize:        4 kB
# MMUPageSize:           4 kB
# Locked:                0 kB

        if sio.buff == "":
            self.field[PFC.F_START] = 0
            self.field[PFC.F_END] = 0
            self.field[PFC.F_FLAGS] = ""
            self.field[PFC.F_FL_READ] = ""
            self.field[PFC.F_FL_WRITE] = ""
            self.field[PFC.F_FL_EXEC] = ""
            self.field[PFC.F_FL_MAYSHARE] = ""
            self.field[PFC.F_PAGE_OFFSET] = 0
            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_INODE] = 0
            self.field[PFC.F_PATH] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_RSS] = 0
            self.field[PFC.F_PSS] = 0
            self.field[PFC.F_SH_CLEAN] = 0
            self.field[PFC.F_SH_DIRTY] = 0
            self.field[PFC.F_PR_CLEAN] = 0
            self.field[PFC.F_PR_DIRTY] = 0
            self.field[PFC.F_REFERENCED] = 0
            self.field[PFC.F_ANONYMOUS] = 0
            self.field[PFC.F_ANON_HUGE_PAGES] = 0
            self.field[PFC.F_SWAP] = 0
            self.field[PFC.F_KERNEL_PGSZ] = 0
            self.field[PFC.F_MMU_PGSZ] = 0
            self.field[PFC.F_LOCKED] = 0

        for __pref in self.__pref2field:
            self.field[self.__pref2field[__pref]] = 0

        __pref = ""

        while __pref != self.__eor_pref and sio.buff != "":
            sio.read_line()
            __pref = sio.get_word(0)

            try:
                __field = self.__pref2field[__pref]
                self.field[__field] = PBR.conv_by_rules(sio.get_word(1),
                        { CONV: long } )
            except KeyError:
                pass

        self.field[PFC.F_FL_READ] = self.field[PFC.F_FLAGS][:1]
        self.field[PFC.F_FL_WRITE] = self.field[PFC.F_FLAGS][1:2]
        self.field[PFC.F_FL_EXEC] = self.field[PFC.F_FLAGS][2:3]
        self.field[PFC.F_FL_MAYSHARE] = self.field[PFC.F_FLAGS][3:4]

        self.st_addr = self.field[PFC.F_START]
        self.en_addr = self.field[PFC.F_END]
        self.flags = self.field[PFC.F_FLAGS]
        self.path = self.field[PFC.F_PATH]
        self.size = self.field[PFC.F_SIZE]
        self.rss = self.field[PFC.F_RSS]
        self.pss = self.field[PFC.F_PSS]
        self.referenced = self.field[PFC.F_REFERENCED]
        self.swap = self.field[PFC.F_SWAP]

        return(self.st_addr, self.en_addr, self.flags, self.path, self.size,
                self.rss, self.pss, self.referenced, self.swap)
#
REGISTER_FILE("/proc/self/smaps", ProcSelfSMAPS)
REGISTER_PARTIAL_FILE("smaps", ProcSelfSMAPS)



# ---
class ProcSelfEXE(PBR.SymLinkFile):
    """Pull records from /proc/self/exe"""
#
REGISTER_FILE("/proc/self/exe", ProcSelfEXE)
REGISTER_PARTIAL_FILE("exe", ProcSelfEXE)



# ---
class ProcSelfCWD(PBR.SymLinkFile):
    """Pull records from /proc/self/cwd"""
#
REGISTER_FILE("/proc/self/cwd", ProcSelfCWD)
REGISTER_PARTIAL_FILE("cwd", ProcSelfCWD)



# ---
class ProcSelfROOT(PBR.SymLinkFile):
    """Pull records from /proc/self/root"""
#
REGISTER_FILE("/proc/self/root", ProcSelfROOT)
REGISTER_PARTIAL_FILE("root", ProcSelfROOT)



# ---
class ProcSelfFD(PBR.SymLinkFile):
    """Pull records from /proc/self/fd/* files"""

    def extra_init(self, *opts):
        if len(opts) == 0:
            self.infile = "{base}/0".format(base=self.infile)
        return

#
REGISTER_FILE("/proc/self/fd/0", ProcSelfFD)
REGISTER_PARTIAL_FILE("fd/", ProcSelfFD)



#
class ProcSelfSTATUS(PBR.TaggedMultiLineFile):
    """
    Parse contents of process specific 'status' file, ex: /proc/self/status
    """

# source: fs/proc/array.c
# --and--
# source: fs/proc/task_mmu.c
# --and---
# source: kernel/cpuset.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcSelfHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
        self.minfields = 2
        
        PBR.add_parse_rule(self, { PREFIX: "Name:\t", NAME: PFC.F_PROG_NAME } )
        PBR.add_parse_rule(self, { PREFIX: "State:\t",
                NAME: PFC.F_RUNSTATUS } )
        PBR.add_parse_rule(self, { PREFIX: "Tgid:\t", NAME: PFC.F_THREAD_GID,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "Pid:\t", NAME: PFC.F_PID,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "PPid:\t", NAME: PFC.F_PPID,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "TracerPid:\t",
                NAME: PFC.F_TRACER_PID, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "Uid:\t", NAME: PFC.F_UID_SET } )
        PBR.add_parse_rule(self, { PREFIX: "Gid:\t", NAME: PFC.F_GID_SET } )
        PBR.add_parse_rule(self, { PREFIX: "FDSize:\t", NAME: PFC.F_FDSIZE,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "Groups:\t", NAME: PFC.F_GROUPS } )
        PBR.add_parse_rule(self, { PREFIX: "VmPeak:\t", NAME: PFC.F_VM_PEAK,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmSize:\t", NAME: PFC.F_VM_SIZE,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmLck:\t", NAME: PFC.F_VM_LOCK,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmPin:\t", NAME: PFC.F_VM_PIN,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmHWM:\t", NAME: PFC.F_VM_HWM,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmRSS:\t", NAME: PFC.F_VM_RSS,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmData:\t", NAME: PFC.F_VM_DATA,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmStk:\t", NAME: PFC.F_VM_STACK,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmExe:\t", NAME: PFC.F_VM_EXE,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmLib:\t", NAME: PFC.F_VM_LIB,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmPTE:\t", NAME: PFC.F_VM_PTE,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "VmSwap:\t", NAME: PFC.F_VM_SWAP,
                SUFFIX: " kB", CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "Threads:\t", NAME: PFC.F_THREADS,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "SigQ:\t", NAME: PFC.F_SIG_QUEUE } )
        PBR.add_parse_rule(self, { PREFIX: "SigPnd:\t",
                NAME: PFC.F_SIG_PEND } )
        PBR.add_parse_rule(self, { PREFIX: "ShdPnd:\t",
                NAME: PFC.F_SIG_SH_PEND } )
        PBR.add_parse_rule(self, { PREFIX: "SigBlk:\t",
                NAME: PFC.F_SIG_BLOCK } )
        PBR.add_parse_rule(self, { PREFIX: "SigIgn:\t", NAME: PFC.F_SIG_IGN } )
        PBR.add_parse_rule(self, { PREFIX: "SigCgt:\t",
                NAME: PFC.F_SIG_CAUGHT } )
        PBR.add_parse_rule(self, { PREFIX: "CapInh:\t", NAME:
                PFC.F_CAP_INHERIT } )
        PBR.add_parse_rule(self, { PREFIX: "CapPrm:\t",
                NAME: PFC.F_CAP_PERM } )
        PBR.add_parse_rule(self, { PREFIX: "CapEff:\t", NAME: PFC.F_CAP_EFF } )
        PBR.add_parse_rule(self, { PREFIX: "CapBnd:\t",
                NAME: PFC.F_CAP_BSET } )
        PBR.add_parse_rule(self, { PREFIX: "Cpus_allowed:\t",
                NAME: PFC.F_CPU_ALLOW_MASK } )
        PBR.add_parse_rule(self, { PREFIX: "Cpus_allowed_list:\t",
                NAME: PFC.F_CPU_ALLOW_LIST } )
        PBR.add_parse_rule(self, { PREFIX: "Mems_allowed:\t",
                NAME: PFC.F_MEM_ALLOW_MASK } )
        PBR.add_parse_rule(self, { PREFIX: "Mems_allowed_list:\t",
                NAME: PFC.F_MEM_ALLOW_LIST } )
        PBR.add_parse_rule(self, { PREFIX: "voluntary_ctxt_switches:\t",
                NAME: PFC.F_CSWITCH_VOL, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "nonvoluntary_ctxt_switches:\t",
                NAME: PFC.F_CSWITCH_NONVOL, CONV: long } )

        self.add_eor_rule( "nonvoluntary_ctxt_switches", { BEFORE: ":" } )

        return


    def extra_next(self, sio):

        try:
            __split = self.field[PFC.F_UID_SET].split("\t")
        except KeyError:
            __split = []

        __conv = [ PDC.NO_UID, PDC.NO_UID, PDC.NO_UID, PDC.NO_UID ]

        __cr = { CONV: long, ERRVAL: PDC.NO_UID }
        for __off in range(0, min(len(__split), len(__conv))):
            __conv[__off] = PBR.conv_by_rules(__split[__off], __cr)

        self.field[PFC.F_UID] = __conv[0]
        self.field[PFC.F_EUID] = __conv[1]
        self.field[PFC.F_SUID] = __conv[2]
        self.field[PFC.F_FSUID] = __conv[3]

        try:
            __split = self.field[PFC.F_GID_SET].split("\t")
        except KeyError:
            __split = []

        __conv = [ PDC.NO_GID, PDC.NO_GID, PDC.NO_GID, PDC.NO_GID ]

        __cr = { CONV: long, ERRVAL: PDC.NO_UID }
        for __off in range(0, min(len(__split), len(__conv))):
            __conv[__off] = PBR.conv_by_rules(__split[__off], __cr)

        self.field[PFC.F_GID] = __conv[0]
        self.field[PFC.F_EGID] = __conv[1]
        self.field[PFC.F_SGID] = __conv[2]
        self.field[PFC.F_FSGID] = __conv[3]

        try:
            __conv = self.field[PFC.F_GROUPS].strip().split(" ")
        except KeyError:
            __conv = []

        for __off in range(0, len(__conv)):
            __val = __conv[__off]
            __conv[__off] = PBR.conv_by_rules(__val, { CONV: long,
                    ERRVAL: PDC.NO_GID } )

        self.field[PFC.F_GROUPS] = __conv

        return self.field

REGISTER_FILE("/proc/self/status", ProcSelfSTATUS)
REGISTER_PARTIAL_FILE("status", ProcSelfSTATUS)



#
class ProcSelfSCHED(PBR.TaggedMultiLineFile):
    """Parse contents of process specific 'sched' file, ex: /proc/self/sched"""

# source: fs/proc/base.c
# --and--
# source: kernel/sched_debug.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcSelfHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
        self.minfields = 2
        
        self.__two_longs = ( PFC.F_EXEC_START, PFC.F_RUNTIME,
                PFC.F_EXEC_RUNTIME, PFC.F_ST_WAIT_START, PFC.F_ST_SLEEP_START,
                PFC.F_ST_BLOCK_START, PFC.F_ST_SLEEP_MAX, PFC.F_ST_BLOCK_MAX,
                PFC.F_ST_EXEC_MAX, PFC.F_ST_SLICE_MAX, PFC.F_ST_WAIT_MAX,
                PFC.F_ST_WAIT_SUM, PFC.F_ST_IOWAIT_SUM, PFC.F_AVG_ATOM,
                PFC.F_AVG_PER_CPU )

        PBR.add_parse_rule(self, { NAME: PFC.F_PROGRAM, HAS: "#threads:", } )
        PBR.add_parse_rule(self, { NAME: PFC.F_EXEC_START,
                PREFIX: "se.exec_start", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_RUNTIME, PREFIX: "se.vruntime",
                AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_EXEC_RUNTIME,
                PREFIX: "se.sum_exec_runtime", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_WAIT_START,
                PREFIX: "se.statistics.wait_start", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_SLEEP_START,
                PREFIX: "se.statistics.sleep_start", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_BLOCK_START,
                PREFIX: "se.statistics.block_start", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_SLEEP_MAX,
                PREFIX: "se.statistics.sleep_max", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_BLOCK_MAX,
                PREFIX: "se.statistics.block_max", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_EXEC_MAX,
                PREFIX: "se.statistics.exec_max", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_SLICE_MAX,
                PREFIX: "se.statistics.slice_max", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_WAIT_MAX,
                PREFIX: "se.statistics.wait_max", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_WAIT_SUM,
                PREFIX: "se.statistics.wait_sum", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_WAIT_COUNT,
                PREFIX: "se.statistics.wait_count", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_IOWAIT_SUM,
                PREFIX: "se.statistics.iowait_sum", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_IOWAIT_COUNT,  CONV: long,
                PREFIX: "se.statistics.iowait_count", AFTER: ":"  } )
        PBR.add_parse_rule(self, { NAME: PFC.F_NR_MIGR,
                PREFIX: "se.nr_migrations", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_MIGR_COLD, CONV: long,
                PREFIX: "se.statistics.nr_migrations_cold", AFTER: ":",  } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_FAIL_MIGR_AFF,
                PREFIX: "se.statistics.nr_failed_migrations_affine",
                AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_FAIL_MIGR_RUN,
                PREFIX: "se.statistics.nr_failed_migrations_running",
                AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_FAIL_MIGR_HOT,
                PREFIX: "se.statistics.nr_failed_migrations_hot", AFTER: ":",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_FORCED_MIGR,
                PREFIX: "se.statistics.nr_forced_migrations", AFTER: ":",
                CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE, CONV: long,
                PREFIX: "se.statistics.nr_wakeups", AFTER: ":"  } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_SYNC, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_sync", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_MIGR, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_migrate", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_LOC, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_local", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_REM, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_remote", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_AFF, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_affine", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_AFF_ATT,
                PREFIX: "se.statistics.nr_wakeups_affine_attempts",
                AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_PASS, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_passive", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_ST_NR_WAKE_IDLE, CONV: long,
                PREFIX: "se.statistics.nr_wakeups_idle", AFTER: ":" } )
        PBR.add_parse_rule(self, { NAME: PFC.F_AVG_ATOM, PREFIX: "avg_atom",
                AFTER: ":",  } )
        PBR.add_parse_rule(self, { NAME: PFC.F_AVG_PER_CPU,
                PREFIX: "avg_per_cpu", AFTER: ":",  } )
        PBR.add_parse_rule(self, { NAME: PFC.F_NR_SWITCH,
                PREFIX: "nr_switches", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_NR_VOL_SWITCH,
                PREFIX: "nr_voluntary_switches", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_NR_INVOL_SWITCH,
                PREFIX: "nr_involuntary_switches", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_LOAD_WEIGHT,
                PREFIX: "se.load.weight", AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_POLICY, PREFIX: "policy",
                AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_PRIORITY, PREFIX: "prio",
                AFTER: ":", CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_CLOCK_DELTA,
                PREFIX: "clock-delta", AFTER: ":", CONV: long } )

        self.add_eor_rule( "clock-delta", { BEFORE: ":" } )

        return


    def extra_next(self, sio):
        __mix = self.field[PFC.F_PROGRAM]
        self.field[PFC.F_PID] = PBR.conv_by_rules(__mix, { NAME: PFC.F_PID,
                AFTER: "(", BEFORE: ",", CONV: long } )
        self.field[PFC.F_THREADS] = PBR.conv_by_rules(__mix, {
                NAME: PFC.F_PID, AFTER: "#threads: ", BEFORE: ")",
                CONV: long } )
        self.field[PFC.F_PROGRAM] = PBR.conv_by_rules(__mix, { 
                NAME: PFC.F_PID, BEFORE: " (" } )

        for __key in self.__two_longs:
            self.field[__key] = PBR.hilo_pair_from_str(self.field[__key])

        return self.field

REGISTER_FILE("/proc/self/sched", ProcSelfSCHED)
REGISTER_PARTIAL_FILE("sched", ProcSelfSCHED)


#
class ProcSelfPERSONALITY(PBR.FixedWhitespaceDelimRecs):
    """
    Parse process specific file 'personality', ex: /proc/self/personality
    """

# source: fs/proc/base.c
#
# Extract from that code
# 
# static int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
#                                 struct pid *pid, struct task_struct *task)
# {
#         int err = lock_trace(task);
#         if (!err) {
#                 seq_printf(m, "%08x\n", task->personality);
#                 unlock_trace(task);
#         }
#         return err;
# }

    def extra_init(self, *opts):
        self.minfields = 1

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PERSONALITY,
                CONV: long, BASE: 16 } )

        self.personality = ""
        return


    def extra_next(self, sio):

        self.personality = self.field[PFC.F_PERSONALITY]

        return self.personality

REGISTER_FILE("/proc/self/personality", ProcSelfPERSONALITY)
REGISTER_PARTIAL_FILE("personality", ProcSelfPERSONALITY)




#
class ProcSelfAUTOGROUP(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/autogroup file
    """

# source: kernel/sched_autogroup.c
#
#  seq_printf(m, "/autogroup-%ld nice %d\n", ag->id, ag->nice);
#

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, PREFIX: "/autogroup-", CONV: long, 
                NAME: PFC.F_ID } )
        PBR.add_parse_rule(self, { POS: 2, CONV: long, NAME: PFC.F_NICE } )
        return
                 

    def extra_next(self, sio):

        __id = self.field[PFC.F_ID]
        __nice = self.field[PFC.F_NICE]

        return(__id, __nice)

REGISTER_FILE("/proc/self/autogroup", ProcSelfAUTOGROUP)
REGISTER_PARTIAL_FILE("autogroup", ProcSelfAUTOGROUP)




#
class ProcSelfCOMM(PBR.SingleTextField):
    """
    Parse /proc/self/comm file
    """

# source: fs/proc/base.c
#
#  seq_printf(m, "%s\n", p->comm);
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_COMM] = __line
        return(__line)

REGISTER_FILE("/proc/self/comm", ProcSelfCOMM)
REGISTER_PARTIAL_FILE("comm", ProcSelfCOMM)




#
class ProcSelfCMDLINE(PBR.SingleTextField):
    """
    Parse /proc/self/cmdline file
    """

# source: fs/proc/cmdline.c
#
#   seq_printf(m, "%s\n", saved_command_line);
#

    def extra_next(self, sio):
        __split = sio.buff.split("\0")
        self.field[PFC.F_COMM] = " ".join(__split)
        return(self.field[PFC.F_COMM])

REGISTER_FILE("/proc/self/cmdline", ProcSelfCMDLINE)
REGISTER_PARTIAL_FILE("ps/cmdline", ProcSelfCMDLINE)
REGISTER_PARTIAL_FILE("cmdline", ProcSelfCMDLINE)




#
class ProcSelfCPUSET(PBR.SingleTextField):
    """
    Parse /proc/self/cpuset file
    """

# source: 
#
#
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_CPU_SET] = __line
        return(self.field[PFC.F_CPU_SET])

REGISTER_FILE("/proc/self/cpuset", ProcSelfCPUSET)
REGISTER_PARTIAL_FILE("cpuset", ProcSelfCPUSET)




#
class ProcSelfSYSCALL(PBR.SingleTextField):
    """
    Parse /proc/self/syscall file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# if (task_current_syscall(task, &nr, args, 6, &sp, &pc))
#         res = sprintf(buffer, "running\n");
# else if (nr < 0)
#         res = sprintf(buffer, "%ld 0x%lx 0x%lx\n", nr, sp, pc);
# else
#         res = sprintf(buffer,
#                "%ld 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
#                nr,
#                args[0], args[1], args[2], args[3], args[4], args[5],
#                sp, pc);
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_SYSCALL] = __line

        sio.close_file()

        return(self.field[PFC.F_SYSCALL])

REGISTER_FILE("/proc/self/syscall", ProcSelfSYSCALL)
REGISTER_PARTIAL_FILE("syscall", ProcSelfSYSCALL)




#
class ProcSelfWCHAN(PBR.SingleTextField):
    """
    Parse /proc/self/wchan file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# if (lookup_symbol_name(wchan, symname) < 0)
#         if (!ptrace_may_access(task, PTRACE_MODE_READ))
#                 return 0;
#         else
#                 return sprintf(buffer, "%lu", wchan);
# else
#         return sprintf(buffer, "%s", symname);
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_WCHAN] = __line

        sio.close_file()

        return(self.field[PFC.F_WCHAN])

REGISTER_FILE("/proc/self/wchan", ProcSelfWCHAN)
REGISTER_PARTIAL_FILE("wchan", ProcSelfWCHAN)




#
class ProcSelfSESSIONID(PBR.SingleTextField):
    """
    Parse /proc/self/sessionid file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
#                         audit_get_sessionid(task));
# put_task_struct(task);
# return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_SESSIONID] = __line

        return(self.field[PFC.F_SESSIONID])

REGISTER_FILE("/proc/self/sessionid", ProcSelfSESSIONID)
REGISTER_PARTIAL_FILE("sessionid", ProcSelfSESSIONID)




#
class ProcSelfLOGINUID(PBR.SingleTextField):
    """
    Parse /proc/self/loginuid file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
#                         audit_get_loginuid(task));
# put_task_struct(task);
# return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
#

    def extra_next(self, sio):
        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_LOGINUID] = __line

        return(self.field[PFC.F_LOGINUID])

REGISTER_FILE("/proc/self/loginuid", ProcSelfLOGINUID)
REGISTER_PARTIAL_FILE("loginuid", ProcSelfLOGINUID)




class ProcSelfSTATM(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/statm file
    """

# source: fs/proc/array.c
#
# Excerpt from that code
#
# seq_printf(m, "%lu %lu %lu %lu 0 %lu 0\n",
#                 size, resident, shared, text, data);
#

    def extra_init(self, *opts):
        self.minfields = 7

        PBR.add_parse_rule(self, { POS: 0, CONV: long,
                NAME: PFC.F_SIZE } )
        PBR.add_parse_rule(self, { POS: 1, CONV: long,
                NAME: PFC.F_RESIDENT_SIZE } )
        PBR.add_parse_rule(self, { POS: 2, CONV: long,
                NAME: PFC.F_SHARED_SIZE } )
        PBR.add_parse_rule(self, { POS: 3, CONV: long,
                NAME: PFC.F_TEXT_SIZE } )
        PBR.add_parse_rule(self, { POS: 5, CONV: long,
                NAME: PFC.F_DATA_SIZE } )
        return
                 

    def extra_next(self, sio):

        __size = self.field[PFC.F_SIZE]
        __resident = self.field[PFC.F_RESIDENT_SIZE]
        __shared = self.field[PFC.F_SHARED_SIZE]
        __text = self.field[PFC.F_TEXT_SIZE]
        __data = self.field[PFC.F_DATA_SIZE]

        return(__size, __resident, __shared, __text, __data)

REGISTER_FILE("/proc/self/statm", ProcSelfSTATM)
REGISTER_PARTIAL_FILE("statm", ProcSelfSTATM)




class ProcSelfSTAT(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/stat file
    """

# source: 
#
# Excerpt from that code
#
# See README.ProcSelfHandlers for kernel code snippets
#

    def extra_init(self, *opts):
        self.minfields = 7

        PBR.add_parse_rule(self, { POS: 0, CONV: long, NAME: PFC.F_PID_NR } )
        PBR.add_parse_rule(self, { POS: 1, AFTER: "(", BEFORE: ")",
                NAME: PFC.F_COMM } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_STATE } )
        PBR.add_parse_rule(self, { POS: 3, CONV: long, NAME: PFC.F_PPID } )
        PBR.add_parse_rule(self, { POS: 4, CONV: long, NAME: PFC.F_PGID } )
        PBR.add_parse_rule(self, { POS: 5, CONV: long, NAME: PFC.F_SID } )
        PBR.add_parse_rule(self, { POS: 6, CONV: long, NAME: PFC.F_TTY_NR } )
        PBR.add_parse_rule(self, { POS: 7, CONV: long, NAME: PFC.F_TTY_PGRP } )
        PBR.add_parse_rule(self, { POS: 8, CONV: long, NAME: PFC.F_FLAGS } )
        PBR.add_parse_rule(self, { POS: 9, CONV: long, NAME: PFC.F_MIN_FLT } )
        PBR.add_parse_rule(self, { POS: 10, CONV: long,
                NAME: PFC.F_CMIN_FLT } )
        PBR.add_parse_rule(self, { POS: 11, CONV: long, NAME: PFC.F_MAJ_FLT } )
        PBR.add_parse_rule(self, { POS: 12, CONV: long,
                NAME: PFC.F_CMAJ_FLT } )
        PBR.add_parse_rule(self, { POS: 13, CONV: long, NAME: PFC.F_UTIME } )
        PBR.add_parse_rule(self, { POS: 14, CONV: long, NAME: PFC.F_STIME } )
        PBR.add_parse_rule(self, { POS: 15, CONV: long, NAME: PFC.F_CUTIME } )
        PBR.add_parse_rule(self, { POS: 16, CONV: long, NAME: PFC.F_CSTIME } )
        PBR.add_parse_rule(self, { POS: 17, CONV: long,
                NAME: PFC.F_PRIORITY } )
        PBR.add_parse_rule(self, { POS: 18, CONV: long, NAME: PFC.F_NICE } )
        PBR.add_parse_rule(self, { POS: 19, CONV: long, NAME: PFC.F_THREADS } )
        PBR.add_parse_rule(self, { POS: 21, CONV: long,
                NAME: PFC.F_START_TIME } )
        PBR.add_parse_rule(self, { POS: 22, CONV: long, NAME: PFC.F_VSIZE } )
        PBR.add_parse_rule(self, { POS: 23, CONV: long,
                NAME: PFC.F_RSS_SIZE } )
        PBR.add_parse_rule(self, { POS: 24, CONV: long, NAME: PFC.F_RSS_LIM } )
                
        PBR.add_parse_rule(self, { POS: 25, CONV: long,
                NAME: PFC.F_START_CODE } )
        PBR.add_parse_rule(self, { POS: 26, CONV: long,
                NAME: PFC.F_END_CODE } )
        PBR.add_parse_rule(self, { POS: 27, CONV: long,
                NAME: PFC.F_START_STACK } )
        PBR.add_parse_rule(self, { POS: 28, CONV: long, NAME: PFC.F_ESP } )
        PBR.add_parse_rule(self, { POS: 29, CONV: long, NAME: PFC.F_EIP } )
        PBR.add_parse_rule(self, { POS: 30, CONV: long,
                NAME: PFC.F_SIG_PEND } )
        PBR.add_parse_rule(self, { POS: 31, CONV: long,
                NAME: PFC.F_SIG_BLOCK } )
        PBR.add_parse_rule(self, { POS: 32, CONV: long,
                NAME: PFC.F_SIG_IGNORE } )
        PBR.add_parse_rule(self, { POS: 33, CONV: long,
                NAME: PFC.F_SIG_CATCH } )
        PBR.add_parse_rule(self, { POS: 34, CONV: long, NAME: PFC.F_WCHAN } )
        PBR.add_parse_rule(self, { POS: 37, CONV: long,
                NAME: PFC.F_EXIT_SIG } )
        PBR.add_parse_rule(self, { POS: 38, CONV: long, NAME: PFC.F_TASK } )
        PBR.add_parse_rule(self, { POS: 39, CONV: long,
                NAME: PFC.F_RT_PRIORITY } )
        PBR.add_parse_rule(self, { POS: 40, CONV: long, NAME: PFC.F_POLICY } )
        PBR.add_parse_rule(self, { POS: 41, CONV: long,
                NAME: PFC.F_IO_TICKS } )
        PBR.add_parse_rule(self, { POS: 42, CONV: long, NAME: PFC.F_GTIME } )
        PBR.add_parse_rule(self, { POS: 43, CONV: long, NAME: PFC.F_CGTIME } )
        return
                 

    def extra_next(self, sio):
        return(self.field)

REGISTER_FILE("/proc/self/stat", ProcSelfSTAT)
REGISTER_PARTIAL_FILE("ps/stat", ProcSelfSTAT)




class ProcSelfSCHEDSTAT(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/statm file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
#static int proc_pid_schedstat(struct task_struct *task, char *buffer)
#{
#    return sprintf(buffer, "%llu %llu %lu\n",
#             (unsigned long long)task->se.sum_exec_runtime,
#             (unsigned long long)task->sched_info.run_delay,
#                task->sched_info.pcount);
#}
#

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, CONV: long, NAME: PFC.F_RUN_TIME } )
        PBR.add_parse_rule(self, { POS: 1, CONV: long,
                NAME: PFC.F_RUNQUEUE_TIME } )
        PBR.add_parse_rule(self, { POS: 2, CONV: long,
                NAME: PFC.F_RUN_TIMESLICES } )
        return
                 

    def extra_next(self, sio):

        __run = self.field[PFC.F_RUN_TIME]
        __queue = self.field[PFC.F_RUNQUEUE_TIME]
        __slices = self.field[PFC.F_RUN_TIMESLICES]

        return(__run, __queue, __slices)

REGISTER_FILE("/proc/self/schedstat", ProcSelfSCHEDSTAT)
REGISTER_PARTIAL_FILE("ps/schedstat", ProcSelfSCHEDSTAT)




class ProcSelfCOREDUMPFILTER(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/coredump_filter file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# len = snprintf(buffer, sizeof(buffer), "%08lx\n",
#                ((mm->flags & MMF_DUMP_FILTER_MASK) >>
#                 MMF_DUMP_FILTER_SHIFT));
# mmput(mm);
# ret = simple_read_from_buffer(buf, count, ppos, buffer, len);
#

    def extra_init(self, *opts):
        self.minfields = 1
        PBR.add_parse_rule(self, { POS: 0, CONV: long, BASE: 16,
                NAME: PFC.F_COREDUMP_FILTER } )
        return
                 
    def extra_next(self, sio):
        return(self.field[PFC.F_COREDUMP_FILTER])

REGISTER_FILE("/proc/self/coredump_filter", ProcSelfCOREDUMPFILTER)
REGISTER_PARTIAL_FILE("ps/coredump_filter", ProcSelfCOREDUMPFILTER)




class ProcSelfOOMSCORE(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/oom_score file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# if (pid_alive(task))
#         points = oom_badness(task, NULL, NULL,
#                                 totalram_pages + total_swap_pages);
# read_unlock(&tasklist_lock);
# return sprintf(buffer, "%lu\n", points);
#

    def extra_init(self, *opts):
        self.minfields = 1
        PBR.add_parse_rule(self, { POS: 0, CONV: long,
                NAME: PFC.F_OOM_SCORE } )
        return
                 
    def extra_next(self, sio):
        return(self.field[PFC.F_OOM_SCORE])

REGISTER_FILE("/proc/self/oom_score", ProcSelfOOMSCORE)
REGISTER_PARTIAL_FILE("oom_score", ProcSelfOOMSCORE)




class ProcSelfOOMADJ(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/oom_adj file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# if (lock_task_sighand(task, &flags)) {
#         oom_adjust = task->signal->oom_adj;
#         unlock_task_sighand(task, &flags);
# }
#
# put_task_struct(task);
#
# len = snprintf(buffer, sizeof(buffer), "%i\n", oom_adjust);
#
# return simple_read_from_buffer(buf, count, ppos, buffer, len);
#

    def extra_init(self, *opts):
        self.minfields = 1
        PBR.add_parse_rule(self, { POS: 0, CONV: long, NAME: PFC.F_OOM_ADJ } )
        return
                 
    def extra_next(self, sio):
        return(self.field[PFC.F_OOM_ADJ])

REGISTER_FILE("/proc/self/oom_adj", ProcSelfOOMADJ)
REGISTER_PARTIAL_FILE("oom_adj", ProcSelfOOMADJ)




class ProcSelfOOMSCOREADJ(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/self/oom_adj file
    """

# source: fs/proc/base.c
#
# Excerpt from that code
#
# if (lock_task_sighand(task, &flags)) {
#         oom_score_adj = task->signal->oom_score_adj;
#         unlock_task_sighand(task, &flags);
# }
# put_task_struct(task);
# len = snprintf(buffer, sizeof(buffer), "%d\n", oom_score_adj);
# return simple_read_from_buffer(buf, count, ppos, buffer, len);
#

    def extra_init(self, *opts):
        self.minfields = 1
        PBR.add_parse_rule(self, { POS: 0, CONV: long,
                NAME: PFC.F_OOM_SCORE_ADJ } )
        return
                 
    def extra_next(self, sio):
        return(self.field[PFC.F_OOM_SCORE_ADJ])

REGISTER_FILE("/proc/self/oom_score_adj", ProcSelfOOMSCOREADJ)
REGISTER_PARTIAL_FILE("oom_score_adj", ProcSelfOOMSCOREADJ)



#
class ProcSelfENVIRON(PBR.SingleTextField):
    """
    Parse /proc/self/environ file
    """

# source: fs/proc/base.c
#
# The routine responsible for gathering the data written to this file is
# environ_read() but reviewing that code probably won't explain the contents of
# the file very much.  The important point to note is that it's just a
# collection of '\0' terminated name/value pairs string together.  And there's
# no LF ('\n') on the end.
#

    def extra_next(self, sio):

        __nvps = sio.buff.split("\0")
        for __ref in __nvps:
            __key = __ref.partition("=")[0]
            if __key != __ref:
                __val = __ref.partition("=")[2]
                self.field[__key] = __val

        return(self.field)

REGISTER_FILE("/proc/self/environ", ProcSelfENVIRON)
REGISTER_PARTIAL_FILE("environ", ProcSelfENVIRON)




if __name__ == "__main__":

    print "Collection of handlers to parse file in the root /proc/self and \
/proc/[0-9]* directories"

