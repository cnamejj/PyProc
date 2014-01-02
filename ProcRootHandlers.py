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

    print "Collection of handlers to parse file in the root /proc directory"


# ---
class ProcRootEXECDOMAINS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/execdomains"""
# source: kernel/exec_domain.c
#   for (ep = exec_domains; ep; ep = ep->next)
#           seq_printf(m, "%d-%d\t%-16s\t[%s]\n",
#                         ep->pers_low, ep->pers_high, ep->name,
#                          module_name(ep->module));

    def extra_init(self, *opts):
        self.minfields = 3

        self.pers_low = 0
        self.pers_high = 0
        self.exdom_name = ""
        self.exdom_module = ""
        self.__FieldSplitDelim = "-"
        return

    def extra_next(self, sio):

# -- Sample records (the real file has no column headers, they are added to clarify how the file is parsed)
# PL-PH Name                    Module
# 0-0	Linux           	[kernel]

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_PERSONALITY_LOW] = 0
            self.field[PFC.F_PERSONALITY_HIGH] = 0
            self.field[PFC.F_EXDOM_NAME] = ""
            self.field[PFC.F_EXDOM_MODULE] = ""

        else:
            __split = sio.lineparts[0].partition(self.__FieldSplitDelim)
            self.field[PFC.F_PERSONALITY_LOW] = long(__split[0])
            self.field[PFC.F_PERSONALITY_HIGH] = long(__split[2])
            self.field[PFC.F_EXDOM_NAME] = sio.lineparts[1]
            self.field[PFC.F_EXDOM_MODULE] = sio.lineparts[2]

        self.pers_low = self.field[PFC.F_PERSONALITY_LOW]
        self.pers_high = self.field[PFC.F_PERSONALITY_HIGH]
        self.exdom_name = self.field[PFC.F_EXDOM_NAME]
        self.exdom_module = self.field[PFC.F_EXDOM_MODULE]

        return( self.pers_low, self.pers_high, self.exdom_name, self.exdom_module)
#
RegisterProcFileHandler("/proc/execdomains", ProcRootEXECDOMAINS)
RegisterPartialProcFileHandler("execdomains", ProcRootEXECDOMAINS)



# ---
class ProcRootCGROUPS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/cgroups"""
# source: kernel/cgroup.c
#
#      for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
#              struct cgroup_subsys *ss = subsys[i];
#              if (ss == NULL)
#                      continue;
#              seq_printf(m, "%s\t%d\t%d\t%d\n",
#                         ss->name, ss->root->hierarchy_id,
#                         ss->root->number_of_cgroups, !ss->disabled);
#      }


    def extra_init(self, *opts):
        self.minfields = 4
        self.skipped = "#subsys_name"

        self.subsys = ""
        self.hierachy = 0
        self.cgroups = 0
        self.enabled = 0
        return

    def extra_next(self, sio):

# -- Sample records
# #subsys_name	hierarchy	num_cgroups	enabled
# cpuset	0	1	1
# cpu		0	1	1
# cpuacct	0	1	1

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_SUBSYSTEM] = ""
            self.field[PFC.F_HIERARCHY] = 0
            self.field[PFC.F_NUM_CGROUPS] = 0
            self.field[PFC.F_ENABLED] = 0

        else:
            self.field[PFC.F_SUBSYSTEM] = sio.lineparts[0]
            self.field[PFC.F_HIERARCHY] = long(sio.lineparts[1])
            self.field[PFC.F_NUM_CGROUPS] = long(sio.lineparts[2])
            self.field[PFC.F_ENABLED] = long(sio.lineparts[3])

        self.subsys = self.field[PFC.F_SUBSYSTEM]
        self.hierachy = self.field[PFC.F_HIERARCHY]
        self.cgroups = self.field[PFC.F_NUM_CGROUPS]
        self.enabled = self.field[PFC.F_ENABLED] = 0

        return( self.subsys, self.hierachy, self.cgroups, self.enabled)
#
RegisterProcFileHandler("/proc/cgroups", ProcRootCGROUPS)
RegisterPartialProcFileHandler("cgroups", ProcRootCGROUPS)



# ---
class ProcRootMTRR(PBR.fixed_delim_format_recs):
    """Pull records from /proc/mtrr"""
# source: arch/x86/kernel/cpu/mtrr/if.c
#
#        for (i = 0; i < max; i++) {
#                mtrr_if->get(i, &base, &size, &type);
#                if (size == 0) {
#                        mtrr_usage_table[i] = 0;
#                        continue;
#                }
#                if (size < (0x100000 >> PAGE_SHIFT)) {
#                        /* less than 1MB */
#                        factor = 'K';
#                        size <<= PAGE_SHIFT - 10;
#                } else {
#                        factor = 'M';
#                        size >>= 20 - PAGE_SHIFT;
#                }
#                /* Base can be > 32bit */
#                len += seq_printf(seq, "reg%02i: base=0x%06lx000 "
#                        "(%5luMB), size=%5lu%cB, count=%d: %s\n",
#                        i, base, base >> (20 - PAGE_SHIFT), size,
#                        factor, mtrr_usage_table[i],
#                        mtrr_attrib_to_str(type));
#        }

    def extra_init(self, *opts):
        self.minfields = 6

        self.index = 0
        self.base = 0
        self.size = 0
        self.count = 0
        self.type = ""
        self.__SizePref = "size="
        return

    def extra_next(self, sio):

# -- Sample records
#
# reg00: base=0x000000000 (    0MB), size= 2048MB, count=1: write-back
# reg01: base=0x080000000 ( 2048MB), size= 1024MB, count=1: write-back
# reg02: base=0x0c0000000 ( 3072MB), size=  256MB, count=1: write-back
# reg03: base=0x0cf800000 ( 3320MB), size=    8MB, count=1: uncachable


        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_BASE_MEMORY] = 0
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_COUNT] = 0
            self.field[PFC.F_TYPE] = ""

        else:
            self.field[PFC.F_INDEX] = long(sio.lineparts[0][-3:-1])
            self.field[PFC.F_BASE_MEMORY] = long(sio.lineparts[1][-9:-5], 16)

            __offset = 3
            if sio.lineparts[__offset] == self.__SizePref:
                __offset = __offset + 1
            elif sio.lineparts[__offset][:len(self.__SizePref)] != self.__SizePref:
                __offset = __offset + 1
                if sio.lineparts[__offset] == self.__SizePref:
                    __offset = __offset + 1
            self.field[PFC.F_SIZE] = long(sio.lineparts[__offset][-8:-3])

            __offset = __offset + 1
            self.field[PFC.F_COUNT] = long(sio.lineparts[__offset][6:-1])

            __offset = __offset + 1
            self.field[PFC.F_TYPE] = sio.lineparts[__offset]
                
        self.index = self.field[PFC.F_INDEX]
        self.base = self.field[PFC.F_BASE_MEMORY]
        self.size = self.field[PFC.F_SIZE]
        self.count = self.field[PFC.F_COUNT]
        self.type = self.field[PFC.F_TYPE]

        return( self.index, self.base, self.size, self.count, self.type)
#
RegisterProcFileHandler("/proc/mtrr", ProcRootMTRR)
RegisterPartialProcFileHandler("mtrr", ProcRootMTRR)



# ---
class ProcRootMODULES(PBR.fixed_delim_format_recs):
    """Pull records from /proc/modules"""
# source: kernel/module.c
#
# ... in routine m_show():
#
#        seq_printf(m, "%s %u",
#                   mod->name, mod->init_size + mod->core_size);
#        print_unload_info(m, mod);
#
#        /* Informative for users. */
#        seq_printf(m, " %s",
#                   mod->state == MODULE_STATE_GOING ? "Unloading":
#                   mod->state == MODULE_STATE_COMING ? "Loading":
#                   "Live");
#        /* Used by oprofile and other similar tools. */
#        seq_printf(m, " 0x%pK", mod->module_core);
#
#        /* Taints info */
#        if (mod->taints)
#                seq_printf(m, " %s", module_flags(mod, buf));
#
#        seq_printf(m, "\n");
#
# ... in routine print_unload_info():
#
#        seq_printf(m, " %u ", module_refcount(mod));
#
#        /* Always include a trailing , so userspace can differentiate
#           between this and the old multi-field proc format. */
#        list_for_each_entry(use, &mod->source_list, source_list) {
#                printed_something = 1;
#                seq_printf(m, "%s,", use->source->name);
#        }
#
#        if (mod->init != NULL && mod->exit == NULL) {
#                printed_something = 1;
#                seq_printf(m, "[permanent],");
#        }
#
#        if (!printed_something)
#                seq_printf(m, "-");
#

    def extra_init(self, *opts):
        self.minfields = 6

        self.module = ""
        self.size = 0
        self.refcount = 0
        self.source_list = ""
        self.status = ""
        self.module_core = 0
        self.taints = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# pci_stub 12622 1 - Live 0x0000000000000000
# vboxpci 23200 0 - Live 0x0000000000000000 (O)
# vboxnetadp 13382 0 - Live 0x0000000000000000 (O)
# vboxnetflt 23441 0 - Live 0x0000000000000000 (O)
# vboxdrv 287130 3 vboxpci,vboxnetadp,vboxnetflt, Live 0x0000000000000000 (O)

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_MODULE] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_SOURCE_LIST] = ""
            self.field[PFC.F_STATUS] = ""
            self.field[PFC.F_MODULE_CORE] = 0
            self.field[PFC.F_TAINTS] = ""

        else:
            self.field[PFC.F_MODULE] = sio.lineparts[0]
            self.field[PFC.F_SIZE] = long(sio.lineparts[1])
            self.field[PFC.F_REFCOUNT] = long(sio.lineparts[2])
            self.field[PFC.F_SOURCE_LIST] = sio.lineparts[3]
            self.field[PFC.F_STATUS] = sio.lineparts[4]
            self.field[PFC.F_MODULE_CORE] = long(sio.lineparts[5][2:], 16)
            if sio.linewords > 6:
                self.field[PFC.F_TAINTS] = sio.lineparts[6]
            else:
                self.field[PFC.F_TAINTS] = ""

        self.module = self.field[PFC.F_MODULE]
        self.size = self.field[PFC.F_SIZE]
        self.refcount = self.field[PFC.F_REFCOUNT]
        self.source_list = self.field[PFC.F_SOURCE_LIST]
        self.status = self.field[PFC.F_STATUS]
        self.module_core = self.field[PFC.F_MODULE_CORE]
        self.taints = self.field[PFC.F_TAINTS]

        return(self.module, self.size, self.refcount, self.source_list, self.status, self.module_core, self.taints)
#
RegisterProcFileHandler("/proc/modules", ProcRootMODULES)
RegisterPartialProcFileHandler("modules", ProcRootMODULES)


# ---
class ProcRootBUDDYINFO(PBR.fixed_delim_format_recs):
    """Pull records from /proc/buddyinfo"""
# source: mm/vmstat.c
#
#        seq_printf(m, "Node %d, zone %8s ", pgdat->node_id, zone->name);
#        for (order = 0; order < MAX_ORDER; ++order)
#                seq_printf(m, "%6lu ", zone->free_area[order].nr_free);
#        seq_putc(m, '\n');

    def extra_init(self, *opts):
        self.minfields = 15

        self.node = 0
        self.zone = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# Node 0, zone      DMA      1      0      1      0      1      1      1      0      1      1      3 
# Node 0, zone    DMA32  18435  13755   5520    786      7      1      0      1      0      0      0 
# Node 0, zone   Normal  36118   8165   6999    374      0      0      0      0      0      0      1 


        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_NODE] = 0
            self.field[PFC.F_ZONE] = ""
            self.field[PFC.F_FRBL_AREA_1] = 0
            self.field[PFC.F_FRBL_AREA_2] = 0
            self.field[PFC.F_FRBL_AREA_3] = 0
            self.field[PFC.F_FRBL_AREA_4] = 0
            self.field[PFC.F_FRBL_AREA_5] = 0
            self.field[PFC.F_FRBL_AREA_6] = 0
            self.field[PFC.F_FRBL_AREA_7] = 0
            self.field[PFC.F_FRBL_AREA_8] = 0
            self.field[PFC.F_FRBL_AREA_9] = 0
            self.field[PFC.F_FRBL_AREA_10] = 0
            self.field[PFC.F_FRBL_AREA_11] = 0

        else:
            self.field[PFC.F_NODE] = long(sio.lineparts[1][:-1])
            self.field[PFC.F_ZONE] = sio.lineparts[3]
            self.field[PFC.F_FRBL_AREA_1] = sio.lineparts[4]
            self.field[PFC.F_FRBL_AREA_2] = sio.lineparts[5]
            self.field[PFC.F_FRBL_AREA_3] = sio.lineparts[6]
            self.field[PFC.F_FRBL_AREA_4] = sio.lineparts[7]
            self.field[PFC.F_FRBL_AREA_5] = sio.lineparts[8]
            self.field[PFC.F_FRBL_AREA_6] = sio.lineparts[9]
            self.field[PFC.F_FRBL_AREA_7] = sio.lineparts[10]
            self.field[PFC.F_FRBL_AREA_8] = sio.lineparts[11]
            self.field[PFC.F_FRBL_AREA_9] = sio.lineparts[12]
            self.field[PFC.F_FRBL_AREA_10] = sio.lineparts[13]
            self.field[PFC.F_FRBL_AREA_11] = sio.lineparts[14]

        self.node = self.field[PFC.F_NODE]
        self.zone = self.field[PFC.F_ZONE]

        return(self.node, self.zone)
#
RegisterProcFileHandler("/proc/buddyinfo", ProcRootBUDDYINFO)
RegisterPartialProcFileHandler("buddyinfo", ProcRootBUDDYINFO)



# ---
class ProcRootSWAPS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/swaps"""
# source: mm/swapfile.c
#
#        if (si == SEQ_START_TOKEN) {
#                seq_puts(swap,"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
#                return 0;
#        }
#
#        file = si->swap_file;
#        len = seq_path(swap, &file->f_path, " \t\n\\");
#        seq_printf(swap, "%*s%s\t%u\t%u\t%d\n",
#                        len < 40 ? 40 - len : 1, " ",
#                        S_ISBLK(file->f_path.dentry->d_inode->i_mode) ?
#                                "partition" : "file\t",
#                        si->pages << (PAGE_SHIFT - 10),
#                        si->inuse_pages << (PAGE_SHIFT - 10),
#                        si->prio);
#

    def extra_init(self, *opts):
        self.minfields = 5
        self.skipped = "Filename"

        self.filename = ""
        self.type = ""
        self.size = 0
        self.used = 0
        self.priority = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# Filename				Type		Size	Used	Priority
# /dev/sda3                               partition	16777212	49700	-1
# /dev/sdb3                               partition	16777212	0	-2

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_FILENAME] = ""
            self.field[PFC.F_TYPE] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_USED] = 0
            self.field[PFC.F_PRIORITY] = 0

        else:
            self.field[PFC.F_FILENAME] = sio.lineparts[0]
            self.field[PFC.F_TYPE] = sio.lineparts[1]
            self.field[PFC.F_SIZE] = long(sio.lineparts[2])
            self.field[PFC.F_USED] = long(sio.lineparts[3])
            self.field[PFC.F_PRIORITY] = long(sio.lineparts[4])

        self.filename = self.field[PFC.F_FILENAME]
        self.type = self.field[PFC.F_TYPE]
        self.size = self.field[PFC.F_SIZE]
        self.used = self.field[PFC.F_USED]
        self.priority = self.field[PFC.F_PRIORITY]

        return(self.filename, self.type, self.size, self.used, self.priority)
#
RegisterProcFileHandler("/proc/swaps", ProcRootSWAPS)
RegisterPartialProcFileHandler("swaps", ProcRootSWAPS)



# ---
class ProcRootLOCKS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/locks"""
# source: fs/locks.c
#
#         seq_printf(f, "%lld:%s ", id, pfx);
#         if (IS_POSIX(fl)) {
#                 seq_printf(f, "%6s %s ",
#                              (fl->fl_flags & FL_ACCESS) ? "ACCESS" : "POSIX ",
#                              (inode == NULL) ? "*NOINODE*" :
#                              mandatory_lock(inode) ? "MANDATORY" : "ADVISORY ");
#         } else if (IS_FLOCK(fl)) {
#                 if (fl->fl_type & LOCK_MAND) {
#                         seq_printf(f, "FLOCK  MSNFS     ");
#                 } else {
#                         seq_printf(f, "FLOCK  ADVISORY  ");
#                 }
#         } else if (IS_LEASE(fl)) {
#                 seq_printf(f, "LEASE  ");
#                 if (lease_breaking(fl))
#                         seq_printf(f, "BREAKING  ");
#                 else if (fl->fl_file)
#                         seq_printf(f, "ACTIVE    ");
#                 else
#                         seq_printf(f, "BREAKER   ");
#         } else {
#                 seq_printf(f, "UNKNOWN UNKNOWN  ");
#         }
#         if (fl->fl_type & LOCK_MAND) {
#                 seq_printf(f, "%s ",
#                                (fl->fl_type & LOCK_READ)
#                                ? (fl->fl_type & LOCK_WRITE) ? "RW   " : "READ "
#                                : (fl->fl_type & LOCK_WRITE) ? "WRITE" : "NONE ");
#         } else {
#                 seq_printf(f, "%s ",
#                                (lease_breaking(fl))
#                                ? (fl->fl_type & F_UNLCK) ? "UNLCK" : "READ "
#                                : (fl->fl_type & F_WRLCK) ? "WRITE" : "READ ");
#         }
#         if (inode) {
# #ifdef WE_CAN_BREAK_LSLK_NOW
#                 seq_printf(f, "%d %s:%ld ", fl_pid,
#                                 inode->i_sb->s_id, inode->i_ino);
# #else
#                 /* userspace relies on this representation of dev_t ;-( */
#                 seq_printf(f, "%d %02x:%02x:%ld ", fl_pid,
#                                 MAJOR(inode->i_sb->s_dev),
#                                 MINOR(inode->i_sb->s_dev), inode->i_ino);
# #endif
#         } else {
#                 seq_printf(f, "%d <none>:0 ", fl_pid);
#         }
#         if (IS_POSIX(fl)) {
#                 if (fl->fl_end == OFFSET_MAX)
#                         seq_printf(f, "%Ld EOF\n", fl->fl_start);
#                 else
#                         seq_printf(f, "%Ld %Ld\n", fl->fl_start, fl->fl_end);
#         } else {
#                 seq_printf(f, "0 EOF\n");
#         }

    def extra_init(self, *opts):
        self.minfields = 8

        self.index = 0
        self.locktype = ""
        self.subtype = ""
        self.ioaction = ""
        self.pid = 0
        self.start = 0
        self.end = 0
        self.__SkipPrefix = "->"
        return

    def extra_next(self, sio):

# -- Sample records
#
# 6: POSIX  ADVISORY  READ  25090 09:01:121767769 1073741826 1073742335
# 7: POSIX  ADVISORY  READ  25090 09:01:121767788 128 128
# 8: POSIX  ADVISORY  READ  25090 09:01:121767851 1073741826 1073742335
# 9: POSIX  ADVISORY  WRITE 25090 09:01:121767662 0 EOF
# 10: POSIX  ADVISORY  READ  9743 09:01:125042780 128 128

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_LOCK_TYPE] = ""
            self.field[PFC.F_LOCK_SUBTYPE] = ""
            self.field[PFC.F_LOCK_IO] = ""
            self.field[PFC.F_PID] = 0
            self.field[PFC.F_LOCK_INODE] = ""
            self.field[PFC.F_START] = 0
            self.field[PFC.F_END_STRING] = ""
            self.field[PFC.F_END] = 0

        else:
            self.field[PFC.F_INDEX] = long(sio.lineparts[0][:-1])
            if sio.lineparts[1] != self.__SkipPrefix:
                __offset = 1
            else:
                __offset = 2
            self.field[PFC.F_LOCK_TYPE] = sio.lineparts[__offset]
            __offset = __offset + 1
            self.field[PFC.F_LOCK_SUBTYPE] = sio.lineparts[__offset]
            __offset = __offset + 1
            self.field[PFC.F_LOCK_IO] = sio.lineparts[__offset]
            __offset = __offset + 1
            self.field[PFC.F_PID] = long(sio.lineparts[__offset])
            __offset = __offset + 1
            self.field[PFC.F_LOCK_INODE] = sio.lineparts[__offset]
            __offset = __offset + 1
            self.field[PFC.F_START] = long(sio.lineparts[__offset])
            __offset = __offset + 1
            self.field[PFC.F_END_STRING] = sio.lineparts[__offset]
            if self.field[PFC.F_END_STRING] == "EOF":
                self.field[PFC.F_END] = numpy.inf
            else:
                self.field[PFC.F_END] = long(self.field[PFC.F_END_STRING])

        self.index = self.field[PFC.F_INDEX]
        self.locktype = self.field[PFC.F_LOCK_TYPE]
        self.subtype = self.field[PFC.F_LOCK_SUBTYPE]
        self.ioaction = self.field[PFC.F_LOCK_IO]
        self.pid = self.field[PFC.F_PID]
        self.start = self.field[PFC.F_START]
        self.end = self.field[PFC.F_END]

        return(self.index, self.locktype, self.subtype, self.ioaction, self.pid, self.start, self.end)
#
RegisterProcFileHandler("/proc/locks", ProcRootLOCKS)
RegisterPartialProcFileHandler("locks", ProcRootLOCKS)



# ---
class ProcRootDISKSTATS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/diskstats"""
# source: block/genhd.c
#
#     while ((hd = disk_part_iter_next(&piter))) {
#             cpu = part_stat_lock();
#             part_round_stats(cpu, hd);
#             part_stat_unlock();
#             seq_printf(seqf, "%4d %7d %s %lu %lu %lu "
#                        "%u %lu %lu %lu %u %u %u %u\n",
#                        MAJOR(part_devt(hd)), MINOR(part_devt(hd)),
#                        disk_name(gp, hd->partno, buf),
#                        part_stat_read(hd, ios[READ]),
#                        part_stat_read(hd, merges[READ]),
#                        part_stat_read(hd, sectors[READ]),
#                        jiffies_to_msecs(part_stat_read(hd, ticks[READ])),
#                        part_stat_read(hd, ios[WRITE]),
#                        part_stat_read(hd, merges[WRITE]),
#                        part_stat_read(hd, sectors[WRITE]),
#                        jiffies_to_msecs(part_stat_read(hd, ticks[WRITE])),
#                        part_in_flight(hd),
#                        jiffies_to_msecs(part_stat_read(hd, io_ticks)),
#                        jiffies_to_msecs(part_stat_read(hd, time_in_queue))
#                     );
#     }

    def extra_init(self, *opts):
        self.minfields = 14

        self.major_dev = 0
        self.minor_dev = 0
        self.disk_name = ""
        self.read_ios = 0
        self.read_merges = 0
        self.read_sectors = 0
        self.read_msecs = 0
        self.write_ios = 0
        self.write_merges = 0
        self.write_sectors = 0
        self.write_msecs = 0
        self.part_in_flight = 0
        self.msecs_io = 0
        self.msecs_queue_time = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# 7       6 loop6 0 0 0 0 0 0 0 0 0 0 0
# 7       7 loop7 0 0 0 0 0 0 0 0 0 0 0
# 8       0 sda 15235018 10980568 3312891398 74957548 8362788 4577595 144647677 114936764 0 90848652 189870564
# 8       1 sda1 398 1129 4568 1424 1 0 1 0 0 800 1424
# 8       2 sda2 15185612 10961911 3312352646 74838696 7650568 4513340 143561212 103557888 0 79839900 178373748

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_DISK_NAME] = ""
            self.field[PFC.F_READ_IOS] = 0
            self.field[PFC.F_READ_MERGES] = 0
            self.field[PFC.F_READ_SECTORS] = 0
            self.field[PFC.F_READ_MSECS] = 0
            self.field[PFC.F_WRITE_IOS] = 0
            self.field[PFC.F_WRITE_MERGES] = 0
            self.field[PFC.F_WRITE_SECTORS] = 0
            self.field[PFC.F_WRITE_MSECS] = 0
            self.field[PFC.F_PART_IN_FLIGHT] = 0
            self.field[PFC.F_IO_MSECS] = 0
            self.field[PFC.F_QUEUE_TIME_MSECS] = 0

        else:
            self.field[PFC.F_MAJOR_DEV] = long(sio.lineparts[0])
            self.field[PFC.F_MINOR_DEV] = long(sio.lineparts[1])
            self.field[PFC.F_DISK_NAME] = sio.lineparts[2]
            self.field[PFC.F_READ_IOS] = long(sio.lineparts[3])
            self.field[PFC.F_READ_MERGES] = long(sio.lineparts[4])
            self.field[PFC.F_READ_SECTORS] = long(sio.lineparts[5])
            self.field[PFC.F_READ_MSECS] = long(sio.lineparts[6])
            self.field[PFC.F_WRITE_IOS] = long(sio.lineparts[7])
            self.field[PFC.F_WRITE_MERGES] = long(sio.lineparts[8])
            self.field[PFC.F_WRITE_SECTORS] = long(sio.lineparts[9])
            self.field[PFC.F_WRITE_MSECS] = long(sio.lineparts[10])
            self.field[PFC.F_PART_IN_FLIGHT] = long(sio.lineparts[11])
            self.field[PFC.F_IO_MSECS] = long(sio.lineparts[12])
            self.field[PFC.F_QUEUE_TIME_MSECS] = long(sio.lineparts[13])

        self.major_dev = self.field[PFC.F_MAJOR_DEV]
        self.minor_dev = self.field[PFC.F_MINOR_DEV]
        self.disk_name = self.field[PFC.F_DISK_NAME]
        self.read_ios = self.field[PFC.F_READ_IOS]
        self.read_merges = self.field[PFC.F_READ_MERGES]
        self.read_sectors = self.field[PFC.F_READ_SECTORS]
        self.read_msecs = self.field[PFC.F_READ_MSECS]
        self.write_ios = self.field[PFC.F_WRITE_IOS]
        self.write_merges = self.field[PFC.F_WRITE_MERGES]
        self.write_sectors = self.field[PFC.F_WRITE_SECTORS]
        self.write_msecs = self.field[PFC.F_WRITE_MSECS]
        self.part_in_flight = self.field[PFC.F_PART_IN_FLIGHT]
        self.io_msecs = self.field[PFC.F_IO_MSECS]
        self.queue_time_msecs = self.field[PFC.F_QUEUE_TIME_MSECS]

        return(self.major_dev, self.minor_dev, self.disk_name, self.read_ios, self.read_merges,
          self.read_sectors, self.read_msecs, self.write_ios, self.write_merges, self.write_sectors,
          self.write_msecs, self.part_in_flight, self.io_msecs, self.queue_time_msecs)

#
RegisterProcFileHandler("/proc/diskstats", ProcRootDISKSTATS)
RegisterPartialProcFileHandler("diskstats", ProcRootDISKSTATS)



# ---
class ProcRootVMSTAT(PBR.fixed_delim_format_recs):
    """Pull records from /proc/vmstat"""
# source: mm/vmstat.c
#
#        unsigned long off = l - (unsigned long *)m->private;
#
#        seq_printf(m, "%s %lu\n", vmstat_text[off], *l);

    def extra_init(self, *opts):
        self.minfields = 2

        self.category = ""
        self.cat_count = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# nr_free_pages 127192
# nr_inactive_anon 68591
# nr_active_anon 763003
# nr_inactive_file 4514318

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_CATEGORY] = ""
            self.field[PFC.F_COUNT] = 0

        else:
            self.field[PFC.F_CATEGORY] = sio.lineparts[0]
            self.field[PFC.F_COUNT] = long(sio.lineparts[1])

        self.category = self.field[PFC.F_CATEGORY]
        self.cat_count = self.field[PFC.F_COUNT]

        return(self.category, self.cat_count)

#
RegisterProcFileHandler("/proc/vmstat", ProcRootVMSTAT)
RegisterPartialProcFileHandler("vmstat", ProcRootVMSTAT)



# ---
class ProcRootMEMINFO(PBR.fixed_delim_format_recs):
    """Pull records from /proc/meminfo"""
# source: fs/proc/meminfo.c
# --and--
# source: mm/hugetlb.c
# --and--
# source: arch/x86/mm/pageattr.c
#
# from: fs/proc/meminfo.c
# ---
# 	seq_printf(m,
# 		"MemTotal:       %8lu kB\n"
# 		"MemFree:        %8lu kB\n"
# 		"Buffers:        %8lu kB\n"
# 		"Cached:         %8lu kB\n"
# 		"SwapCached:     %8lu kB\n"
# 		"Active:         %8lu kB\n"
# 		"Inactive:       %8lu kB\n"
# 		"Active(anon):   %8lu kB\n"
# 		"Inactive(anon): %8lu kB\n"
# 		"Active(file):   %8lu kB\n"
# 		"Inactive(file): %8lu kB\n"
# 		"Unevictable:    %8lu kB\n"
# 		"Mlocked:        %8lu kB\n"
# #ifdef CONFIG_HIGHMEM
# 		"HighTotal:      %8lu kB\n"
# 		"HighFree:       %8lu kB\n"
# 		"LowTotal:       %8lu kB\n"
# 		"LowFree:        %8lu kB\n"
# #endif
# #ifndef CONFIG_MMU
# 		"MmapCopy:       %8lu kB\n"
# #endif
# 		"SwapTotal:      %8lu kB\n"
# 		"SwapFree:       %8lu kB\n"
# 		"Dirty:          %8lu kB\n"
# 		"Writeback:      %8lu kB\n"
# 		"AnonPages:      %8lu kB\n"
# 		"Mapped:         %8lu kB\n"
# 		"Shmem:          %8lu kB\n"
# 		"Slab:           %8lu kB\n"
# 		"SReclaimable:   %8lu kB\n"
# 		"SUnreclaim:     %8lu kB\n"
# 		"KernelStack:    %8lu kB\n"
# 		"PageTables:     %8lu kB\n"
# #ifdef CONFIG_QUICKLIST
# 		"Quicklists:     %8lu kB\n"
# #endif
# 		"NFS_Unstable:   %8lu kB\n"
# 		"Bounce:         %8lu kB\n"
# 		"WritebackTmp:   %8lu kB\n"
# 		"CommitLimit:    %8lu kB\n"
# 		"Committed_AS:   %8lu kB\n"
# 		"VmallocTotal:   %8lu kB\n"
# 		"VmallocUsed:    %8lu kB\n"
# 		"VmallocChunk:   %8lu kB\n"
# #ifdef CONFIG_MEMORY_FAILURE
# 		"HardwareCorrupted: %5lu kB\n"
# #endif
# #ifdef CONFIG_TRANSPARENT_HUGEPAGE
# 		"AnonHugePages:  %8lu kB\n"
# #endif
# 		,
# 		K(i.totalram),
# 		K(i.freeram),
# 		K(i.bufferram),
# 		K(cached),
# 		K(total_swapcache_pages),
# 		K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]),
# 		K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]),
# 		K(pages[LRU_ACTIVE_ANON]),
# 		K(pages[LRU_INACTIVE_ANON]),
# 		K(pages[LRU_ACTIVE_FILE]),
# 		K(pages[LRU_INACTIVE_FILE]),
# 		K(pages[LRU_UNEVICTABLE]),
# 		K(global_page_state(NR_MLOCK)),
# #ifdef CONFIG_HIGHMEM
# 		K(i.totalhigh),
# 		K(i.freehigh),
# 		K(i.totalram-i.totalhigh),
# 		K(i.freeram-i.freehigh),
# #endif
# #ifndef CONFIG_MMU
# 		K((unsigned long) atomic_long_read(&mmap_pages_allocated)),
# #endif
# 		K(i.totalswap),
# 		K(i.freeswap),
# 		K(global_page_state(NR_FILE_DIRTY)),
# 		K(global_page_state(NR_WRITEBACK)),
# #ifdef CONFIG_TRANSPARENT_HUGEPAGE
# 		K(global_page_state(NR_ANON_PAGES)
# 		  + global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
# 		  HPAGE_PMD_NR),
# #else
# 		K(global_page_state(NR_ANON_PAGES)),
# #endif
# 		K(global_page_state(NR_FILE_MAPPED)),
# 		K(global_page_state(NR_SHMEM)),
# 		K(global_page_state(NR_SLAB_RECLAIMABLE) +
# 				global_page_state(NR_SLAB_UNRECLAIMABLE)),
# 		K(global_page_state(NR_SLAB_RECLAIMABLE)),
# 		K(global_page_state(NR_SLAB_UNRECLAIMABLE)),
# 		global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024,
# 		K(global_page_state(NR_PAGETABLE)),
# #ifdef CONFIG_QUICKLIST
# 		K(quicklist_total_size()),
# #endif
# 		K(global_page_state(NR_UNSTABLE_NFS)),
# 		K(global_page_state(NR_BOUNCE)),
# 		K(global_page_state(NR_WRITEBACK_TEMP)),
# 		K(allowed),
# 		K(committed),
# 		(unsigned long)VMALLOC_TOTAL >> 10,
# 		vmi.used >> 10,
# 		vmi.largest_chunk >> 10
# #ifdef CONFIG_MEMORY_FAILURE
# 		,atomic_long_read(&mce_bad_pages) << (PAGE_SHIFT - 10)
# #endif
# #ifdef CONFIG_TRANSPARENT_HUGEPAGE
# 		,K(global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
# 		   HPAGE_PMD_NR)
# #endif
# 		);
# 
# 	hugetlb_report_meminfo(m);
# 
# 	arch_report_meminfo(m);
#
# from: mm/hugetlb.c
# ---
#        seq_printf(m,
#                        "HugePages_Total:   %5lu\n"
#                        "HugePages_Free:    %5lu\n"
#                        "HugePages_Rsvd:    %5lu\n"
#                        "HugePages_Surp:    %5lu\n"
#                        "Hugepagesize:   %8lu kB\n",
#                        h->nr_huge_pages,
#                        h->free_huge_pages,
#                        h->resv_huge_pages,
#                        h->surplus_huge_pages,
#                        1UL << (huge_page_order(h) + PAGE_SHIFT - 10));
#
#
# from: arch/x86/mm/pageattr.c
# ---
#         seq_printf(m, "DirectMap4k:    %8lu kB\n",
#                         direct_pages_count[PG_LEVEL_4K] << 2);
# #if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#         seq_printf(m, "DirectMap2M:    %8lu kB\n",
#                         direct_pages_count[PG_LEVEL_2M] << 11);
# #else
#         seq_printf(m, "DirectMap4M:    %8lu kB\n",
#                         direct_pages_count[PG_LEVEL_2M] << 12);
# #endif
# #ifdef CONFIG_X86_64
#         if (direct_gbpages)
#                 seq_printf(m, "DirectMap1G:    %8lu kB\n",
#                         direct_pages_count[PG_LEVEL_1G] << 20);
# #endif

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Filename"

        self.category = ""
        self.size = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# Committed_AS:    7228044 kB
# VmallocTotal:   34359738367 kB
# VmallocUsed:      626600 kB
# VmallocChunk:   34359103472 kB
# HardwareCorrupted:     0 kB
# AnonHugePages:         0 kB
# HugePages_Total:       0
# HugePages_Free:        0

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_CATEGORY] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_UNITS] = ""

        else:
            self.field[PFC.F_CATEGORY] = sio.lineparts[0]
            self.field[PFC.F_SIZE] = long(sio.lineparts[1])
            if sio.linewords >= 3:
                self.field[PFC.F_UNITS] = sio.lineparts[2]
            else:
                self.field[PFC.F_UNITS] = ""

        self.category = self.field[PFC.F_CATEGORY]
        self.size = self.field[PFC.F_SIZE]

        return(self.category, self.size)

#
RegisterProcFileHandler("/proc/meminfo", ProcRootMEMINFO)
RegisterPartialProcFileHandler("meminfo", ProcRootMEMINFO)



# ---
class ProcRootPARTITIONS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/partitions"""
# source: block/genhd.c
#
#     /* show the full disk and all non-0 size partitions of it */
#     disk_part_iter_init(&piter, sgp, DISK_PITER_INCL_PART0);
#     while ((part = disk_part_iter_next(&piter)))
#             seq_printf(seqf, "%4d  %7d %10llu %s\n",
#                        MAJOR(part_devt(part)), MINOR(part_devt(part)),
#                        (unsigned long long)part->nr_sects >> 1,
#                        disk_name(sgp, part->partno, buf));

    def extra_init(self, *opts):
        self.minfields = 4
        self.skipped = "major"

        self.major_dev = 0
        self.minor_dev = 0
        self.blocks = ""
        self.part_name = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# major minor  #blocks  name
# 
#    8        0 1953514584 sda
#    8        1     102400 sda1
#    8        2 1610612736 sda2

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_BLOCKS] = 0
            self.field[PFC.F_PARTITION_NAME] = ""

        else:
            self.field[PFC.F_MAJOR_DEV] = long(sio.lineparts[0])
            self.field[PFC.F_MINOR_DEV] = long(sio.lineparts[1])
            self.field[PFC.F_BLOCKS] = long(sio.lineparts[2])
            self.field[PFC.F_PARTITION_NAME] = sio.lineparts[3]

        self.major_dev = self.field[PFC.F_MAJOR_DEV]
        self.minor_dev = self.field[PFC.F_MINOR_DEV]
        self.blocks = self.field[PFC.F_BLOCKS]
        self.part_name = self.field[PFC.F_PARTITION_NAME]

        return(self.major_dev, self.minor_dev, self.blocks, self.part_name)

#
RegisterProcFileHandler("/proc/partitions", ProcRootPARTITIONS)
RegisterPartialProcFileHandler("partitions", ProcRootPARTITIONS)
