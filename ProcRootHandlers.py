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



# ---
class ProcRootMISC(PBR.fixed_delim_format_recs):
    """Pull records from /proc/misc"""
# source: drivers/char/misc.c
#
#    const struct miscdevice *p = list_entry(v, struct miscdevice, list);
#
#    seq_printf(seq, "%3i %s\n", p->minor, p->name ? p->name : "");


    def extra_init(self, *opts):
        self.minfields = 2

        self.minor_dev = 0
        self.device = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
#  56 vboxnetctl
#  57 vboxdrv
#  58 network_throughput
#  59 network_latency
#  60 cpu_dma_latency
# 236 device-mapper

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_DEVICE] = ""

        else:
            self.field[PFC.F_MINOR_DEV] = long(sio.lineparts[0])
            self.field[PFC.F_DEVICE] = sio.lineparts[1]

        self.minor_dev = self.field[PFC.F_MINOR_DEV]
        self.device = self.field[PFC.F_DEVICE]

        return(self.minor_dev, self.device)

#
RegisterProcFileHandler("/proc/misc", ProcRootMISC)
RegisterPartialProcFileHandler("misc", ProcRootMISC)



# ---
class ProcRootKALLSYMS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/kallsyms"""
# source: kernel/kallsyms.c
#
#        if (iter->module_name[0]) {
#                char type;
#
#                /*
#                 * Label it "global" if it is exported,
#                 * "local" if not exported.
#                 */
#                type = iter->exported ? toupper(iter->type) :
#                                        tolower(iter->type);
#                seq_printf(m, "%pK %c %s\t[%s]\n", (void *)iter->value,
#                           type, iter->name, iter->module_name);
#        } else
#                seq_printf(m, "%pK %c %s\n", (void *)iter->value,
#                           iter->type, iter->name);

    def extra_init(self, *opts):
        self.minfields = 3

        self.address = 0
        self.type = ""
        self.symbol = ""
        self.module = ""
        return

    def extra_next(self, sio):

# -- Sample records (the first field is all '0's when run from a non-root user)
#
# ffffffff8204b000 b .brk.m2p_overrides
# ffffffff8204f000 b .brk.dmi_alloc
# ffffffff8205f000 B __brk_limit
# ffffffffa0382000 t pci_stub_probe       [pci_stub]
# ffffffffa0384000 d stub_driver  [pci_stub]
# ffffffffa038202c t pci_stub_exit        [pci_stub]


        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_ADDRESS] = 0
            self.field[PFC.F_TYPE] = ""
            self.field[PFC.F_SYMBOL] = ""
            self.field[PFC.F_MODULE] = ""

        else:
            self.field[PFC.F_ADDRESS] = long(sio.lineparts[0], 16)
            self.field[PFC.F_TYPE] = sio.lineparts[1]
            self.field[PFC.F_SYMBOL] = sio.lineparts[2]
            if sio.linewords >= 4:
                self.field[PFC.F_MODULE] = sio.lineparts[3][1:-1]
            else:
                self.field[PFC.F_MODULE] = ""

        self.address = self.field[PFC.F_ADDRESS]
        self.type = self.field[PFC.F_TYPE]
        self.symbol = self.field[PFC.F_SYMBOL]
        self.module = self.field[PFC.F_MODULE]

        return(self.address, self.type, self.symbol, self.module)

#
RegisterProcFileHandler("/proc/kallsyms", ProcRootKALLSYMS)
RegisterPartialProcFileHandler("kallsyms", ProcRootKALLSYMS)



# ---
class ProcRootFILESYSTEMS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/filesystems"""
# source: fs/filesystems.c
#
#        while (tmp) {
#                seq_printf(m, "%s\t%s\n",
#                        (tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
#                        tmp->name);
#                tmp = tmp->next;
#        }

    def extra_init(self, *opts):
        self.minfields = 1

        self.dev_flag = ""
        self.filesystem = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# nodev	pipefs
# nodev	anon_inodefs
# nodev	devpts
# 	ext3
# 	ext4
# nodev	ramfs

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_DEV_FLAG] = ""
            self.field[PFC.F_FILESYSTEM] = ""

        else:
            if sio.linewords >= 2:
                self.field[PFC.F_DEV_FLAG] = sio.lineparts[0]
                self.field[PFC.F_FILESYSTEM] = sio.lineparts[1]
            else:
                self.field[PFC.F_DEV_FLAG] = ""
                self.field[PFC.F_FILESYSTEM] = sio.lineparts[0]

        self.dev_flag = self.field[PFC.F_DEV_FLAG]
        self.filesystem = self.field[PFC.F_FILESYSTEM]

        return(self.dev_flag, self.filesystem)

#
RegisterProcFileHandler("/proc/filesystems", ProcRootFILESYSTEMS)
RegisterPartialProcFileHandler("filesystems", ProcRootFILESYSTEMS)



# ---
class ProcRootDMA(PBR.fixed_delim_format_recs):
    """Pull records from /proc/DMA"""
# source: kernel/dma.c
#
# #ifdef MAX_DMA_CHANNELS
# static int proc_dma_show(struct seq_file *m, void *v)
# {
#         int i;
# 
#         for (i = 0 ; i < MAX_DMA_CHANNELS ; i++) {
#                 if (dma_chan_busy[i].lock) {
#                         seq_printf(m, "%2d: %s\n", i,
#                                    dma_chan_busy[i].device_id);
#                 }
#         }
#         return 0;
# }
# #else
# static int proc_dma_show(struct seq_file *m, void *v)
# {
#         seq_puts(m, "No DMA\n");
#         return 0;
# }
# #endif /* MAX_DMA_CHANNELS */

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "No"

        self.channel = 0
        self.device = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 4: cascade

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_CHANNEL] = 0
            self.field[PFC.F_DEVICE_NAME] = ""

        else:
            self.field[PFC.F_CHANNEL] = long(sio.lineparts[0][:-1])
            self.field[PFC.F_DEVICE_NAME] = sio.lineparts[1]

        self.channel = self.field[PFC.F_CHANNEL]
        self.device = self.field[PFC.F_DEVICE_NAME]

        return(self.channel, self.device)

#
RegisterProcFileHandler("/proc/dma", ProcRootDMA)
RegisterPartialProcFileHandler("dma", ProcRootDMA)



# ---
class ProcRootFB(PBR.fixed_delim_format_recs):
    """Pull records from /proc/fb"""
# source: 
#
#        struct fb_info *fi = registered_fb[i];
#
#        if (fi)
#                seq_printf(m, "%d %s\n", fi->node, fi->fix.id);

    def extra_init(self, *opts):
        self.minfields = 2

        self.node = 0
        self.id = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 0 EFI VGA

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_NODE] = 0
            self.field[PFC.F_ID_LIST] = ""

        else:
            self.field[PFC.F_NODE] = long(sio.lineparts[0])
            self.field[PFC.F_ID_LIST] = " ".join(sio.lineparts[1:])

        self.node = self.field[PFC.F_NODE]
        self.id = self.field[PFC.F_ID_LIST]

        return(self.node, self.id)

#
RegisterProcFileHandler("/proc/fb", ProcRootFB)
RegisterPartialProcFileHandler("fb", ProcRootFB)



# ---
class ProcRootCONSOLES(PBR.fixed_delim_format_recs):
    """Pull records from /proc/consoles"""
# source: fs/proc/consoles.c
#
#        seq_printf(m, "%s%d%n", con->name, con->index, &len);
#        len = 21 - len;
#        if (len < 1)
#                len = 1;
#        seq_printf(m, "%*c%c%c%c (%s)", len, ' ', con->read ? 'R' : '-',
#                        con->write ? 'W' : '-', con->unblank ? 'U' : '-',
#                        flags);
#        if (dev)
#                seq_printf(m, " %4d:%d", MAJOR(dev), MINOR(dev));
#
#        seq_printf(m, "\n");

    def extra_init(self, *opts):
        self.minfields = 4

        self.device_name = ""
        self.io_type = ""
        self.flags = ""
        self.device_num = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# tty0                 -WU (EC p  )    4:7

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_DEVICE_NAME] = ""
            self.field[PFC.F_IO_TYPE] = ""
            self.field[PFC.F_FLAGS] = ""
            self.field[PFC.F_DEVICE_NUMBER] = ""

        else:
            self.field[PFC.F_DEVICE_NAME] = sio.lineparts[0]
            self.field[PFC.F_IO_TYPE] = sio.lineparts[1]
            __subrec = " ".join(sio.lineparts[2:-1])
            if __subrec[:1] == "(":
                __subrec = __subrec[1:]
            if __subrec[-1:] == ")":
                __subrec = __subrec[:-1]
            if __subrec[-1:] == " ":
                __subrec = __subrec[:-1]
            self.field[PFC.F_FLAGS] = __subrec
            self.field[PFC.F_DEVICE_NUMBER] = sio.lineparts[-1]

        self.device_name = self.field[PFC.F_DEVICE_NAME]
        self.io_type = self.field[PFC.F_IO_TYPE]
        self.flags = self.field[PFC.F_FLAGS]
        self.device_num = self.field[PFC.F_DEVICE_NUMBER]

        return(self.device_name, self.io_type, self.flags, self.device_num)

#
RegisterProcFileHandler("/proc/consoles", ProcRootCONSOLES)
RegisterPartialProcFileHandler("consoles", ProcRootCONSOLES)



# ---
class ProcRootKEY_USERS(PBR.fixed_delim_format_recs):
    """Pull records from /proc/key-users"""
# source: security/keys/proc.c
#
#        seq_printf(m, "%5u: %5d %d/%d %d/%d %d/%d\n",
#                   user->uid,
#                   atomic_read(&user->usage),
#                   atomic_read(&user->nkeys),
#                   atomic_read(&user->nikeys),
#                   user->qnkeys,
#                   maxkeys,
#                   user->qnbytes,
#                   maxbytes);

    def extra_init(self, *opts):
        self.minfields = 5
        self.__FieldSplitDelim = "/"

        self.uid = 0
        self.usage = 0
        self.nkeys = 0
        self.nikeys = 0
        self.qnkeys = 0
        self.maxkeys = 0
        self.qnbytes = 0
        self.maxbytes = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
#     0:     4 3/3 0/200 0/20000

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_UID] = 0
            self.field[PFC.F_USAGE] = 0
            self.field[PFC.F_NKEYS] = 0
            self.field[PFC.F_NIKEYS] = 0
            self.field[PFC.F_QNKEYS] = 0
            self.field[PFC.F_MAXKEYS] = 0
            self.field[PFC.F_QNBYTES] = 0
            self.field[PFC.F_MAXBYTES] = 0

        else:
            self.field[PFC.F_UID] = long(sio.lineparts[0][:-1])
            self.field[PFC.F_USAGE] = long(sio.lineparts[1])
            __split = sio.lineparts[2].partition(self.__FieldSplitDelim)
            self.field[PFC.F_NKEYS] = long(__split[0])
            self.field[PFC.F_NIKEYS] = long(__split[2])
            __split = sio.lineparts[3].partition(self.__FieldSplitDelim)
            self.field[PFC.F_QNKEYS] = long(__split[0])
            self.field[PFC.F_MAXKEYS] = long(__split[2])
            __split = sio.lineparts[4].partition(self.__FieldSplitDelim)
            self.field[PFC.F_QNBYTES] = long(__split[0])
            self.field[PFC.F_MAXBYTES] = long(__split[2])

        self.uid = self.field[PFC.F_UID]
        self.usage = self.field[PFC.F_USAGE]
        self.nkeys = self.field[PFC.F_NKEYS]
        self.nikeys = self.field[PFC.F_NIKEYS]
        self.qnkeys = self.field[PFC.F_QNKEYS]
        self.maxkeys = self.field[PFC.F_MAXKEYS]
        self.qnbytes = self.field[PFC.F_QNBYTES]
        self.maxbytes = self.field[PFC.F_MAXBYTES]

        return(self.uid, self.usage, self.nkeys, self.nikeys, self.qnkeys, self.maxkeys, self.qnbytes, self.maxbytes)

#
RegisterProcFileHandler("/proc/key-users", ProcRootKEY_USERS)
RegisterPartialProcFileHandler("key-users", ProcRootKEY_USERS)



# ---
class ProcRootVERSION_SIGNATURE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/version_signature"""
# source: 
#
#         seq_printf(m, "%s\n", CONFIG_VERSION_SIGNATURE);

    def extra_init(self, *opts):
        self.minfields = 1

        self.version = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# Ubuntu 3.2.0-24.39-generic 3.2.16

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_VERSION_STRING] = ""

        else:
            self.field[PFC.F_VERSION_STRING] = " ".join(sio.lineparts)

        self.version = self.field[PFC.F_VERSION_STRING]

        return(self.version)

#
RegisterProcFileHandler("/proc/version_signature", ProcRootVERSION_SIGNATURE)
RegisterPartialProcFileHandler("version_signature", ProcRootVERSION_SIGNATURE)



# ---
class ProcRootVERSION(PBR.fixed_delim_format_recs):
    """Pull records from /proc/version"""
# source: fs/proc/version.c
#
#        seq_printf(m, linux_proc_banner,
#                utsname()->sysname,
#                utsname()->release,
#                utsname()->version);

    def extra_init(self, *opts):
        self.minfields = 3
        self.__FixedBannerPrefix = "Linux"
        self.__FieldDelim = ") "

        self.full_string = ""
        self.sysname = ""
        self.release = ""
        self.version = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# Linux version 3.2.0-24-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #39-Ubuntu SMP Mon May 21 16:52:17 UTC 2012

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_VERSION_STRING] = ""
            self.field[PFC.F_SYSNAME] = ""
            self.field[PFC.F_RELEASE] = ""
            self.field[PFC.F_VERSION] = ""

        else:
            self.field[PFC.F_VERSION_STRING] = " ".join(sio.lineparts)
            if sio.linewords < 6 or sio.lineparts[0] != self.__FixedBannerPrefix:
                self.field[PFC.F_SYSNAME] = ""
                self.field[PFC.F_RELEASE] = ""
                self.field[PFC.F_VERSION] = ""
            else:
                self.field[PFC.F_SYSNAME] = sio.lineparts[0]
                self.field[PFC.F_RELEASE] = sio.lineparts[2]
                __split = " ".join(sio.lineparts).split(self.__FieldDelim)
                self.field[PFC.F_VERSION] = __split[-1:][0]

        self.full_string = self.field[PFC.F_VERSION_STRING]
        self.sysname = self.field[PFC.F_SYSNAME]
        self.release = self.field[PFC.F_RELEASE]
        self.version = self.field[PFC.F_VERSION]

        return(self.sysname, self.release, self.version, self.full_string)
#
RegisterProcFileHandler("/proc/version", ProcRootVERSION)
RegisterPartialProcFileHandler("version", ProcRootVERSION)



# ---
class ProcRootUPTIME(PBR.fixed_delim_format_recs):
    """Pull records from /proc/uptime"""
# source: fs/proc/uptime.c
#
#        do_posix_clock_monotonic_gettime(&uptime);
#        monotonic_to_bootbased(&uptime);
#        nsec = cputime64_to_jiffies64(idletime) * TICK_NSEC;
#        idle.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
#        idle.tv_nsec = rem;
#        seq_printf(m, "%lu.%02lu %lu.%02lu\n",
#                        (unsigned long) uptime.tv_sec,
#                        (uptime.tv_nsec / (NSEC_PER_SEC / 100)),
#                        (unsigned long) idle.tv_sec,
#                        (idle.tv_nsec / (NSEC_PER_SEC / 100)));

    def extra_init(self, *opts):
        self.minfields = 2

        self.uptime = 0.0
        self.idle = 0.0
        return

    def extra_next(self, sio):

# -- Sample records
#
# 3815061.73 30116159.34

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_UPTIME] = 0.0
            self.field[PFC.F_IDLE] = 0.0

        else:
            self.field[PFC.F_UPTIME] = float(sio.lineparts[0])
            self.field[PFC.F_IDLE] = float(sio.lineparts[1])

        self.uptime = self.field[PFC.F_UPTIME]
        self.idle = self.field[PFC.F_IDLE]

        return(self.uptime, self.idle)
#
RegisterProcFileHandler("/proc/uptime", ProcRootUPTIME)
RegisterPartialProcFileHandler("uptime", ProcRootUPTIME)



# ---
class ProcRootLOADAVG(PBR.fixed_delim_format_recs):
    """Pull records from /proc/loadavg"""
# source: fs/proc/loadavg.c
#
#        seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %ld/%d %d\n",
#                LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
#                LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
#                LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
#                nr_running(), nr_threads,
#                task_active_pid_ns(current)->last_pid);

    def extra_init(self, *opts):
        self.minfields = 5
        self.__FieldDelim = "/"

        self.load0 = 0.0
        self.load1 = 0.0
        self.load2 = 0.0
        self.running = 0
        self.threads = 0
        self.lastpid = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# 0.11 0.25 0.26 1/595 14644

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_LOAD_AV0] = 0.0
            self.field[PFC.F_LOAD_AV1] = 0.0
            self.field[PFC.F_LOAD_AV2] = 0.0
            self.field[PFC.F_NUM_TASKS] = 0
            self.field[PFC.F_NUM_THREADS] = 0
            self.field[PFC.F_LAST_PID] = 0

        else:
            self.field[PFC.F_LOAD_AV0] = float(sio.lineparts[0])
            self.field[PFC.F_LOAD_AV1] = float(sio.lineparts[1])
            self.field[PFC.F_LOAD_AV2] = float(sio.lineparts[2])
            __split = sio.lineparts[3].partition(self.__FieldDelim)
            self.field[PFC.F_NUM_TASKS] = long(__split[0])
            self.field[PFC.F_NUM_THREADS] = long(__split[2])
            self.field[PFC.F_LAST_PID] = long(sio.lineparts[4])

        self.load0 = self.field[PFC.F_LOAD_AV0]
        self.load1 = self.field[PFC.F_LOAD_AV1]
        self.load2 = self.field[PFC.F_LOAD_AV2]
        self.running = self.field[PFC.F_NUM_TASKS]
        self.threads = self.field[PFC.F_NUM_THREADS]
        self.lastpid = self.field[PFC.F_LAST_PID]

        return(self.load0, self.load1, self.load2, self.running, self.threads, self.lastpid)
#
RegisterProcFileHandler("/proc/loadavg", ProcRootLOADAVG)
RegisterPartialProcFileHandler("loadavg", ProcRootLOADAVG)



# ---
class ProcRootCMDLINE(PBR.fixed_delim_format_recs):
    """Pull records from /proc/cmdline"""
# source: fs/proc/cmdline.c
#
#         seq_printf(m, "%s\n", saved_command_line);

    def extra_init(self, *opts):
        self.minfields = 1

        self.cmdline = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# BOOT_IMAGE=/vmlinuz-3.2.0-24-generic root=UUID=a959862a-84b7-4373-b7d6-954ac9005249 ro quiet splash vt.handoff=7

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_CMDLINE] = ""

        else:
            self.field[PFC.F_CMDLINE] = " ".join(sio.lineparts)

        self.cmdline = self.field[PFC.F_CMDLINE]

        return(self.cmdline)
#
RegisterProcFileHandler("/proc/cmdline", ProcRootCMDLINE)
RegisterPartialProcFileHandler("cmdline", ProcRootCMDLINE)



# ---
class ProcRootSLABINFO(PBR.fixed_delim_format_recs):
    """Pull records from /proc/slabinfo"""
# source: mm/slub.c
# --and--
# source: mm/slab.c
#
# This one is tricky...  There's kernel code that appears to create and write
# "/proc/slabinfo" in two places.  Both "slub.c" and "slab.c" contain lines that
# would write out info to that file.  I'm including code snippets from both and
# making sure this routine can handle output generated by either.
#
# from:
# ---
# source: mm/slub.c
#        seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d", s->name, nr_inuse,
#                   nr_objs, s->size, oo_objects(s->oo),
#                   (1 << oo_order(s->oo)));
#        seq_printf(m, " : tunables %4u %4u %4u", 0, 0, 0);
#        seq_printf(m, " : slabdata %6lu %6lu %6lu", nr_slabs, nr_slabs,
#                   0UL);
#        seq_putc(m, '\n');
#
# from:
# ---
# source: mm/slab.c
#
# ...header routine...
# #if STATS
#         seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
# #else
#         seq_puts(m, "slabinfo - version: 2.1\n");
# #endif
#         seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
#                  "<objperslab> <pagesperslab>");
#         seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
#         seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
# #if STATS
#         seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
#                  "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
#         seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
# #endif
#         seq_putc(m, '\n');
#
# ...data entries...
# 	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
# 		   name, active_objs, num_objs, cachep->buffer_size,
# 		   cachep->num, (1 << cachep->gfporder));
# 	seq_printf(m, " : tunables %4u %4u %4u",
# 		   cachep->limit, cachep->batchcount, cachep->shared);
# 	seq_printf(m, " : slabdata %6lu %6lu %6lu",
# 		   active_slabs, num_slabs, shared_avail);
# #if STATS
# 	{			/* list3 stats */
# 		unsigned long high = cachep->high_mark;
# 		unsigned long allocs = cachep->num_allocations;
# 		unsigned long grown = cachep->grown;
# 		unsigned long reaped = cachep->reaped;
# 		unsigned long errors = cachep->errors;
# 		unsigned long max_freeable = cachep->max_freeable;
# 		unsigned long node_allocs = cachep->node_allocs;
# 		unsigned long node_frees = cachep->node_frees;
# 		unsigned long overflows = cachep->node_overflow;
# 
# 		seq_printf(m, " : globalstat %7lu %6lu %5lu %4lu "
# 			   "%4lu %4lu %4lu %4lu %4lu",
# 			   allocs, high, grown,
# 			   reaped, errors, max_freeable, node_allocs,
# 			   node_frees, overflows);
# 	}
# 	/* cpu stats */
# 	{
# 		unsigned long allochit = atomic_read(&cachep->allochit);
# 		unsigned long allocmiss = atomic_read(&cachep->allocmiss);
# 		unsigned long freehit = atomic_read(&cachep->freehit);
# 		unsigned long freemiss = atomic_read(&cachep->freemiss);
# 
# 		seq_printf(m, " : cpustat %6lu %6lu %6lu %6lu",
# 			   allochit, allocmiss, freehit, freemiss);
# 	}
# #endif
# 	seq_putc(m, '\n');

    def extra_init(self, *opts):
        self.minfields = 16
        self.skipped = "#"
        self.__ExtendedRec = 33

        self.slab = ""
        self.act_objs = 0
        self.num_objs = 0
        self.obj_size = 0
        self.obj_per_slab = 0
        self.pages_per_slab = 0
        self.limit = 0
        self.batchcount = 0
        self.shared = 0
        self.act_slabs = 0
        self.num_slabs = 0
        self.shared_avail = 0
        return

    def extra_next(self, sio):

# -- Sample records
#
# slabinfo - version: 2.1
# # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
# fat_inode_cache      216    216    672   24    4 : tunables    0    0    0 : slabdata      9      9      0
# fat_cache            714    714     40  102    1 : tunables    0    0    0 : slabdata      7      7      0
# nf_conntrack_expect      0      0    240   34    2 : tunables    0    0    0 : slabdata      0      0      0

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_SLAB_NAME] = ""
            self.field[PFC.F_ACTIVE_OBJS] = 0
            self.field[PFC.F_NUM_OBJS] = 0
            self.field[PFC.F_OBJ_SIZE] = 0
            self.field[PFC.F_OBJ_PER_SLAB] = 0
            self.field[PFC.F_PAGES_PER_SLAB] = 0
            self.field[PFC.F_LIMIT] = 0
            self.field[PFC.F_BATCHCOUNT] = 0
            self.field[PFC.F_SHARED] = 0
            self.field[PFC.F_ACTIVE_SLABS] = 0
            self.field[PFC.F_NUM_SLABS] = 0
            self.field[PFC.F_SHARED_AVAIL] = 0
            self.field[PFC.F_LIST_ALLOCS] = 0
            self.field[PFC.F_MAX_OBJS] = 0
            self.field[PFC.F_GROWN] = 0
            self.field[PFC.F_REAPED] = 0
            self.field[PFC.F_ERROR] = 0
            self.field[PFC.F_MAX_FREEABLE] = 0
            self.field[PFC.F_NODE_ALLOCS] = 0
            self.field[PFC.F_REMOTE_FREES] = 0
            self.field[PFC.F_ALIEN_OVERFLOW] = 0
            self.field[PFC.F_ALLOC_HIT] = 0
            self.field[PFC.F_ALLOC_MISS] = 0
            self.field[PFC.F_FREE_HIT] = 0
            self.field[PFC.F_FREE_MISS] = 0

        else:
            self.field[PFC.F_SLAB_NAME] = sio.lineparts[0]
            self.field[PFC.F_ACTIVE_OBJS] = long(sio.lineparts[1])
            self.field[PFC.F_NUM_OBJS] = long(sio.lineparts[2])
            self.field[PFC.F_OBJ_SIZE] = long(sio.lineparts[3])
            self.field[PFC.F_OBJ_PER_SLAB] = long(sio.lineparts[4])
            self.field[PFC.F_PAGES_PER_SLAB] = long(sio.lineparts[5])
            self.field[PFC.F_LIMIT] = long(sio.lineparts[8])
            self.field[PFC.F_BATCHCOUNT] = long(sio.lineparts[9])
            self.field[PFC.F_SHARED] = long(sio.lineparts[10])
            self.field[PFC.F_ACTIVE_SLABS] = long(sio.lineparts[13])
            self.field[PFC.F_NUM_SLABS] = long(sio.lineparts[14])
            self.field[PFC.F_SHARED_AVAIL] = long(sio.lineparts[15])

            if sio.linewords >= self.__ExtendedRec:
                self.field[PFC.F_LIST_ALLOCS] = long(sio.lineparts[18])
                self.field[PFC.F_MAX_OBJS] = long(sio.lineparts[19])
                self.field[PFC.F_GROWN] = long(sio.lineparts[20])
                self.field[PFC.F_REAPED] = long(sio.lineparts[21])
                self.field[PFC.F_ERROR] = long(sio.lineparts[22])
                self.field[PFC.F_MAX_FREEABLE] = long(sio.lineparts[23])
                self.field[PFC.F_NODE_ALLOCS] = long(sio.lineparts[24])
                self.field[PFC.F_REMOTE_FREES] = long(sio.lineparts[25])
                self.field[PFC.F_ALIEN_OVERFLOW] = long(sio.lineparts[26])
                self.field[PFC.F_ALLOC_HIT] = long(sio.lineparts[29])
                self.field[PFC.F_ALLOC_MISS] = long(sio.lineparts[30])
                self.field[PFC.F_FREE_HIT] = long(sio.lineparts[31])
                self.field[PFC.F_FREE_MISS] = long(sio.lineparts[32])
            else:
                self.field[PFC.F_LIST_ALLOCS] = 0
                self.field[PFC.F_MAX_OBJS] = 0
                self.field[PFC.F_GROWN] = 0
                self.field[PFC.F_REAPED] = 0
                self.field[PFC.F_ERROR] = 0
                self.field[PFC.F_MAX_FREEABLE] = 0
                self.field[PFC.F_NODE_ALLOCS] = 0
                self.field[PFC.F_REMOTE_FREES] = 0
                self.field[PFC.F_ALIEN_OVERFLOW] = 0
                self.field[PFC.F_ALLOC_HIT] = 0
                self.field[PFC.F_ALLOC_MISS] = 0
                self.field[PFC.F_FREE_HIT] = 0
                self.field[PFC.F_FREE_MISS] = 0

        self.slab = self.field[PFC.F_SLAB_NAME]
        self.act_objs = self.field[PFC.F_ACTIVE_OBJS]
        self.num_objs = self.field[PFC.F_NUM_OBJS]
        self.obj_size = self.field[PFC.F_OBJ_SIZE]
        self.obj_per_slab = self.field[PFC.F_OBJ_PER_SLAB]
        self.pages_per_slab = self.field[PFC.F_PAGES_PER_SLAB]
        self.limit = self.field[PFC.F_LIMIT]
        self.batchcount = self.field[PFC.F_BATCHCOUNT]
        self.shared = self.field[PFC.F_SHARED]
        self.act_slabs = self.field[PFC.F_ACTIVE_SLABS]
        self.num_slabs = self.field[PFC.F_NUM_SLABS]
        self.shared_avail = self.field[PFC.F_SHARED_AVAIL]

        return(self.slab, self.act_objs, self.num_objs, self.obj_size, self.obj_per_slab,
          self.pages_per_slab, self.limit, self.batchcount, self.shared, self.act_slabs,
          self.num_slabs, self.shared_avail)
#
RegisterProcFileHandler("/proc/slabinfo", ProcRootSLABINFO)
RegisterPartialProcFileHandler("slabinfo", ProcRootSLABINFO)



# ---
class ProcRootVMALLOCINFO(PBR.fixed_delim_format_recs):
    """Pull records from /proc/vmallocinfo"""
# source: 
#
#        seq_printf(m, "0x%p-0x%p %7ld",
#                v->addr, v->addr + v->size, v->size);
#
#        if (v->caller)
#                seq_printf(m, " %pS", v->caller);
#
#        if (v->nr_pages)
#                seq_printf(m, " pages=%d", v->nr_pages);
#
#        if (v->phys_addr)
#                seq_printf(m, " phys=%llx", (unsigned long long)v->phys_addr);
#
#        if (v->flags & VM_IOREMAP)
#                seq_printf(m, " ioremap");
#
#        if (v->flags & VM_ALLOC)
#                seq_printf(m, " vmalloc");
#
#        if (v->flags & VM_MAP)
#                seq_printf(m, " vmap");
#
#        if (v->flags & VM_USERMAP)
#                seq_printf(m, " user");
#
#        if (v->flags & VM_VPAGES)
#                seq_printf(m, " vpages");
#
#        show_numa_info(m, v);
#        seq_putc(m, '\n');
#
# ...and from show_numa_info()...
#                for_each_node_state(nr, N_HIGH_MEMORY)
#                        if (counters[nr])
#                                seq_printf(m, " N%u=%u", nr, counters[nr]);

    def extra_init(self, *opts):
        self.minfields = 2
        self.__FieldDelim = "-"
        self.__NameBracket = "["
        self.__PrefixPages = "pages="
        self.__PrefixPhys = "phys="
        self.__FlagIOREMAP = "ioremap"
        self.__FlagVMALLOC = "vmalloc"
        self.__FlagVMAP = "vmap"
        self.__FlagUSERMAP = "user"
        self.__FlagVPAGES = "vpages"
        self.__PrefixNuma = "N"

        self.start_addr = 0
        self.end_addr = 0
        self.size = 0
        self.caller = ""
        self.flags = ""
        self.numa = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 0xffffc900100c0000-0xffffc900100e1000  135168 e1000_probe+0x21b/0xa0b [e1000e] phys=fbf00000 ioremap
# 0xffffc900100e1000-0xffffc900100ea000   36864 xt_alloc_table_info+0xda/0x10e [x_tables] pages=8 vmalloc N0=8
# 0xffffc900100ea000-0xffffc900100f3000   36864 xt_alloc_table_info+0xda/0x10e [x_tables] pages=8 vmalloc N0=8
# 0xffffc900100fb000-0xffffc90010100000   20480 swap_cgroup_swapon+0x60/0x170 pages=4 vmalloc N0=4
# 0xffffc90010100000-0xffffc90011101000 16781312 efi_ioremap+0x1a/0x57 phys=ff000000 ioremap
# 0xffffc90011101000-0xffffc90013102000 33558528 alloc_large_system_hash+0x14b/0x215 pages=8192 vmalloc vpages N0=8192

        __flags = ""
        __numa = ""
        __invalid = ""

        if sio.buff == "":

            self.field = dict()

            self.field[PFC.F_START] = 0
            self.field[PFC.F_END] = 0
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_CALLER] = ""
            self.field[PFC.F_PAGES] = 0
            self.field[PFC.F_PHYS_ADDR] = 0
            self.field[PFC.F_IOREMAP] = 0
            self.field[PFC.F_VM_ALLOC] = 0
            self.field[PFC.F_VM_MAP] = 0
            self.field[PFC.F_USER_MAP] = 0
            self.field[PFC.F_VM_PAGES] = 0
            self.field[PFC.F_NUMA_INFO] = ""

        else:
            __split = sio.lineparts[0].partition(self.__FieldDelim)
            self.field[PFC.F_START] = long(__split[0][2:], 16)
            self.field[PFC.F_END] = long(__split[2][2:], 16)
            self.field[PFC.F_SIZE] = long(sio.lineparts[1])

            self.field[PFC.F_CALLER] = ""
            self.field[PFC.F_PAGES] = 0
            self.field[PFC.F_PHYS_ADDR] = 0
            self.field[PFC.F_IOREMAP] = 0
            self.field[PFC.F_VM_ALLOC] = 0
            self.field[PFC.F_VM_MAP] = 0
            self.field[PFC.F_USER_MAP] = 0
            self.field[PFC.F_VM_PAGES] = 0
            self.field[PFC.F_NUMA_INFO] = ""

            __off = 2
            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                __pref = self.__PrefixPages
                if __check[:len(__pref)] == __pref:
                    self.field[PFC.F_PAGES] = long(__check[len(__pref):], 16)
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                else:
                    self.field[PFC.F_CALLER] = __check
                __off = __off + 1

            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                if __check[0:1] == self.__NameBracket:
                    self.field[PFC.F_CALLER] = "{base} {qual}".format(base=self.field[PFC.F_CALLER], qual=__check)
                    __off = __off + 1

            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                __pref = self.__PrefixPages
                if __check[:len(__pref)] == __pref:
                    self.field[PFC.F_PAGES] = long(__check[len(__pref):], 16)
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                __pref = self.__PrefixPhys
                if __check[:len(__pref)] == __pref:
                    self.field[PFC.F_PHYS_ADDR] = long(__check[len(__pref):], 16)
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FlagIOREMAP:
                    self.field[PFC.F_IOREMAP] = 1
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FlagVMALLOC:
                    self.field[PFC.F_VM_ALLOC] = 1
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FlagVMAP:
                    self.field[PFC.F_VM_MAP] = 1
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FlagUSERMAP:
                    self.field[PFC.F_USER_MAP] = 1
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            if sio.linewords > __off:
                if sio.lineparts[__off] == self.__FlagVPAGES:
                    self.field[PFC.F_VM_PAGES] = 1
                    __flags = "{flags} {next}".format(flags=__flags, next=sio.lineparts[__off])
                    __off = __off + 1

            for __rest in range(__off, sio.linewords):
                __check = sio.lineparts[__rest]
                if __check[0:1] == self.__PrefixNuma:
                    __numa = "{curr} {app}".format(curr=__numa, app=__check)
                else:
                    __invalid = "{curr} {app}".format(curr=__invalid, app=__check)

            if __numa[0:1] == " ":
                self.field[PFC.F_NUMA_INFO] = __numa[1:]
            else:
                self.field[PFC.F_NUMA_INFO] = __numa

            if __invalid[0:1] == " ":
                self.field[PFC.F_INVALID] = __invalid[1:]
            else:
                self.field[PFC.F_INVALID] = __invalid

        self.start_addr = self.field[PFC.F_START]
        self.end_addr = self.field[PFC.F_END]
        self.size = self.field[PFC.F_SIZE]
        self.caller = self.field[PFC.F_CALLER]
        self.flags = __flags
        self.numa = __numa

        return(self.start_addr, self.end_addr, self.size, self.caller, self.flags, self.numa)
#
RegisterProcFileHandler("/proc/vmallocinfo", ProcRootVMALLOCINFO)
RegisterPartialProcFileHandler("vmallocinfo", ProcRootVMALLOCINFO)



# ---
class ProcRootMDSTAT(PBR.fixed_delim_format_recs):
    """Pull records from /proc/mdstat"""
# source: drivers/md/raid10.c
# --and--
# source: drivers/md/md.c
#
# from: drivers/md/raid10.c
# ---
# static void status(struct seq_file *seq, struct mddev *mddev)
# {
#         struct r10conf *conf = mddev->private;
#         int i;
# 
#         if (conf->near_copies < conf->raid_disks)
#                 seq_printf(seq, " %dK chunks", mddev->chunk_sectors / 2);
#         if (conf->near_copies > 1)
#                 seq_printf(seq, " %d near-copies", conf->near_copies);
#         if (conf->far_copies > 1) {
#                 if (conf->far_offset)
#                         seq_printf(seq, " %d offset-copies", conf->far_copies);
#                 else
#                         seq_printf(seq, " %d far-copies", conf->far_copies);
#         }
#         seq_printf(seq, " [%d/%d] [", conf->raid_disks,
#                                         conf->raid_disks - mddev->degraded);
#         for (i = 0; i < conf->raid_disks; i++)
#                 seq_printf(seq, "%s",
#                               conf->mirrors[i].rdev &&
#                               test_bit(In_sync, &conf->mirrors[i].rdev->flags) ? "U" : "_");
#         seq_printf(seq, "]");
# }
#
# from: drivers/md/raid10.c
# ---
# static void status_unused(struct seq_file *seq)
# {
# 
# 	seq_printf(seq, "unused devices: ");
# 
# 	list_for_each_entry(rdev, &pending_raid_disks, same_set) {
# 		char b[BDEVNAME_SIZE];
# 		i++;
# 		seq_printf(seq, "%s ",
# 			      bdevname(rdev->bdev,b));
# 	}
# 	if (!i)
# 		seq_printf(seq, "<none>");
# 
# 	seq_printf(seq, "\n");
# }
# 
# 
# static void status_resync(struct seq_file *seq, struct mddev * mddev)
# {
# 	{
# 		int i, x = per_milli/50, y = 20-x;
# 		seq_printf(seq, "[");
# 		for (i = 0; i < x; i++)
# 			seq_printf(seq, "=");
# 		seq_printf(seq, ">");
# 		for (i = 0; i < y; i++)
# 			seq_printf(seq, ".");
# 		seq_printf(seq, "] ");
# 	}
# 	seq_printf(seq, " %s =%3u.%u%% (%llu/%llu)",
# 		   (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)?
# 		    "reshape" :
# 		    (test_bit(MD_RECOVERY_CHECK, &mddev->recovery)?
# 		     "check" :
# 		     (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) ?
# 		      "resync" : "recovery"))),
# 		   per_milli/10, per_milli % 10,
# 		   (unsigned long long) resync/2,
# 		   (unsigned long long) max_sectors/2);
# ...code deleted...
# 
# 	seq_printf(seq, " finish=%lu.%lumin", (unsigned long)rt / 60,
# 		   ((unsigned long)rt % 60)/6);
# 
# 	seq_printf(seq, " speed=%ldK/sec", db/2/dt);
# }
# 
# static int md_seq_show(struct seq_file *seq, void *v)
# {
# ...code deleted...
# 
# 	if (v == (void*)1) {
# 		struct md_personality *pers;
# 		seq_printf(seq, "Personalities : ");
# 		spin_lock(&pers_lock);
# 		list_for_each_entry(pers, &pers_list, list)
# 			seq_printf(seq, "[%s] ", pers->name);
# 
# 		spin_unlock(&pers_lock);
# 		seq_printf(seq, "\n");
# 		seq->poll_event = atomic_read(&md_event_count);
# 		return 0;
# 	}
# 	if (v == (void*)2) {
# 		status_unused(seq);
# 		return 0;
# 	}
# 
# 	if (mddev_lock(mddev) < 0)
# 		return -EINTR;
# 
# 	if (mddev->pers || mddev->raid_disks || !list_empty(&mddev->disks)) {
# 		seq_printf(seq, "%s : %sactive", mdname(mddev),
# 						mddev->pers ? "" : "in");
# 		if (mddev->pers) {
# 			if (mddev->ro==1)
# 				seq_printf(seq, " (read-only)");
# 			if (mddev->ro==2)
# 				seq_printf(seq, " (auto-read-only)");
# 			seq_printf(seq, " %s", mddev->pers->name);
# 		}
# 
# 		sectors = 0;
# 		list_for_each_entry(rdev, &mddev->disks, same_set) {
# 			char b[BDEVNAME_SIZE];
# 			seq_printf(seq, " %s[%d]",
# 				bdevname(rdev->bdev,b), rdev->desc_nr);
# 			if (test_bit(WriteMostly, &rdev->flags))
# 				seq_printf(seq, "(W)");
# 			if (test_bit(Faulty, &rdev->flags)) {
# 				seq_printf(seq, "(F)");
# 				continue;
# 			} else if (rdev->raid_disk < 0)
# 				seq_printf(seq, "(S)"); /* spare */
# 			sectors += rdev->sectors;
# 		}
# 
# 		if (!list_empty(&mddev->disks)) {
# 			if (mddev->pers)
# 				seq_printf(seq, "\n      %llu blocks",
# 					   (unsigned long long)
# 					   mddev->array_sectors / 2);
# 			else
# 				seq_printf(seq, "\n      %llu blocks",
# 					   (unsigned long long)sectors / 2);
# 		}
# 		if (mddev->persistent) {
# 			if (mddev->major_version != 0 ||
# 			    mddev->minor_version != 90) {
# 				seq_printf(seq," super %d.%d",
# 					   mddev->major_version,
# 					   mddev->minor_version);
# 			}
# 		} else if (mddev->external)
# 			seq_printf(seq, " super external:%s",
# 				   mddev->metadata_type);
# 		else
# 			seq_printf(seq, " super non-persistent");
# 
# 		if (mddev->pers) {
# 			mddev->pers->status(seq, mddev);
# 	 		seq_printf(seq, "\n      ");
# 			if (mddev->pers->sync_request) {
# 				if (mddev->curr_resync > 2) {
# 					status_resync(seq, mddev);
# 					seq_printf(seq, "\n      ");
# 				} else if (mddev->curr_resync == 1 || mddev->curr_resync == 2)
# 					seq_printf(seq, "\tresync=DELAYED\n      ");
# 				else if (mddev->recovery_cp < MaxSector)
# 					seq_printf(seq, "\tresync=PENDING\n      ");
# 			}
# 		} else
# 			seq_printf(seq, "\n       ");
# 
# 		if ((bitmap = mddev->bitmap)) {
# 			unsigned long chunk_kb;
# 			unsigned long flags;
# 			spin_lock_irqsave(&bitmap->lock, flags);
# 			chunk_kb = mddev->bitmap_info.chunksize >> 10;
# 			seq_printf(seq, "bitmap: %lu/%lu pages [%luKB], "
# 				"%lu%s chunk",
# 				bitmap->pages - bitmap->missing_pages,
# 				bitmap->pages,
# 				(bitmap->pages - bitmap->missing_pages)
# 					<< (PAGE_SHIFT - 10),
# 				chunk_kb ? chunk_kb : mddev->bitmap_info.chunksize,
# 				chunk_kb ? "KB" : "B");
# 			if (bitmap->file) {
# 				seq_printf(seq, ", file: ");
# 				seq_path(seq, &bitmap->file->f_path, " \t\n");
# 			}
# 
# 			seq_printf(seq, "\n");
# 			spin_unlock_irqrestore(&bitmap->lock, flags);
# 		}
# 
# 		seq_printf(seq, "\n");
# 	}
# 	mddev_unlock(mddev);
# 	
# 	return 0;
# }

    def extra_init(self, *opts):
        self.__MinWords_first = 1
        self.__MinWords_second = 0
        self.minfields = self.__MinWords_first

        self.rec_type = ""
        self.personalities = []
        self.device_list = []
        self.active_stat = ""
        self.pers_name = ""
        self.partition_list = dict()
        self.wrmostly_list = dict()
        self.faulty_list = dict()
        self.spare_list = dict()
        self.readonly = 0
        self.blocks = 0
        self.super = ""
        self.chunk = 0
        self.nearcopy = 0
        self.offsetcopy = 0
        self.farcopy = 0
        self.activeparts = 0
        self.totalparts = 0
        self.part_usemap = ""
        self.rebuild_prog = ""
        self.resync_stat = ""
        self.rebuild_act = ""
        self.percent = 0
        self.rebuild_done = 0
        self.rebuild_total = 0
        self.finish = 0
        self.speed = 0
        self.nomiss_pages = 0
        self.total_pages = 0
        self.nomiss_pages_kb = 0
        self.bitmap_chunk = 0
        self.bitmap_file = ""

        self.__REC_PERSONALITY = "Personalities"
        self.__REC_UNUSED = "unused"
        self.__REC_BITMAP = "bitmap:"
        self.__READONLY_FLAG = "(read-only)"
        self.__AUTOREADONLY_FLAG = "(auto-read-only)"
        self.__SUPER_FLAG = "super"
        self.__CHUNK_FLAG = "chunks"
        self.__NEAR_COPY_FLAG = "near-copies"
        self.__OFFSET_COPY_FLAG = "offset-copies"
        self.__FAR_COPY_FLAG = "far-copies"
        self.__OPEN_LIST = "["
        self.__NUM_SPLIT = "/"
        self.__PROG_SPLIT = ">"
        self.__USED_Y = "U"
        self.__USED_N = "_"
        self.__BLOCKS_FLAG = "blocks"
        self.__BITMAP_FLAG = "bitmap:"
        self.__RESYNC_FLAG = "resync"
        self.__RESYNC_DELIM = "="
        self.__VALUE_PREF = "="
        self.__FINISH_SUFF = "min"
        self.__SPEED_SUFF = "K/sec"
        self.__PAGES_SUFF = "KB],"
        self.__KB_SUFF = "KB"
        self.__B_SUFF = "B"
        self.__PATH_PREF = "file:"
        self.__INFO_DELIM = "("
        self.__DEV_DELIM = "["
        self.__WRMOSTLY_FLAG = "W"
        self.__FAULTY_FLAG = "F"
        self.__SPARE_FLAG = "S"
        return

    def parse_personality_record(self, sio):
        if sio.linewords > 1:
            self.field[PFC.F_PERSONALITIES] = sio.lineparts[2:]
        else:
            self.field[PFC.F_PERSONALITIES] = []
        return

    def parse_unused_record(self, sio):
        if sio.linewords > 1:
            self.field[PFC.F_DEVICE_LIST] = sio.lineparts[2:]
        else:
            self.field[PFC.F_DEVICE_LIST] = []
        return

    def parse_bitmap_subrec(self, sio):
        __split = sio.lineparts[1].partition(self.__NUM_SPLIT)
        self.field[PFC.F_PAGES_NOMISS] = long(__split[0])
        self.field[PFC.F_PAGES_TOTAL] = long(__split[2])

        __curr = sio.lineparts[3]
        self.field[PFC.F_PAGES_NOMISS_KB] = long(__curr[1:-len(self.__PAGES_SUFF)])

        __curr = sio.lineparts[4]
        if __curr[-len(self.__KB_SUFF):] == self.__KB_SUFF:
            self.field[PFC.F_BITMAP_CHUNK] = long(__curr[:-len(self.__KB_SUFF)]) * 1024
        else:
            self.field[PFC.F_BITMAP_CHUNK] = long(__curr[:-len(self.__B_SUFF)])

        if sio.linewords >= 7:
            __curr = " ".join(sio.lineparts[6:])
            if __curr[:len(self.__PATH_PREF)] == self.__PATH_PREF:
                __curr = __curr[len(self.__PATH_PREF):]

            if __curr[:1] == " ":
                __curr = __curr[1:]
            self.field[PFC.F_FILEPATH] = __curr

        return

    def parse_rebuild_subrec(self, sio):
        __curr = sio.lineparts[0]
        if __curr[:len(self.__RESYNC_FLAG)] == self.__RESYNC_FLAG:
            self.field[PFC.F_RESYNC_STAT] = __curr.partition(self.__RESYNC_DELIM)[2]
        else:
            self.field[PFC.F_REBUILD_PROG] = sio.lineparts[0]
            self.field[PFC.F_REBUILD_ACTION] = sio.lineparts[1]

            __off = 2
            if sio.lineparts[__off] == self.__VALUE_PREF:
                __off = __off + 1
                __curr = sio.lineparts[__off]
            else:
                __curr = sio.lineparts[__off][1:]
            self.field[PFC.F_PERCENT] = float(__curr[:-1])

            __off = __off + 1
            __split = sio.lineparts[__off].partition(self.__NUM_SPLIT)
            self.field[PFC.F_REBUILD_DONE] = long(__split[0][1:])
            self.field[PFC.F_REBUILD_TOTAL] = long(__split[2][:-1])

            __off = __off + 1
            __split = sio.lineparts[__off].partition(self.__VALUE_PREF)
            self.field[PFC.F_FIN_TIME] = float(__split[2][:-len(self.__FINISH_SUFF)])

            __off = __off + 1
            __split = sio.lineparts[__off].partition(self.__VALUE_PREF)
            self.field[PFC.F_SPEED] = long(__split[2][:-len(self.__SPEED_SUFF)])
        return

    def parse_blocks_subrec(self, sio):
        __words = sio.linewords
        self.field[PFC.F_BLOCKS] = long(sio.lineparts[0])
        __off = 2
        if __off < __words and sio.lineparts[__off] == self.__SUPER_FLAG:
            self.field[PFC.F_SUPER] = sio.lineparts[__off + 1]
            __off = __off + 2
        if __off < __words and sio.lineparts[__off + 1] == self.__CHUNK_FLAG:
            self.field[PFC.F_CHUNK] = long(sio.lineparts[__off][:-1])
            __off = __off + 2
        if __off < __words and sio.lineparts[__off + 1] == self.__NEAR_COPY_FLAG:
            self.field[PFC.F_NEAR_COPY] = long(sio.lineparts[__off])
            __off = __off + 2
        if __off < __words and sio.lineparts[__off + 1] == self.__OFFSET_COPY_FLAG:
            self.field[PFC.F_OFFSET_COPY] = long(sio.lineparts[__off])
            __off = __off + 2
        if __off < __words and sio.lineparts[__off + 1] == self.__FAR_COPY_FLAG:
            self.field[PFC.F_FAR_COPY] = long(sio.lineparts[__off])
            __off = __off + 2

        for __try in range(2):
            if __off < __words and sio.lineparts[__off][:1] == self.__OPEN_LIST:
                __curr = sio.lineparts[__off]
                __split = __curr.partition(self.__NUM_SPLIT)
                if __split[0] != __curr:
                    self.field[PFC.F_TOTAL_PARTS] = long(__split[0][1:])
                    self.field[PFC.F_ACTIVE_PARTS] = long(__split[2][:-1])
                elif __curr[1:2] == self.__USED_Y or __curr[1:2] == self.__USED_N:
                    self.field[PFC.F_PART_USEMAP] = __curr
                __off = __off + 1
        return

    def parse_partition_list(self, sio, rawlist):
        __dplist = rawlist.split(" ")
        __partmap = dict()
        __wrmostly = dict()
        __faulty = dict()
        __spare = dict()

        for __devinfo in __dplist:
            __bits = __devinfo.split(self.__INFO_DELIM)
            __split = __bits[0].partition(self.__DEV_DELIM)
            __pnum = long(__split[2][:-1])

            __partmap[__pnum] = __split[0]
            __wrmostly[__pnum] = 0
            __faulty[__pnum] = 0
            __spare[__pnum] = 0

            for __flag in __bits[1:]:
                __flag = __flag[:-1]
                if __flag == self.__WRMOSTLY_FLAG:
                    __wrmostly[__pnum] = 1
                elif __flag == self.__FAULTY_FLAG:
                    __faulty[__pnum] = 1
                elif __flag == self.__SPARE_FLAG:
                    __spare[__pnum] = 1

        self.field[PFC.F_PARTITION_LIST] = __partmap
        self.field[PFC.F_WRMOSTLY_LIST] = __wrmostly
        self.field[PFC.F_FAULTY_LIST] = __faulty
        self.field[PFC.F_SPARE_LIST] = __spare
        return

    def parse_mddev_record(self, sio):
        self.field[PFC.F_ACTIVE_STAT] = sio.lineparts[2]
        __off = 3
        if sio.lineparts[__off] == self.__READONLY_FLAG:
            self.field[PFC.F_READONLY] = 1
            __off = __off + 1
        if sio.lineparts[__off] == self.__AUTOREADONLY_FLAG:
            self.field[PFC.F_READONLY] = 2
            __off = __off + 1
        self.field[PFC.F_PERS_NAME] = sio.lineparts[__off]
        __off = __off + 1
        self.parse_partition_list(sio, " ".join(sio.lineparts[__off:]))

        sio.MinWords = self.__MinWords_second
        sio.read_line()
        for __subrec in range(3):
            if sio.linewords > 0:
                __keyfield = sio.lineparts[0]
                if sio.linewords > 1 and sio.lineparts[1] == self.__BLOCKS_FLAG:
                    self.parse_blocks_subrec(sio)
                elif __keyfield[:1] == self.__OPEN_LIST:
                    self.parse_rebuild_subrec(sio)
                elif __keyfield == self.__BITMAP_FLAG:
                    self.parse_bitmap_subrec(sio)
                sio.read_line()
        sio.MinWords = self.__MinWords_first
        return

    def extra_next(self, sio):

# -- Sample records #1
# Personalities : [linear] [multipath] [raid0] [raid1] [raid10] [raid6] [raid5] [raid4] 
# md1 : active raid10 sda2[0] sdd1[3] sdb2[1] sdc2[2]
#       3221222400 blocks super 1.2 512K chunks 2 near-copies [4/4] [UUUU]
#       
# md0 : active raid10 sdb1[0] sdc1[1]
#       104856064 blocks super 1.2 2 near-copies [2/2] [UU]
#       
# unused devices: <none>
#
# -- Sample records #2
# Personalities : [raid10] 
# md127 : active raid10 sda2[0] sdb1[1]
#       1564531200 blocks super 1.1 2 near-copies [2/1] [_U]
#       [=>...................]  recovery =  5.2% (82101312/1564531200) finish=115.9min speed=213025K/sec
#       bitmap: 12/12 pages [48KB], 65536KB chunk
# 
# unused devices: <none>

        self.field = dict()

        self.field[PFC.F_REC_TYPE] = ""
        self.field[PFC.F_PERSONALITIES] = []
        self.field[PFC.F_DEVICE_LIST] = []
        self.field[PFC.F_ACTIVE_STAT] = ""
        self.field[PFC.F_PERS_NAME] = ""
        self.field[PFC.F_PARTITION_LIST] = dict()
        self.field[PFC.F_WRMOSTLY_LIST] = dict()
        self.field[PFC.F_FAULTY_LIST] = dict()
        self.field[PFC.F_SPARE_LIST] = dict()
        self.field[PFC.F_READONLY] = 0
        self.field[PFC.F_BLOCKS] = 0
        self.field[PFC.F_SUPER] = ""
        self.field[PFC.F_CHUNK] = 0
        self.field[PFC.F_NEAR_COPY] = 0
        self.field[PFC.F_OFFSET_COPY] = 0
        self.field[PFC.F_FAR_COPY] = 0
        self.field[PFC.F_ACTIVE_PARTS] = 0
        self.field[PFC.F_TOTAL_PARTS] = 0
        self.field[PFC.F_PART_USEMAP] = ""
        self.field[PFC.F_REBUILD_PROG] = ""
        self.field[PFC.F_RESYNC_STAT] = ""
        self.field[PFC.F_REBUILD_ACTION] = ""
        self.field[PFC.F_PERCENT] = 0
        self.field[PFC.F_REBUILD_DONE] = 0
        self.field[PFC.F_REBUILD_TOTAL] = 0
        self.field[PFC.F_FIN_TIME] = 0
        self.field[PFC.F_SPEED] = 0
        self.field[PFC.F_PAGES_NOMISS] = 0
        self.field[PFC.F_PAGES_TOTAL] = 0
        self.field[PFC.F_PAGES_NOMISS_KB] = 0
        self.field[PFC.F_BITMAP_CHUNK] = 0
        self.field[PFC.F_FILEPATH] = ""

        if sio.buff != "":
            __rec = sio.lineparts[0]
            self.field[PFC.F_REC_TYPE] = __rec

            if __rec == self.__REC_PERSONALITY:
                self.parse_personality_record(sio)

            elif __rec == self.__REC_UNUSED:
                self.parse_unused_record(sio)

            elif __rec != "":
                self.parse_mddev_record(sio)

        self.rec_type = self.field[PFC.F_REC_TYPE]
        self.personalities = self.field[PFC.F_PERSONALITIES]
        self.device_list = self.field[PFC.F_DEVICE_LIST]
        self.active_stat = self.field[PFC.F_ACTIVE_STAT]
        self.pers_name = self.field[PFC.F_PERS_NAME]
        self.partition_list = self.field[PFC.F_PARTITION_LIST]
        self.wrmostly_list = self.field[PFC.F_WRMOSTLY_LIST]
        self.faulty_list = self.field[PFC.F_FAULTY_LIST]
        self.spare_list = self.field[PFC.F_SPARE_LIST]
        self.readonly = self.field[PFC.F_READONLY]
        self.blocks = self.field[PFC.F_BLOCKS]
        self.super = self.field[PFC.F_SUPER]
        self.chunk = self.field[PFC.F_CHUNK]
        self.nearcopy = self.field[PFC.F_NEAR_COPY]
        self.offsetcopy = self.field[PFC.F_OFFSET_COPY]
        self.farcopy = self.field[PFC.F_FAR_COPY]
        self.activeparts = self.field[PFC.F_ACTIVE_PARTS]
        self.totalparts = self.field[PFC.F_TOTAL_PARTS]
        self.part_usemap = self.field[PFC.F_PART_USEMAP]
        self.rebuild_prog = self.field[PFC.F_REBUILD_PROG]
        self.resync_stat = self.field[PFC.F_RESYNC_STAT]
        self.rebuild_act = self.field[PFC.F_REBUILD_ACTION]
        self.percent = self.field[PFC.F_PERCENT]
        self.rebuild_done = self.field[PFC.F_REBUILD_DONE]
        self.rebuild_total = self.field[PFC.F_REBUILD_TOTAL]
        self.finish = self.field[PFC.F_FIN_TIME]
        self.speed = self.field[PFC.F_SPEED]
        self.nomiss_pages = self.field[PFC.F_PAGES_NOMISS]
        self.total_pages = self.field[PFC.F_PAGES_TOTAL]
        self.nomiss_pages_kb = self.field[PFC.F_PAGES_NOMISS_KB]
        self.bitmap_chunk = self.field[PFC.F_BITMAP_CHUNK]
        self.bitmap_file = self.field[PFC.F_FILEPATH]

        return(self.rec_type, self.personalities, self.device_list, self.active_stat, self.pers_name,
          self.partition_list, self.wrmostly_list, self.faulty_list, self.spare_list, self.readonly,
          self.blocks, self.super, self.chunk, self.nearcopy, self.offsetcopy, self.farcopy,
          self.activeparts, self.totalparts, self.part_usemap, self.rebuild_prog, self.resync_stat,
          self.rebuild_act, self.percent, self.rebuild_done, self.rebuild_total, self.finish, self.speed,
          self.nomiss_pages, self.total_pages, self.nomiss_pages_kb, self.bitmap_chunk, self.bitmap_file)
#
RegisterProcFileHandler("/proc/mdstat", ProcRootMDSTAT)
RegisterPartialProcFileHandler("mdstat", ProcRootMDSTAT)
