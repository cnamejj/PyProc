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


import numpy
import ProcBaseRoutines
import ProcFieldConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants

FIELD_NAME = PBR.FIELD_NAME
FIELD_NUMBER = PBR.FIELD_NUMBER
CONVERSION = PBR.CONVERSION
ERROR_VAL = PBR.ERROR_VAL
NUM_BASE = PBR.NUM_BASE
PREFIX_VAL = PBR.PREFIX_VAL
SUFFIX_VAL = PBR.SUFFIX_VAL
BEFORE_VAL = PBR.BEFORE_VAL
AFTER_VAL = PBR.AFTER_VAL

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_PERSONALITY_LOW, BEFORE_VAL: "-", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_PERSONALITY_HIGH, AFTER_VAL: "-", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_EXDOM_NAME } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_EXDOM_MODULE } )

        self.pers_low = 0
        self.pers_high = 0
        self.exdom_name = ""
        self.exdom_module = ""
        return

    def extra_next(self, sio):

# -- Sample records (the real file has no column headers, they are added to clarify how the file is parsed)
# PL-PH Name                    Module
# 0-0	Linux           	[kernel]

        if sio.buff == "":

            self.field[PFC.F_PERSONALITY_LOW] = 0
            self.field[PFC.F_PERSONALITY_HIGH] = 0
            self.field[PFC.F_EXDOM_NAME] = ""
            self.field[PFC.F_EXDOM_MODULE] = ""

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_SUBSYSTEM } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_HIERARCHY, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_NUM_CGROUPS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_ENABLED, CONVERSION: long } )

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

            self.field[PFC.F_SUBSYSTEM] = ""
            self.field[PFC.F_HIERARCHY] = 0
            self.field[PFC.F_NUM_CGROUPS] = 0
            self.field[PFC.F_ENABLED] = 0

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_INDEX, PREFIX_VAL: "reg", SUFFIX_VAL: ":", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_BASE_MEMORY, PREFIX_VAL: "base=0x", SUFFIX_VAL: "00000", CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NAME: PFC.F_COUNT, PREFIX_VAL: "count=", SUFFIX_VAL: ":", CONVERSION: long } )

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
            self.field[PFC.F_INDEX] = 0
            self.field[PFC.F_BASE_MEMORY] = 0
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_COUNT] = 0
            self.field[PFC.F_TYPE] = ""

        else:
            __offset = 3
            if sio.lineparts[__offset] == self.__SizePref:
                __offset = __offset + 1
            elif sio.lineparts[__offset][:len(self.__SizePref)] != self.__SizePref:
                __offset = __offset + 1
                if sio.lineparts[__offset] == self.__SizePref:
                    __offset = __offset + 1
            self.field[PFC.F_SIZE] = long(sio.lineparts[__offset][-8:-3])

            __offset = __offset + 2
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_MODULE } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_SIZE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_REFCOUNT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_SOURCE_LIST } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_STATUS } )
        self.add_parse_rule( { FIELD_NUMBER: 5, FIELD_NAME: PFC.F_MODULE_CORE, PREFIX_VAL: "0x", CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NUMBER: 6, FIELD_NAME: PFC.F_TAINTS } )

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
            self.field[PFC.F_MODULE] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_REFCOUNT] = 0
            self.field[PFC.F_SOURCE_LIST] = ""
            self.field[PFC.F_STATUS] = ""
            self.field[PFC.F_MODULE_CORE] = 0
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

        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_NODE, SUFFIX_VAL: ",", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_ZONE } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_FRBL_AREA_1 } )
        self.add_parse_rule( { FIELD_NUMBER: 5, FIELD_NAME: PFC.F_FRBL_AREA_2 } )
        self.add_parse_rule( { FIELD_NUMBER: 6, FIELD_NAME: PFC.F_FRBL_AREA_3 } )
        self.add_parse_rule( { FIELD_NUMBER: 7, FIELD_NAME: PFC.F_FRBL_AREA_4 } )
        self.add_parse_rule( { FIELD_NUMBER: 8, FIELD_NAME: PFC.F_FRBL_AREA_5 } )
        self.add_parse_rule( { FIELD_NUMBER: 9, FIELD_NAME: PFC.F_FRBL_AREA_6 } )
        self.add_parse_rule( { FIELD_NUMBER: 10, FIELD_NAME: PFC.F_FRBL_AREA_7 } )
        self.add_parse_rule( { FIELD_NUMBER: 11, FIELD_NAME: PFC.F_FRBL_AREA_8 } )
        self.add_parse_rule( { FIELD_NUMBER: 12, FIELD_NAME: PFC.F_FRBL_AREA_9 } )
        self.add_parse_rule( { FIELD_NUMBER: 13, FIELD_NAME: PFC.F_FRBL_AREA_10 } )
        self.add_parse_rule( { FIELD_NUMBER: 14, FIELD_NAME: PFC.F_FRBL_AREA_11 } )

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_FILENAME } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_TYPE } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_SIZE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_USED, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_PRIORITY, CONVERSION: long } )

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
            self.field[PFC.F_FILENAME] = ""
            self.field[PFC.F_TYPE] = ""
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_USED] = 0
            self.field[PFC.F_PRIORITY] = 0

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
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_MAJOR_DEV, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_MINOR_DEV, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_DISK_NAME } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_READ_IOS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_READ_MERGES, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 5, FIELD_NAME: PFC.F_READ_SECTORS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 6, FIELD_NAME: PFC.F_READ_MSECS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 7, FIELD_NAME: PFC.F_WRITE_IOS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 8, FIELD_NAME: PFC.F_WRITE_MERGES, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 9, FIELD_NAME: PFC.F_WRITE_SECTORS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 10, FIELD_NAME: PFC.F_WRITE_MSECS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 11, FIELD_NAME: PFC.F_PART_IN_FLIGHT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 12, FIELD_NAME: PFC.F_IO_MSECS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 13, FIELD_NAME: PFC.F_QUEUE_TIME_MSECS, CONVERSION: long } )

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
        self.io_msecs = 0
        self.queue_time_msecs = 0
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_CATEGORY } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_COUNT, CONVERSION: long } )

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
            self.field[PFC.F_CATEGORY] = ""
            self.field[PFC.F_COUNT] = 0

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
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Filename"

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_CATEGORY } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_SIZE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_UNITS } )

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
            self.field[PFC.F_CATEGORY] = ""
            self.field[PFC.F_SIZE] = 0
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_MAJOR_DEV, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_MINOR_DEV, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_BLOCKS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_PARTITION_NAME } )

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
            self.field[PFC.F_MAJOR_DEV] = 0
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_BLOCKS] = 0
            self.field[PFC.F_PARTITION_NAME] = ""

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_MINOR_DEV, CONVERSION: long  } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_DEVICE  } )

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
            self.field[PFC.F_MINOR_DEV] = 0
            self.field[PFC.F_DEVICE] = ""

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_ADDRESS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_TYPE } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_SYMBOL } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_MODULE, PREFIX_VAL: "[", SUFFIX_VAL: "]" } )

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
            self.field[PFC.F_ADDRESS] = 0
            self.field[PFC.F_TYPE] = ""
            self.field[PFC.F_SYMBOL] = ""
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_CHANNEL, CONVERSION: long, SUFFIX_VAL: ":" } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_DEVICE_NAME } )

        self.channel = 0
        self.device = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 4: cascade

        if sio.buff == "":
            self.field[PFC.F_CHANNEL] = 0
            self.field[PFC.F_DEVICE_NAME] = ""

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_NODE, CONVERSION: long } )

        self.node = 0
        self.id = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# 0 EFI VGA

        if sio.buff == "":
            self.field[PFC.F_NODE] = 0
            self.field[PFC.F_ID_LIST] = ""

        else:
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_DEVICE_NAME } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_IO_TYPE } )

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
            self.field[PFC.F_DEVICE_NAME] = ""
            self.field[PFC.F_IO_TYPE] = ""
            self.field[PFC.F_FLAGS] = ""
            self.field[PFC.F_DEVICE_NUMBER] = ""

        else:
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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_UID, SUFFIX_VAL: ":", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_USAGE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_NKEYS, BEFORE_VAL: "/", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_NIKEYS, AFTER_VAL: "/", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_QNKEYS, BEFORE_VAL: "/", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_MAXKEYS, AFTER_VAL: "/", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_QNBYTES, BEFORE_VAL: "/", CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_MAXBYTES, AFTER_VAL: "/", CONVERSION: long } )

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
            self.field[PFC.F_UID] = 0
            self.field[PFC.F_USAGE] = 0
            self.field[PFC.F_NKEYS] = 0
            self.field[PFC.F_NIKEYS] = 0
            self.field[PFC.F_QNKEYS] = 0
            self.field[PFC.F_MAXKEYS] = 0
            self.field[PFC.F_QNBYTES] = 0
            self.field[PFC.F_MAXBYTES] = 0

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_UPTIME, CONVERSION: float } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_IDLE, CONVERSION: float } )

        self.uptime = 0.0
        self.idle = 0.0
        return

    def extra_next(self, sio):

# -- Sample records
#
# 3815061.73 30116159.34

        if sio.buff == "":
            self.field[PFC.F_UPTIME] = 0.0
            self.field[PFC.F_IDLE] = 0.0

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

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_LOAD_AV0, CONVERSION: float } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_LOAD_AV1, CONVERSION: float } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_LOAD_AV2, CONVERSION: float } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_NUM_TASKS, CONVERSION: long, BEFORE_VAL: "/" } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_NUM_THREADS, CONVERSION: long, AFTER_VAL: "/" } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_LAST_PID, CONVERSION: long } )

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
            self.field[PFC.F_LOAD_AV0] = 0.0
            self.field[PFC.F_LOAD_AV1] = 0.0
            self.field[PFC.F_LOAD_AV2] = 0.0
            self.field[PFC.F_NUM_TASKS] = 0
            self.field[PFC.F_NUM_THREADS] = 0
            self.field[PFC.F_LAST_PID] = 0

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
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 16
        self.skipped = "#"

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_SLAB_NAME } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_ACTIVE_OBJS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 2, FIELD_NAME: PFC.F_NUM_OBJS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 3, FIELD_NAME: PFC.F_OBJ_SIZE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 4, FIELD_NAME: PFC.F_OBJ_PER_SLAB, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 5, FIELD_NAME: PFC.F_PAGES_PER_SLAB, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 8, FIELD_NAME: PFC.F_LIMIT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 9, FIELD_NAME: PFC.F_BATCHCOUNT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 10, FIELD_NAME: PFC.F_SHARED, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 13, FIELD_NAME: PFC.F_ACTIVE_SLABS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 14, FIELD_NAME: PFC.F_NUM_SLABS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 15, FIELD_NAME: PFC.F_SHARED_AVAIL, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 18, FIELD_NAME: PFC.F_LIST_ALLOCS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 19, FIELD_NAME: PFC.F_MAX_OBJS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 20, FIELD_NAME: PFC.F_GROWN, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 21, FIELD_NAME: PFC.F_REAPED, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 22, FIELD_NAME: PFC.F_ERROR, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 23, FIELD_NAME: PFC.F_MAX_FREEABLE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 24, FIELD_NAME: PFC.F_NODE_ALLOCS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 25, FIELD_NAME: PFC.F_REMOTE_FREES, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 26, FIELD_NAME: PFC.F_ALIEN_OVERFLOW, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 29, FIELD_NAME: PFC.F_ALLOC_HIT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 30, FIELD_NAME: PFC.F_ALLOC_MISS, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 31, FIELD_NAME: PFC.F_FREE_HIT, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NUMBER: 32, FIELD_NAME: PFC.F_FREE_MISS, CONVERSION: long } )

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
        self.__NameBracket = "["
        self.__PrefixPages = "pages="
        self.__PrefixPhys = "phys="
        self.__FlagIOREMAP = "ioremap"
        self.__FlagVMALLOC = "vmalloc"
        self.__FlagVMAP = "vmap"
        self.__FlagUSERMAP = "user"
        self.__FlagVPAGES = "vpages"
        self.__PrefixNuma = "N"

        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_START, BEFORE_VAL: "-", PREFIX_VAL: "0x", CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NUMBER: 0, FIELD_NAME: PFC.F_END, AFTER_VAL: "-", PREFIX_VAL: "0x", CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NUMBER: 1, FIELD_NAME: PFC.F_SIZE, CONVERSION: long } )
        self.add_parse_rule( { FIELD_NAME: PFC.F_PAGES, PREFIX_VAL: "pages=", CONVERSION: long, NUM_BASE: 16 } )
        self.add_parse_rule( { FIELD_NAME: PFC.F_PHYS_ADDR, PREFIX_VAL: "phys=", CONVERSION: long, NUM_BASE: 16 } )

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

        self.field[PFC.F_CALLER] = ""
        self.field[PFC.F_VM_MAP] = 0
        self.field[PFC.F_USER_MAP] = 0
        self.field[PFC.F_VM_PAGES] = 0
        self.field[PFC.F_NUMA_INFO] = ""
        self.field[PFC.F_IOREMAP] = 0
        self.field[PFC.F_VM_ALLOC] = 0

        if sio.buff == "":
            self.field[PFC.F_START] = 0
            self.field[PFC.F_END] = 0
            self.field[PFC.F_SIZE] = 0
            self.field[PFC.F_PAGES] = 0
            self.field[PFC.F_PHYS_ADDR] = 0

        else:
            __off = 2
            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                if __check.startswith(self.__PrefixPages):
                    __flags = "{flags} {next}".format(flags=__flags, next=__check)
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
                if __check.startswith(self.__PrefixPages):
                    __flags = "{flags} {next}".format(flags=__flags, next=__check)
                    __off = __off + 1

            if sio.linewords > __off:
                __check = sio.lineparts[__off]
                if __check.startswith(self.__PrefixPhys):
                    __flags = "{flags} {next}".format(flags=__flags, next=__check)
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
# The kernel source snippets that generate this file are stored in
# "README.ProcNetHandlers" to reduce the size of this module.
#

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
