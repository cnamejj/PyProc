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
Handlers for files in the base /proc directory
"""

import ProcDataConstants
import ProcBaseRoutines
import ProcFieldConstants

PDC = ProcDataConstants
PBR = ProcBaseRoutines
PFC = ProcFieldConstants

NAME = PBR.FIELD_NAME
POS = PBR.FIELD_NUMBER
CONV = PBR.CONVERSION
ERRVAL = PBR.ERROR_VAL
BASE = PBR.NUM_BASE
PREFIX = PBR.PREFIX_VAL
SUFFIX = PBR.SUFFIX_VAL
BEFORE = PBR.BEFORE_VAL
AFTER = PBR.AFTER_VAL
WORDS = PBR.WORDS_VAL
PSUB = PBR.SUBWORD
HAS = PBR.HAS_VAL

REGISTER_FILE = PBR.register_file
REGISTER_PARTIAL_FILE = PBR.register_partial_file



# ---
class ProcRootEXECDOMAINS(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/execdomains"""
# source: kernel/exec_domain.c
#   for (ep = exec_domains; ep; ep = ep->next)
#           seq_printf(m, "%d-%d\t%-16s\t[%s]\n",
#                         ep->pers_low, ep->pers_high, ep->name,
#                          module_name(ep->module));

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PERSONALITY_LOW,
                BEFORE: "-", CONV: long } )
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_PERSONALITY_HIGH,
                AFTER: "-", CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_EXDOM_NAME } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_EXDOM_MODULE } )

        self.pers_low = 0
        self.pers_high = 0
        self.exdom_name = ""
        self.exdom_module = ""
        return

    def extra_next(self, sio):

# -- Sample records (the real file has no column headers, they are added to
#    clarify how the file is parsed)
#
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

        return(self.pers_low, self.pers_high, self.exdom_name,
               self.exdom_module)
#
REGISTER_FILE("/proc/execdomains", ProcRootEXECDOMAINS)
REGISTER_PARTIAL_FILE("execdomains", ProcRootEXECDOMAINS)



# ---
class ProcRootCGROUPS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SUBSYSTEM } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_HIERARCHY,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_NUM_CGROUPS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_ENABLED, CONV: long } )

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
        self.enabled = self.field[PFC.F_ENABLED]

        return(self.subsys, self.hierachy, self.cgroups, self.enabled)
#
REGISTER_FILE("/proc/cgroups", ProcRootCGROUPS)
REGISTER_PARTIAL_FILE("cgroups", ProcRootCGROUPS)



# ---
class ProcRootMTRR(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INDEX, PREFIX: "reg",
                SUFFIX: ":", CONV: long } )
#        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_BASE_MEMORY,
#                PREFIX: "base=0x", SUFFIX: "00000", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_BASE_MEMORY,
                PREFIX: "base=0x", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { NAME: PFC.F_COUNT, PREFIX: "count=",
                SUFFIX: ":", CONV: long } )

        self.index = 0
        self.base = 0
        self.size = 0
        self.count = 0
        self.type = ""
        self.__size_pref = "size="
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
            if sio.get_word(__offset) == self.__size_pref:
                __offset += 1
            elif not sio.get_word(__offset).startswith(self.__size_pref):
                __offset += 1
                if sio.get_word(__offset) == self.__size_pref:
                    __offset += 1
#            self.field[PFC.F_SIZE] = PBR.conv_by_rules(
#                    sio.get_word(__offset)[-8:], { CONV: long,
#                    SUFFIX: "MB," } )
            __size = sio.get_word(__offset).lstrip(self.__size_pref)

            if __size[-3:] == "MB,":
                __scale = 1024 * 1024
            else:
                __scale = 1024

            self.field[PFC.F_SIZE] = int(__size[:-3]) * __scale

            __offset += 2
            self.field[PFC.F_TYPE] = sio.get_word(__offset)

        self.index = self.field[PFC.F_INDEX]
        self.base = self.field[PFC.F_BASE_MEMORY]
        self.size = self.field[PFC.F_SIZE]
        self.count = self.field[PFC.F_COUNT]
        self.type = self.field[PFC.F_TYPE]

        return(self.index, self.base, self.size, self.count, self.type)
#
REGISTER_FILE("/proc/mtrr", ProcRootMTRR)
REGISTER_PARTIAL_FILE("mtrr", ProcRootMTRR)



# ---
class ProcRootMODULES(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/modules
    """

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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MODULE } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_REFCOUNT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SOURCE_LIST } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_STATUS } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_MODULE_CORE,
                PREFIX: "0x", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_TAINTS } )

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

        return(self.module, self.size, self.refcount, self.source_list,
                self.status, self.module_core, self.taints)
#
REGISTER_FILE("/proc/modules", ProcRootMODULES)
REGISTER_PARTIAL_FILE("modules", ProcRootMODULES)


# ---
class ProcRootBUDDYINFO(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/buddyinfo"""
# source: mm/vmstat.c
#
#        seq_printf(m, "Node %d, zone %8s ", pgdat->node_id, zone->name);
#        for (order = 0; order < MAX_ORDER; ++order)
#                seq_printf(m, "%6lu ", zone->free_area[order].nr_free);
#        seq_putc(m, '\n');

    def extra_init(self, *opts):
        self.minfields = 15

        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_NODE, SUFFIX: ",",
                    CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_ZONE } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_FRBL_AREA_1 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_FRBL_AREA_2 } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_FRBL_AREA_3 } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_FRBL_AREA_4 } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_FRBL_AREA_5 } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_FRBL_AREA_6 } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_FRBL_AREA_7 } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_FRBL_AREA_8 } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_FRBL_AREA_9 } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_FRBL_AREA_10 } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_FRBL_AREA_11 } )

        self.node = 0
        self.zone = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# pylint: disable=C0301
#
# Node 0, zone      DMA      1      0      1      0      1      1      1      0      1      1      3
# Node 0, zone    DMA32  18435  13755   5520    786      7      1      0      1      0      0      0
# Node 0, zone   Normal  36118   8165   6999    374      0      0      0      0      0      0      1
#
# pylint: enable=C0301

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
REGISTER_FILE("/proc/buddyinfo", ProcRootBUDDYINFO)
REGISTER_PARTIAL_FILE("buddyinfo", ProcRootBUDDYINFO)



# ---
class ProcRootSWAPS(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/swaps
    """

# source: mm/swapfile.c
#
# pylint: disable=C0301
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
# pylint: enable=C0301

    def extra_init(self, *opts):
        self.minfields = 5
        self.skipped = "Filename"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_FILENAME } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_TYPE } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_USED, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_PRIORITY, CONV: long } )

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
REGISTER_FILE("/proc/swaps", ProcRootSWAPS)
REGISTER_PARTIAL_FILE("swaps", ProcRootSWAPS)



# ---
class ProcRootLOCKS(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/locks"""
# source: fs/locks.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
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
        self.__skip_prefix = "->"
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
            self.field[PFC.F_INDEX] = PBR.conv_by_rules(sio.get_word(0),
                    { CONV: long, SUFFIX: ":" } )
            if sio.get_word(1) != self.__skip_prefix:
                __offset = 1
            else:
                __offset = 2
            self.field[PFC.F_LOCK_TYPE] = sio.get_word(__offset)
            __offset += 1
            self.field[PFC.F_LOCK_SUBTYPE] = sio.get_word(__offset)
            __offset += 1
            self.field[PFC.F_LOCK_IO] = sio.get_word(__offset)
            __offset += 1
            self.field[PFC.F_PID] = PBR.conv_by_rules(
                    sio.get_word(__offset), { CONV: long} )
            __offset += 1
            self.field[PFC.F_LOCK_INODE] = sio.get_word(__offset)
            __offset += 1
            self.field[PFC.F_START] = PBR.conv_by_rules(
                    sio.get_word(__offset), { CONV: long } )
            __offset += 1
            self.field[PFC.F_END_STRING] = sio.get_word(__offset)
            if self.field[PFC.F_END_STRING] == "EOF":
                self.field[PFC.F_END] = PDC.INF
            else:
                self.field[PFC.F_END] = PBR.conv_by_rules(
                        self.field[PFC.F_END_STRING], { CONV: long } )

        self.index = self.field[PFC.F_INDEX]
        self.locktype = self.field[PFC.F_LOCK_TYPE]
        self.subtype = self.field[PFC.F_LOCK_SUBTYPE]
        self.ioaction = self.field[PFC.F_LOCK_IO]
        self.pid = self.field[PFC.F_PID]
        self.start = self.field[PFC.F_START]
        self.end = self.field[PFC.F_END]

        return(self.index, self.locktype, self.subtype, self.ioaction,
                self.pid, self.start, self.end)
#
REGISTER_FILE("/proc/locks", ProcRootLOCKS)
REGISTER_PARTIAL_FILE("locks", ProcRootLOCKS)



# ---
class ProcRootDISKSTATS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MAJOR_DEV,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_MINOR_DEV,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_DISK_NAME } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_READ_IOS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_READ_MERGES,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_READ_SECTORS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_READ_MSECS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_WRITE_IOS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_WRITE_MERGES,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_WRITE_SECTORS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_WRITE_MSECS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_PART_IN_FLIGHT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_IO_MSECS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_QUEUE_TIME_MSECS,
                CONV: long } )

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
# pylint: disable=C0301
#
# 7       6 loop6 0 0 0 0 0 0 0 0 0 0 0
# 7       7 loop7 0 0 0 0 0 0 0 0 0 0 0
# 8       0 sda 15235018 10980568 3312891398 74957548 8362788 4577595 144647677 114936764 0 90848652 189870564
# 8       1 sda1 398 1129 4568 1424 1 0 1 0 0 800 1424
# 8       2 sda2 15185612 10961911 3312352646 74838696 7650568 4513340 143561212 103557888 0 79839900 178373748
#
# pylint: enable=C0301

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

        return(self.major_dev, self.minor_dev, self.disk_name, self.read_ios,
                self.read_merges, self.read_sectors, self.read_msecs,
                self.write_ios, self.write_merges, self.write_sectors,
                self.write_msecs, self.part_in_flight, self.io_msecs,
                self.queue_time_msecs)

#
REGISTER_FILE("/proc/diskstats", ProcRootDISKSTATS)
REGISTER_PARTIAL_FILE("diskstats", ProcRootDISKSTATS)



# ---
class ProcRootVMSTAT(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/vmstat"""
# source: mm/vmstat.c
#
#        unsigned long off = l - (unsigned long *)m->private;
#
#        seq_printf(m, "%s %lu\n", vmstat_text[off], *l);

    def extra_init(self, *opts):
        self.minfields = 2

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_CATEGORY } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_COUNT, CONV: long } )

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
REGISTER_FILE("/proc/vmstat", ProcRootVMSTAT)
REGISTER_PARTIAL_FILE("vmstat", ProcRootVMSTAT)



# ---
class ProcRootMEMINFO(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/meminfo"""
# source: fs/proc/meminfo.c
# --and--
# source: mm/hugetlb.c
# --and--
# source: arch/x86/mm/pageattr.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 2
        self.skipped = "Filename"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_CATEGORY } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_UNITS } )

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
REGISTER_FILE("/proc/meminfo", ProcRootMEMINFO)
REGISTER_PARTIAL_FILE("meminfo", ProcRootMEMINFO)



# ---
class ProcRootPARTITIONS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MAJOR_DEV,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_MINOR_DEV,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_BLOCKS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_PARTITION_NAME } )

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
REGISTER_FILE("/proc/partitions", ProcRootPARTITIONS)
REGISTER_PARTIAL_FILE("partitions", ProcRootPARTITIONS)



# ---
class ProcRootMISC(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/misc"""
# source: drivers/char/misc.c
#
#    const struct miscdevice *p = list_entry(v, struct miscdevice, list);
#
#    seq_printf(seq, "%3i %s\n", p->minor, p->name ? p->name : "");


    def extra_init(self, *opts):
        self.minfields = 2

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MINOR_DEV,
                CONV: long  } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEVICE  } )

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
REGISTER_FILE("/proc/misc", ProcRootMISC)
REGISTER_PARTIAL_FILE("misc", ProcRootMISC)



# ---
class ProcRootKALLSYMS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_ADDRESS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_TYPE } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_SYMBOL } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MODULE, PREFIX: "[",
                SUFFIX: "]" } )

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
REGISTER_FILE("/proc/kallsyms", ProcRootKALLSYMS)
REGISTER_PARTIAL_FILE("kallsyms", ProcRootKALLSYMS)



# ---
class ProcRootFILESYSTEMS(PBR.FixedWhitespaceDelimRecs):
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
                self.field[PFC.F_DEV_FLAG] = sio.get_word(0)
                self.field[PFC.F_FILESYSTEM] = sio.get_word(1)
            else:
                self.field[PFC.F_DEV_FLAG] = ""
                self.field[PFC.F_FILESYSTEM] = sio.get_word(0)

        self.dev_flag = self.field[PFC.F_DEV_FLAG]
        self.filesystem = self.field[PFC.F_FILESYSTEM]

        return(self.dev_flag, self.filesystem)

#
REGISTER_FILE("/proc/filesystems", ProcRootFILESYSTEMS)
REGISTER_PARTIAL_FILE("filesystems", ProcRootFILESYSTEMS)



# ---
class ProcRootDMA(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_CHANNEL, CONV: long,
                SUFFIX: ":" } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEVICE_NAME } )

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
REGISTER_FILE("/proc/dma", ProcRootDMA)
REGISTER_PARTIAL_FILE("dma", ProcRootDMA)



# ---
class ProcRootFB(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/fb"""
# source:
#
#        struct fb_info *fi = registered_fb[i];
#
#        if (fi)
#                seq_printf(m, "%d %s\n", fi->node, fi->fix.id);

    def extra_init(self, *opts):
        self.minfields = 2

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_NODE, CONV: long } )

        self.node = 0
        self.id_list = ""
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
        self.id_list = self.field[PFC.F_ID_LIST]

        return(self.node, self.id_list)

#
REGISTER_FILE("/proc/fb", ProcRootFB)
REGISTER_PARTIAL_FILE("fb", ProcRootFB)



# ---
class ProcRootCONSOLES(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_DEVICE_NAME } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_IO_TYPE } )

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
#            __subrec = " ".join(sio.lineparts[2:-1])
#            if __subrec[:1] == "(":
#                __subrec = __subrec[1:]
#            if __subrec[-1:] == ")":
#                __subrec = __subrec[:-1]
#            if __subrec[-1:] == " ":
#                __subrec = __subrec[:-1]
#            self.field[PFC.F_FLAGS] = __subrec
#            self.field[PFC.F_DEVICE_NUMBER] = sio.get_word(-1)
            __subrec = sio.buff[21:].rstrip("\n")
            __sp = __subrec.partition("(")
            self.field[PFC.F_IO_TYPE] = __sp[0].rstrip(" ")
            __sp = __sp[2].partition(")")
            self.field[PFC.F_FLAGS] = __sp[0]
            self.field[PFC.F_DEVICE_NUMBER] = __sp[2].lstrip(" ")

        self.device_name = self.field[PFC.F_DEVICE_NAME]
        self.io_type = self.field[PFC.F_IO_TYPE]
        self.flags = self.field[PFC.F_FLAGS]
        self.device_num = self.field[PFC.F_DEVICE_NUMBER]

        return(self.device_name, self.io_type, self.flags, self.device_num)

#
REGISTER_FILE("/proc/consoles", ProcRootCONSOLES)
REGISTER_PARTIAL_FILE("consoles", ProcRootCONSOLES)



# ---
class ProcRootKEYUSERS(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_UID, SUFFIX: ":",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_USAGE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_NKEYS, BEFORE: "/",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_NIKEYS, AFTER: "/",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_QNKEYS, BEFORE: "/",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MAXKEYS, AFTER: "/",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_QNBYTES, BEFORE: "/",
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_MAXBYTES, AFTER: "/",
                CONV: long } )

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

        return(self.uid, self.usage, self.nkeys, self.nikeys, self.qnkeys,
                self.maxkeys, self.qnbytes, self.maxbytes)

#
REGISTER_FILE("/proc/key-users", ProcRootKEYUSERS)
REGISTER_PARTIAL_FILE("key-users", ProcRootKEYUSERS)



# ---
class ProcRootVERSIONSIGNATURE(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/version_signature"""
# source:
#
#         seq_printf(m, "%s\n", CONFIG_VERSIONSIGNATURE);

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

        return self.version

#
REGISTER_FILE("/proc/version_signature", ProcRootVERSIONSIGNATURE)
REGISTER_PARTIAL_FILE("version_signature", ProcRootVERSIONSIGNATURE)



# ---
class ProcRootVERSION(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/version"""
# source: fs/proc/version.c
#
#        seq_printf(m, linux_proc_banner,
#                utsname()->sysname,
#                utsname()->release,
#                utsname()->version);

    def extra_init(self, *opts):
        self.minfields = 3

        self.full_string = ""
        self.sysname = ""
        self.release = ""
        self.version = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# pylint: disable=C0301
#
# Linux version 3.2.0-24-generic (buildd@crested) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #39-Ubuntu SMP Mon May 21 16:52:17 UTC 2012
#
# pylint: enable=C0301

        if sio.buff == "":
            self.field[PFC.F_VERSION_STRING] = ""
            self.field[PFC.F_SYSNAME] = ""
            self.field[PFC.F_RELEASE] = ""
            self.field[PFC.F_COMP_BY] = ""
            self.field[PFC.F_COMP_HOST] = ""
            self.field[PFC.F_COMPILER] = ""
            self.field[PFC.F_VERSION] = ""

        else:
            self.field[PFC.F_VERSION_STRING] = " ".join(sio.lineparts)
            if sio.linewords < 6:
                self.field[PFC.F_SYSNAME] = ""
                self.field[PFC.F_RELEASE] = ""
                self.field[PFC.F_COMP_BY] = ""
                self.field[PFC.F_COMP_HOST] = ""
                self.field[PFC.F_COMPILER] = ""
                self.field[PFC.F_VERSION] = ""
            else:
                __line = sio.buff.rstrip("\n")
                self.field[PFC.F_SYSNAME] = PBR.conv_by_rules(__line,
                        { BEFORE: " version " } )
                self.field[PFC.F_RELEASE] = PBR.conv_by_rules(__line,
                        { AFTER: " version ", BEFORE: " (" } )
                self.field[PFC.F_COMP_BY] = PBR.conv_by_rules(__line,
                        { AFTER: " (", BEFORE: "@" } )
                self.field[PFC.F_COMP_HOST] = PBR.conv_by_rules(__line,
                        { AFTER: "@", BEFORE: ") " } )
                __dbsp = "(".join(__line.split("(")[2:]).split(") ")
                self.field[PFC.F_COMPILER] = ") ".join(__dbsp[:-1])
                self.field[PFC.F_VERSION] = __dbsp[-1].lstrip(" ")

        self.full_string = self.field[PFC.F_VERSION_STRING]
        self.sysname = self.field[PFC.F_SYSNAME]
        self.release = self.field[PFC.F_RELEASE]
        self.version = self.field[PFC.F_VERSION]

        return(self.sysname, self.release, self.version, self.full_string)
#
REGISTER_FILE("/proc/version", ProcRootVERSION)
REGISTER_PARTIAL_FILE("version", ProcRootVERSION)



# ---
class ProcRootUPTIME(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_UPTIME, CONV: float } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_IDLE, CONV: float } )

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
REGISTER_FILE("/proc/uptime", ProcRootUPTIME)
REGISTER_PARTIAL_FILE("uptime", ProcRootUPTIME)



# ---
class ProcRootLOADAVG(PBR.FixedWhitespaceDelimRecs):
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

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_LOAD_AV0,
                CONV: float } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_LOAD_AV1,
                CONV: float } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_LOAD_AV2,
                CONV: float } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_NUM_TASKS, CONV: long,
                BEFORE: "/" } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_NUM_THREADS, CONV: long,
                AFTER: "/" } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_LAST_PID, CONV: long } )

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

        return(self.load0, self.load1, self.load2, self.running, self.threads,
                self.lastpid)
#
REGISTER_FILE("/proc/loadavg", ProcRootLOADAVG)
REGISTER_PARTIAL_FILE("loadavg", ProcRootLOADAVG)



# ---
class ProcRootCMDLINE(PBR.FixedWhitespaceDelimRecs):
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
# pylint: disable=C0301
#
# BOOT_IMAGE=/vmlinuz-3.2.0-24-generic root=UUID=a959862a-84b7-4373-b7d6-954ac9005249 ro quiet splash vt.handoff=7
#
# pylint: enable=C0301

        self.field[PFC.F_CMDLINE] = sio.buff.rstrip("\n")

        self.cmdline = self.field[PFC.F_CMDLINE]

        return self.cmdline
#
REGISTER_FILE("/proc/cmdline", ProcRootCMDLINE)



# ---
class ProcRootSLABINFO(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/slabinfo"""
# source: mm/slub.c
# --and--
# source: mm/slab.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 16
        self.skipped = "#"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SLAB_NAME } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ACTIVE_OBJS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_NUM_OBJS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_OBJ_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_OBJ_PER_SLAB,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_PAGES_PER_SLAB,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_LIMIT, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_BATCHCOUNT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_SHARED, CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_ACTIVE_SLABS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_NUM_SLABS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_SHARED_AVAIL,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 18, NAME: PFC.F_LIST_ALLOCS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 19, NAME: PFC.F_MAX_OBJS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 20, NAME: PFC.F_GROWN, CONV: long } )
        PBR.add_parse_rule(self, { POS: 21, NAME: PFC.F_REAPED, CONV: long } )
        PBR.add_parse_rule(self, { POS: 22, NAME: PFC.F_ERROR, CONV: long } )
        PBR.add_parse_rule(self, { POS: 23, NAME: PFC.F_MAX_FREEABLE,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 24, NAME: PFC.F_NODE_ALLOCS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 25, NAME: PFC.F_REMOTE_FREES,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 26, NAME: PFC.F_ALIEN_OVERFLOW,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 29, NAME: PFC.F_ALLOC_HIT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 30, NAME: PFC.F_ALLOC_MISS,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 31, NAME: PFC.F_FREE_HIT,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 32, NAME: PFC.F_FREE_MISS,
                CONV: long } )

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
# pylint: disable=C0301
#
# slabinfo - version: 2.1
# # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
# fat_inode_cache      216    216    672   24    4 : tunables    0    0    0 : slabdata      9      9      0
# fat_cache            714    714     40  102    1 : tunables    0    0    0 : slabdata      7      7      0
# nf_conntrack_expect      0      0    240   34    2 : tunables    0    0    0 : slabdata      0      0      0
#
# pylint: enable=C0301

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

        return(self.slab, self.act_objs, self.num_objs, self.obj_size,
                self.obj_per_slab, self.pages_per_slab, self.limit,
                self.batchcount, self.shared, self.act_slabs, self.num_slabs,
                self.shared_avail)
#
REGISTER_FILE("/proc/slabinfo", ProcRootSLABINFO)
REGISTER_PARTIAL_FILE("slabinfo", ProcRootSLABINFO)



# ---
class ProcRootVMALLOCINFO(PBR.FixedWhitespaceDelimRecs):
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
        self.__name_bracket = "["
        self.__prefix_pages = "pages="
        self.__prefix_phys = "phys="
        self.__flag_ioremap = "ioremap"
        self.__flag_vmalloc = "vmalloc"
        self.__flag_vmap = "vmap"
        self.__flag_usermap = "user"
        self.__flag_vpages = "vpages"
        self.__prefix_numa = "N"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_START, BEFORE: "-",
                PREFIX: "0x", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_END, AFTER: "-",
                PREFIX: "0x", CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { NAME: PFC.F_PAGES, PREFIX: "pages=",
                CONV: long, BASE: 16 } )
        PBR.add_parse_rule(self, { NAME: PFC.F_PHYS_ADDR, PREFIX: "phys=",
                CONV: long, BASE: 16 } )

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
# pylint: disable=C0301
#
# 0xffffc900100c0000-0xffffc900100e1000  135168 e1000_probe+0x21b/0xa0b [e1000e] phys=fbf00000 ioremap
# 0xffffc900100e1000-0xffffc900100ea000   36864 xt_alloc_table_info+0xda/0x10e [x_tables] pages=8 vmalloc N0=8
# 0xffffc900100ea000-0xffffc900100f3000   36864 xt_alloc_table_info+0xda/0x10e [x_tables] pages=8 vmalloc N0=8
# 0xffffc900100fb000-0xffffc90010100000   20480 swap_cgroup_swapon+0x60/0x170 pages=4 vmalloc N0=4
# 0xffffc90010100000-0xffffc90011101000 16781312 efi_ioremap+0x1a/0x57 phys=ff000000 ioremap
# 0xffffc90011101000-0xffffc90013102000 33558528 alloc_large_system_hash+0x14b/0x215 pages=8192 vmalloc vpages N0=8192
#
# pylint: enable=C0301

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
            __check = sio.get_word(__off)
            if __check.startswith(self.__prefix_pages):
                __flags = "{flags} {next}".format(flags=__flags,
                        next=__check)
            else:
                self.field[PFC.F_CALLER] = __check
            __off += 1

            __check = sio.get_word(__off)
            if __check[0:1] == self.__name_bracket:
                self.field[PFC.F_CALLER] = "{base} {qual}".format(
                        base=self.field[PFC.F_CALLER], qual=__check)
                __off += 1

            __check = sio.get_word(__off)
            if __check.startswith(self.__prefix_pages):
                __flags = "{flags} {next}".format(flags=__flags,
                        next=__check)
                __off += 1

            __check = sio.get_word(__off)
            if __check.startswith(self.__prefix_phys):
                __flags = "{flags} {next}".format(flags=__flags,
                        next=__check)
                __off += 1

            if sio.get_word(__off) == self.__flag_ioremap:
                self.field[PFC.F_IOREMAP] = 1
                __flags = "{flags} {next}".format(flags=__flags,
                        next=sio.get_word(__off))
                __off += 1

            if sio.get_word(__off) == self.__flag_vmalloc:
                self.field[PFC.F_VM_ALLOC] = 1
                __flags = "{flags} {next}".format(flags=__flags,
                        next=sio.get_word(__off))
                __off += 1

            if sio.get_word(__off) == self.__flag_vmap:
                self.field[PFC.F_VM_MAP] = 1
                __flags = "{flags} {next}".format(flags=__flags,
                        next=sio.get_word(__off))
                __off += 1

            if sio.get_word(__off) == self.__flag_usermap:
                self.field[PFC.F_USER_MAP] = 1
                __flags = "{flags} {next}".format(flags=__flags,
                        next=sio.get_word(__off))
                __off += 1

            if sio.get_word(__off) == self.__flag_vpages:
                self.field[PFC.F_VM_PAGES] = 1
                __flags = "{flags} {next}".format(flags=__flags,
                        next=sio.get_word(__off))
                __off += 1

            for __rest in range(__off, sio.linewords):
                __check = sio.get_word(__rest)
                if __check[0:1] == self.__prefix_numa:
                    __numa = "{curr} {app}".format(curr=__numa, app=__check)
                else:
                    __invalid = "{curr} {app}".format(curr=__invalid,
                            app=__check)

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

        return(self.start_addr, self.end_addr, self.size, self.caller,
                self.flags, self.numa)
#
REGISTER_FILE("/proc/vmallocinfo", ProcRootVMALLOCINFO)
REGISTER_PARTIAL_FILE("vmallocinfo", ProcRootVMALLOCINFO)


# pylint: disable=R0902
#
# ---
class ProcRootMDSTAT(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/mdstat"""
# source: drivers/md/raid10.c
# --and--
# source: drivers/md/md.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.__min_words_first = 1
        self.__min_words_second = 0
        self.minfields = self.__min_words_first

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
        self.parse_map = dict()
        self.parse_order = dict()
        self.parse_seq = 0
        self.partition_order = []

        self.__rec_personality = "Personalities"
        self.__rec_unused = "unused"
        self.__readonly_flag = "(read-only)"
        self.__autoreadonly_flag = "(auto-read-only)"
        self.__super_flag = "super"
        self.__chunk_flag = "chunks"
        self.__near_copy_flag = "near-copies"
        self.__offset_copy_flag = "offset-copies"
        self.__far_copy_flag = "far-copies"
        self.__open_list = "["
        self.__close_list = "]"
        self.__open_npair = "("
        self.__close_npair = ")"
        self.__pc_end = "%"
        self.__num_split = "/"
        self.__used_y = "U"
        self.__used_n = "_"
        self.__block_flag = "blocks"
        self.__bitmap_flag = "bitmap:"
        self.__resync_flag = "resync"
        self.__resync_delim = "="
        self.__value_pref = "="
        self.__finish_suff = "min"
        self.__speed_suff = "K/sec"
        self.__pages_pref = "["
        self.__pages_suff = "KB],"
        self.__kb_suff = "KB"
        self.__b_suff = "B"
        self.__path_pref = "file:"
        self.__info_delim = "("
        self.__dev_delim = "["
        self.__wrmostly_flag = "W"
        self.__faulty_flag = "F"
        self.__spare_flag = "S"
        self.__k_suff = "K"
        return

    def append_parse_res(self, name):
        """Record order in which fields are parsed"""

        if not self.parse_map.has_key(name):
            self.parse_map[name] = self.parse_seq
            self.parse_order[self.parse_seq] = name
            self.parse_seq += 1

        return

    def parse_personality_record(self, sio):
        """Parse list of disk personalities on the system"""

        self.append_parse_res(PFC.F_PERSONALITIES)
        if sio.linewords > 1:
            self.field[PFC.F_PERSONALITIES] = sio.lineparts[2:]
        else:
            self.field[PFC.F_PERSONALITIES] = []
        return

    def parse_unused_record(self, sio):
        """Parse unused device records"""

        self.append_parse_res(PFC.F_DEVICE_LIST)
        if sio.linewords > 1:
            self.field[PFC.F_DEVICE_LIST] = sio.lineparts[2:]
        else:
            self.field[PFC.F_DEVICE_LIST] = []
        return

# Ex:   bitmap: 12/12 pages [48KB], 65536KB chunk
    def parse_bitmap_subrec(self, sio):
        """Parse bitmap subrecord"""

        self.append_parse_res(PFC.F_PAGES_NOMISS)
        self.field[PFC.F_PAGES_NOMISS] = PBR.conv_by_rules(sio.get_word(1),
                { CONV: long, BEFORE: self.__num_split } )
        self.append_parse_res(PFC.F_PAGES_TOTAL)
        self.field[PFC.F_PAGES_TOTAL] = PBR.conv_by_rules(sio.get_word(1),
                { CONV: long, AFTER: self.__num_split } )

        self.append_parse_res(PFC.F_PAGES_NOMISS_KB)
        self.field[PFC.F_PAGES_NOMISS_KB] = PBR.conv_by_rules(
                sio.get_word(3), { CONV: long, SUFFIX: self.__pages_suff,
                PREFIX: self.__pages_pref } )

        self.append_parse_res(PFC.F_BITMAP_CHUNK)
        self.append_parse_res(PFC.F_BITMAP_CHUNK_TUNITS)
        __curr = sio.get_word(4)
        if __curr.endswith(self.__kb_suff):
            self.field[PFC.F_BITMAP_CHUNK] = PBR.conv_by_rules(__curr,
                    { CONV: long, SUFFIX: self.__kb_suff } )
            self.field[PFC.F_BITMAP_CHUNK] *= 1024
            self.field[PFC.F_BITMAP_CHUNK_TUNITS] = self.__kb_suff
        else:
            self.field[PFC.F_BITMAP_CHUNK] = PBR.conv_by_rules(__curr,
                    { CONV: long, SUFFIX: self.__b_suff } )
            self.field[PFC.F_BITMAP_CHUNK_TUNITS] = self.__b_suff

        if sio.linewords >= 7:
            __curr = " ".join(sio.lineparts[6:])
            if __curr.startswith(self.__path_pref):
                __curr = __curr[len(self.__path_pref):]

            if __curr[:1] == " ":
                __curr = __curr[1:]
            self.append_parse_res(PFC.F_FILEPATH)
            self.field[PFC.F_FILEPATH] = __curr

        return

# Ex: resync=DELAYED
    def parse_resync_subrec(self, sio):
        """Parse a summary subrec with just a resync status"""

        __curr = sio.get_word(0)

        self.append_parse_res(PFC.F_RESYNC_STAT)
        self.field[PFC.F_RESYNC_STAT] = __curr.partition(self.__resync_delim)[2]

# pylint: disable=C0301
#
# Ex: [===>.................]  recovery = 19.1% (299892800/1564531200) finish=84.0min speed=250770K/sec
#
# pylint: enable=C0301
    def parse_rebuild_subrec(self, sio):
        """Parse rebuild status indicator info"""

        __curr = sio.get_word(0)

        self.append_parse_res(PFC.F_REBUILD_PROG)
        self.field[PFC.F_REBUILD_PROG] = sio.get_word(0)
        self.append_parse_res(PFC.F_REBUILD_ACTION)
        self.field[PFC.F_REBUILD_ACTION] = sio.get_word(1)

        __off = 2
        if sio.get_word(__off) == self.__value_pref:
            __off += 1
            __curr = sio.get_word(__off)
        else:
            __curr = sio.get_word(__off)[1:]
        self.append_parse_res(PFC.F_PERCENT)
        self.field[PFC.F_PERCENT] = PBR.conv_by_rules(__curr,
                { CONV: float, SUFFIX: self.__pc_end } )

        self.append_parse_res(PFC.F_REBUILD_DONE)
        __off += 1
        self.field[PFC.F_REBUILD_DONE] = PBR.conv_by_rules(
                sio.get_word(__off),
                { CONV: long, PREFIX: self.__open_npair,
                  BEFORE: self.__num_split } )
        self.append_parse_res(PFC.F_REBUILD_TOTAL)
        self.field[PFC.F_REBUILD_TOTAL] = PBR.conv_by_rules(
                sio.get_word(__off),
                { CONV: long, SUFFIX: self.__close_npair,
                  AFTER: self.__num_split } )

        self.append_parse_res(PFC.F_FIN_TIME)
        __off += 1
        self.field[PFC.F_FIN_TIME] = PBR.conv_by_rules(
                sio.get_word(__off), { CONV: float,
                AFTER: self.__value_pref,
                SUFFIX: self.__finish_suff } )

        self.append_parse_res(PFC.F_SPEED)
        __off += 1
        self.field[PFC.F_SPEED] = PBR.conv_by_rules(sio.get_word(__off),
                { CONV: long, AFTER: self.__value_pref,
                SUFFIX: self.__speed_suff } )
        return

# Ex:   1564531200 blocks super 1.1 2 near-copies [2/1] [_U]
    def parse_blocks_subrec(self, sio):
        """Parse device specific subrecord with block level info"""

        self.append_parse_res(PFC.F_BLOCKS)
        self.field[PFC.F_BLOCKS] = PBR.conv_by_rules(sio.get_word(0),
                { CONV: long } )
        __off = 2

        if sio.get_word(__off) == self.__super_flag:
            self.append_parse_res(PFC.F_SUPER)
            self.field[PFC.F_SUPER] = sio.get_word(__off + 1)
            __off += 2

        if sio.get_word(__off + 1) == self.__chunk_flag:
            self.append_parse_res(PFC.F_CHUNK)
            self.field[PFC.F_CHUNK] = PBR.conv_by_rules(sio.get_word(__off),
                    { CONV: long, SUFFIX: self.__k_suff } )
            __off += 2

        if sio.get_word(__off + 1) == self.__near_copy_flag:
            self.append_parse_res(PFC.F_NEAR_COPY)
            self.field[PFC.F_NEAR_COPY] = PBR.conv_by_rules(
                    sio.get_word(__off), { CONV: long } )
            __off += 2

        if sio.get_word(__off + 1) == self.__offset_copy_flag:
            self.append_parse_res(PFC.F_OFFSET_COPY)
            self.field[PFC.F_OFFSET_COPY] = PBR.conv_by_rules(
                    sio.get_word(__off), { CONV: long } )
            __off += 2

        if sio.get_word(__off + 1) == self.__far_copy_flag:
            self.append_parse_res(PFC.F_FAR_COPY)
            self.field[PFC.F_FAR_COPY] = PBR.conv_by_rules(
                    sio.get_word(__off), { CONV: long } )
            __off += 2

        self.append_parse_res(PFC.F_TOTAL_PARTS)
        __curr = sio.get_word(__off)
        self.field[PFC.F_TOTAL_PARTS] = PBR.conv_by_rules(__curr,
                { CONV: long, PREFIX: self.__open_list,
                  SUFFIX: self.__close_list,
                  BEFORE: self.__num_split } )
        self.append_parse_res(PFC.F_ACTIVE_PARTS)
        self.field[PFC.F_ACTIVE_PARTS] = PBR.conv_by_rules(__curr,
                { CONV: long, PREFIX: self.__open_list,
                  SUFFIX: self.__close_list, AFTER: self.__num_split } )

        self.append_parse_res(PFC.F_PART_USEMAP)
        __off += 1
        __curr = sio.get_word(__off)
        if __curr[1:2] == self.__used_y or __curr[1:2] == self.__used_n:
            self.field[PFC.F_PART_USEMAP] = __curr
        else:
            self.field[PFC.F_PART_USEMAP] = ""

        return

    def parse_partition_list(self, rawlist):
        """Parse the list of partitions"""

        __dplist = rawlist.split(" ")
        __partmap = dict()
        __wrmostly = dict()
        __faulty = dict()
        __spare = dict()
        __order = []

        for __devinfo in __dplist:
            __bits = __devinfo.split(self.__info_delim)
            __split = __bits[0].partition(self.__dev_delim)
            __pnum = long(__split[2][:-1])

            __order.append(__pnum)
            __partmap[__pnum] = __split[0]
            __wrmostly[__pnum] = 0
            __faulty[__pnum] = 0
            __spare[__pnum] = 0

            for __flag in __bits[1:]:
                __flag = __flag[:-1]
                if __flag == self.__wrmostly_flag:
                    __wrmostly[__pnum] = 1
                elif __flag == self.__faulty_flag:
                    __faulty[__pnum] = 1
                elif __flag == self.__spare_flag:
                    __spare[__pnum] = 1

        self.partition_order = __order
        self.append_parse_res(PFC.F_PARTITION_LIST)
        self.field[PFC.F_PARTITION_LIST] = __partmap
        self.append_parse_res(PFC.F_WRMOSTLY_LIST)
        self.field[PFC.F_WRMOSTLY_LIST] = __wrmostly
        self.append_parse_res(PFC.F_FAULTY_LIST)
        self.field[PFC.F_FAULTY_LIST] = __faulty
        self.append_parse_res(PFC.F_SPARE_LIST)
        self.field[PFC.F_SPARE_LIST] = __spare
        return

    def parse_mddev_record(self, sio):
        """Parse device specific record"""

        self.append_parse_res(PFC.F_ACTIVE_STAT)
        __active_stat = sio.get_word(2)
        self.field[PFC.F_ACTIVE_STAT] = __active_stat
        __off = 3
        if sio.get_word(__off) == self.__readonly_flag:
            self.append_parse_res(PFC.F_READONLY)
            self.field[PFC.F_READONLY] = 1
            __off += 1
        if sio.get_word(__off) == self.__autoreadonly_flag:
            self.append_parse_res(PFC.F_READONLY)
            self.field[PFC.F_READONLY] = 2
            __off += 1
        self.append_parse_res(PFC.F_PERS_NAME)
        if __active_stat == PDC.INACTIVE_STATE:
            self.field[PFC.F_PERS_NAME] = PDC.NO_STATUS_AVAILABLE
        else:
            self.field[PFC.F_PERS_NAME] = sio.get_word(__off)
            __off += 1
        self.parse_partition_list(" ".join(sio.lineparts[__off:]))

        sio.min_words = self.__min_words_second
        sio.read_line()
        for __subrec in range(3):
            if sio.linewords > 0:
                __keyfield = sio.get_word(0)
                if sio.get_word(1) == self.__block_flag:
                    self.parse_blocks_subrec(sio)
                elif __keyfield[:1] == self.__open_list:
                    self.parse_rebuild_subrec(sio)
                elif __keyfield.startswith(self.__resync_flag):
                    self.parse_resync_subrec(sio)
                elif __keyfield == self.__bitmap_flag:
                    self.parse_bitmap_subrec(sio)
                sio.read_line()
        sio.min_words = self.__min_words_first
        return

    def extra_next(self, sio):

# -- Sample records #1
#
# pylint: disable=C0301
#
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
#
# pylint: enable=C0301


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

        self.parse_order = dict()
        self.parse_map = dict()
        self.parse_seq = 0

        if sio.buff != "":
            __rec = sio.get_word(0)
            self.field[PFC.F_REC_TYPE] = __rec
            self.append_parse_res(PFC.F_REC_TYPE)

            if __rec == self.__rec_personality:
                self.parse_personality_record(sio)

            elif __rec == self.__rec_unused:
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

        return(self.rec_type, self.personalities, self.device_list,
                self.active_stat, self.pers_name, self.partition_list,
                self.wrmostly_list, self.faulty_list, self.spare_list,
                self.readonly, self.blocks, self.super, self.chunk,
                self.nearcopy, self.offsetcopy, self.farcopy, self.activeparts,
                self.totalparts, self.part_usemap, self.rebuild_prog,
                self.resync_stat, self.rebuild_act, self.percent,
                self.rebuild_done, self.rebuild_total, self.finish, self.speed,
                self.nomiss_pages, self.total_pages, self.nomiss_pages_kb,
                self.bitmap_chunk, self.bitmap_file)
#
REGISTER_FILE("/proc/mdstat", ProcRootMDSTAT)
REGISTER_PARTIAL_FILE("mdstat", ProcRootMDSTAT)

# pylint: enable=R0902



# ---
class ProcRootMOUNTS(PBR.FixedWhitespaceDelimRecs):
    """Pull records from /proc/mounts"""
# source: fs/namespace.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
        self.minfields = 6

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_MOUNT_SRC } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_MOUNT_FS } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_FSTYPE } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_MOUNT_OPTS } )

        self.mnt_source = ""
        self.mount_fs = ""
        self.fstype = ""
        self.mnt_options = ""
        return

    def extra_next(self, sio):

# -- Sample records
#
# rootfs / rootfs rw 0 0
# sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
# proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
# none /sys/fs/fuse/connections fusectl rw,relatime 0 0
# rpc_pipefs /run/rpc_pipefs rpc_pipefs rw,relatime 0 0

        self.mnt_source = self.field[PFC.F_MOUNT_SRC]
        self.mount_fs = self.field[PFC.F_MOUNT_FS]
        self.fstype = self.field[PFC.F_FSTYPE]
        self.mnt_options = self.field[PFC.F_MOUNT_OPTS]

        return(self.mnt_source, self.mount_fs, self.fstype, self.mnt_options)
#
REGISTER_FILE("/proc/mounts", ProcRootMOUNTS)
REGISTER_PARTIAL_FILE("mounts", ProcRootMOUNTS)




#
class ProcRootSOFTIRQS(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/softirq matrix of softirq counts per CPU
    """

# source: fs/proc/softirqs.c
#
# Excerpt from that code:
#
#static int show_softirqs(struct seq_file *p, void *v)
#{
#        int i, j;
#
#        seq_puts(p, "                    ");
#        for_each_possible_cpu(i)
#                seq_printf(p, "CPU%-8d", i);
#        seq_putc(p, '\n');
#
#        for (i = 0; i < NR_SOFTIRQS; i++) {
#                seq_printf(p, "%12s:", softirq_to_name[i]);
#                for_each_possible_cpu(j)
#                        seq_printf(p, " %10u", kstat_softirqs_cpu(i, j));
#                seq_putc(p, '\n');
#        }
#        return 0;
#}

    def extra_init(self, *opts):
        self.minfields = 1
        return

    def extra_next(self, sio):
#
# -- Sample records
#              CPU0       CPU1       CPU2       CPU3
#    HI:          0          0          0          0
# TIMER:  284022609  287940296  327374992  337143936
#NET_TX:       4142        158     520084         98

        if sio.buff != "":
            __irq_order = dict()
            __cpu_order = dict()
            __cpus = dict()
            __seq = 0
            for __col in range(0, sio.linewords):
                __cpus[__col+1] = sio.get_word(__col)
                __cpu_order[str(__col)] = sio.get_word(__col)

            try:
                while sio.read_line():
                    __irq = sio.get_word(0)[:-1]
                    __irq_order[str(__seq)] = __irq
                    __seq += 1
                    __clist = dict()
                    for __col in range(1, sio.linewords):
                        __clist[__cpus[__col]] = PBR.conv_by_rules(
                                sio.get_word(__col), { CONV: long } )
                    self.field[__irq] = __clist

            except StopIteration:
                pass

            self.field[PFC.F_CPU_ORDER] = __cpu_order
            self.field[PFC.F_IRQ_ORDER] = __irq_order

        return self.field

REGISTER_FILE("/proc/softirqs", ProcRootSOFTIRQS)
REGISTER_PARTIAL_FILE("softirqs", ProcRootSOFTIRQS)




#
class ProcRootSTAT(PBR.TaggedMultiLineFile):
    """
    Parse /proc/stats dump of summary system stats
    """

# source: fs/proc/stat.c
#
# Excerpt from that code:
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
        self.minfields = 2

        self.__list_of_longs = set( [PFC.F_SS_CPU, PFC.F_SS_INTR,
                PFC.F_SS_SOFTIRQ] )

        self.__pref_cpu = "cpu"

        self.__intr_summ = "total"

        self.__cpu_plist = dict()
        self.__cpu_plist[0] = "user"
        self.__cpu_plist[1] = "nice"
        self.__cpu_plist[2] = "sys"
        self.__cpu_plist[3] = "idle"
        self.__cpu_plist[4] = "iowait"
        self.__cpu_plist[5] = "irq"
        self.__cpu_plist[6] = "softirq"
        self.__cpu_plist[7] = "steal"
        self.__cpu_plist[8] = "guest"
        self.__cpu_plist[9] = "guest-nice"

        PBR.add_parse_rule(self, { PREFIX: "cpu ", NAME: PFC.F_SS_CPU } )
        PBR.add_parse_rule(self, { PREFIX: "intr ", NAME: PFC.F_SS_INTR } )
        PBR.add_parse_rule(self, { PREFIX: "ctxt ", NAME: PFC.F_SS_CTXT,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "btime ", NAME: PFC.F_SS_BTIME,
                CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "processes ",
                NAME: PFC.F_SS_PROCS_TOT, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "procs_running ",
                NAME: PFC.F_SS_PROCS_RUN, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "procs_blocked ",
                NAME: PFC.F_SS_PROCS_BLOCK, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "softirq ",
                NAME: PFC.F_SS_SOFTIRQ } )

        self.add_eor_rule( "softirq", { BEFORE: " " } )

        return

    def longs_to_cpu_ss(self, long_list):
        """Map a list of longs to a cpu summary stats dict"""

        __res = dict()

        for __off in range(0, len(self.__cpu_plist)):
            try:
                __res[self.__cpu_plist[__off]] = long_list[__off]
            except KeyError:
                __res[self.__cpu_plist[__off]] = 0

        return __res


    def longs_to_intr_ss(self, long_list):
        """Map a list of longs to an interrrupt summary stats dict"""

        __res = { self.__intr_summ: long_list[0] }

        for __off in range(1, len(long_list)):
            __res[__off-1] = long_list[__off]

        return __res


    def extra_next(self, sio):

# -- Sample records
#
#cpu  16227660 208781 5386332 2170952533 2218674 305 55746 7 8 9
#cpu0 3306208 42619 664552 269205678 875412 293 49809 0 0 0
#cpu1 3331254 31567 818902 269027267 1086491 9 802 0 0 0
#ctxt 2418647143
#btime 1390806357
#processes 4128591

        for __subrec in sorted(self.unused_recs):
            __key = self.unused_recs[__subrec].partition(" ")
            if __key[0].startswith(self.__pref_cpu):
                self.__list_of_longs.add(__key[0])
                self.field[__key[0]] = __key[2]

        for __key in self.__list_of_longs:
            __raw = self.field[__key].strip().split(" ")
            __conv = PBR.array_of_longs(__raw)

            if __key == PFC.F_SS_CPU or __key.startswith(self.__pref_cpu):
                self.field[__key] = self.longs_to_cpu_ss(__conv)
            elif __key == PFC.F_SS_INTR:
                self.field[__key] = self.longs_to_intr_ss(__conv)
            else:
                self.field[__key] = __conv

        return self.field

REGISTER_FILE("/proc/stat", ProcRootSTAT)
REGISTER_PARTIAL_FILE("pr/stat", ProcRootSTAT)




#
class ProcRootINTERRUPTS(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/interrupts matrix of per-CPU interrup counts
    """

# source: kernel/irq/proc.c (primary)
#
# There quite a few other routines in the kernel that provide some
# of the contents of the file.  See the README file for the complete
# list.
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 1

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_INTERRUPT,
                SUFFIX: ":" } )

        self.__summ_only = set( ["ERR", "MIS"] )
        self.__pref_cpu = "CPU"
        self.__no_desc = "N/A"
        self.__cpu_list = dict()
        self.__num_cpus = 0
        self.__cpu_wid = 11
        self.__padding = 3
        self.__col1_wid = 0
        self.__col1_delim = ":"

        return


    def extra_next(self, sio):

# -- Sample records
#
# pylint: disable=C0301
#
#          CPU0       CPU1       CPU2       CPU3
# 0:        132          0          0          0   IO-APIC-edge      timer
# 1:          1          1          0          1   IO-APIC-edge      i8042
# 8:          1          0          0          0   IO-APIC-edge      rtc0
# 9:          0          0          0          0   IO-APIC-fasteoi   acpi
#16:          5          5    5591774    4662973   IO-APIC-fasteoi   ahci, uhci_hcd:usb3, nouveau
#
# pylint: enable=C0301

        if self.__num_cpus == 0:
            self.__num_cpus = sio.linewords
            for __off in range(0, self.__num_cpus):
                self.__cpu_list[__off] = sio.get_word(__off)
            self.next()

        else:
            if self.__col1_wid == 0:
                self.__col1_wid = sio.buff.index(self.__col1_delim)

            if self.field[PFC.F_INTERRUPT] in self.__summ_only:
                try:
                    __total = long(sio.get_word(1))
                except ValueError:
                    __total = 0

                __pci = dict()
                for __off in range(0, self.__num_cpus):
                    __pci[self.__cpu_list[__off]] = 0

                self.field[PFC.F_TOT_COUNT] = __total
                self.field[PFC.F_COUNT] = __pci
                self.field[PFC.F_INTERRUPT_DESC] = self.__no_desc
                self.field[PFC.F_COL1_WIDTH] = self.__col1_wid

            else:
                __cl = self.__cpu_list
                __pci = dict()
                __total = 0

                for __off in range(0, self.__num_cpus):
                    try:
                        __conv = long(sio.get_word(__off+1))
                        __total += __conv
                    except ValueError:
                        __conv = 0
                    __pci[__cl[__off]] = __conv

                self.field[PFC.F_COUNT] = __pci
                self.field[PFC.F_TOT_COUNT] = __total
                self.field[PFC.F_COL1_WIDTH] = self.__col1_wid
#                __rest = sio.lineparts[self.__num_cpus+1:]
#                self.field[PFC.F_INTERRUPT_DESC] = " ".join(__rest)
                __rest = self.__col1_wid + (self.__num_cpus * self.__cpu_wid) \
                        + self.__padding
                self.field[PFC.F_INTERRUPT_DESC] = \
                        sio.buff[__rest:].rstrip("\n")

        return self.field

REGISTER_FILE("/proc/interrupts", ProcRootINTERRUPTS)
REGISTER_PARTIAL_FILE("interrupts", ProcRootINTERRUPTS)




#
class ProcRootZONEINFO(PBR.TaggedMultiLineFile):
    """
    Parse /proc/zoneinfo file
    """

# source: mm/vmstat.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 2

        self.__cpu_pref = "cpu:"
        self.__count_pref = "count:"
        self.__high_pref = "high:"
        self.__batch_pref = "batch:"
        self.__vm_stats_pref = "vm stats"
        self.__count_key = "count"
        self.__high_key = "high"
        self.__batch_key = "batch"
        self.__vm_stats_key = "vm-stats-thresh"

        PBR.add_parse_rule(self, { PREFIX: "Node", BEFORE: ",",
                CONV: long, NAME: PFC.F_NODE } )
        PBR.add_parse_rule(self, { PREFIX: "Node", AFTER: " zone ",
                NAME: PFC.F_ZONE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " pages free ",
                CONV: long, NAME: PFC.F_PAGES_FREE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " min ",
                CONV: long, NAME: PFC.F_PAGES_MIN } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " low ",
                CONV: long, NAME: PFC.F_PAGES_LOW } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " high ",
                CONV: long, NAME: PFC.F_PAGES_HIGH } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " scanned ",
                CONV: long, NAME: PFC.F_PAGES_SCANNED } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " spanned ",
                CONV: long, NAME: PFC.F_PAGES_SPANNED } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " present ",
                CONV: long, NAME: PFC.F_PAGES_PRESENT } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " managed ",
                CONV: long, NAME: PFC.F_PAGES_MANAGED } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_free_pages ",
                CONV: long, NAME: PFC.F_NR_FREE_PAGES } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_alloc_batch ",
                CONV: long, NAME: PFC.F_NR_ALLOC_BATCH } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_inactive_anon ",
                CONV: long, NAME: PFC.F_NR_INACTIVE_ANON } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_active_anon ",
		CONV: long, NAME: PFC.F_NR_ACTIVE_ANON } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_inactive_file ",
		CONV: long, NAME: PFC.F_NR_INACTIVE_FILE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_active_file ",
		CONV: long, NAME: PFC.F_NR_ACTIVE_FILE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_unevictable ",
		CONV: long, NAME: PFC.F_NR_UNEVICTABLE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_mlock ",
		CONV: long, NAME: PFC.F_NR_MLOCK } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_anon_pages ",
		CONV: long, NAME: PFC.F_NR_ANON_PAGES } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_mapped ",
		CONV: long, NAME: PFC.F_NR_MAPPED } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_file_pages ",
		CONV: long, NAME: PFC.F_NR_FILE_PAGES } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_dirty ",
		CONV: long, NAME: PFC.F_NR_DIRTY } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_writeback ",
		CONV: long, NAME: PFC.F_NR_WRITEBACK } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_slab_reclaimable ",
		CONV: long, NAME: PFC.F_NR_SLAB_RECLAIM } )
        PBR.add_parse_rule(self, { PREFIX: " ",
                AFTER: " nr_slab_unreclaimable ",
		CONV: long, NAME: PFC.F_NR_SLAB_UNRECLAIM } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_page_table_pages ",
		CONV: long, NAME: PFC.F_NR_PAGE_TABLE_PAGES } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_kernel_stack ",
		CONV: long, NAME: PFC.F_NR_KERNEL_STACK } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_unstable ",
		CONV: long, NAME: PFC.F_NR_UNSTABLE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_bounce ",
		CONV: long, NAME: PFC.F_NR_BOUNCE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_vmscan_write ",
		CONV: long, NAME: PFC.F_NR_VMSCAN_WRITE } )
        PBR.add_parse_rule(self, { PREFIX: " ",
                AFTER: " nr_vmscan_immediate_reclaim ",
		CONV: long, NAME: PFC.F_NR_VMSCAN_IMM_RECLAIM } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_writeback_temp ",
		CONV: long, NAME: PFC.F_NR_WRITEBACK_TEMP } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_isolated_anon ",
		CONV: long, NAME: PFC.F_NR_ISOLATED_ANON } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_isolated_file ",
		CONV: long, NAME: PFC.F_NR_ISOLATED_FILE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_shmem ",
		CONV: long, NAME: PFC.F_NR_SHMEM } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_dirtied ",
		CONV: long, NAME: PFC.F_NR_DIRTIED } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_written ",
		CONV: long, NAME: PFC.F_NR_WRITTEN } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_pages_scanned ",
		CONV: long, NAME: PFC.F_NR_PAGE_SCAN } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_hit ",
		CONV: long, NAME: PFC.F_NUMA_HIT } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_miss ",
		CONV: long, NAME: PFC.F_NUMA_MISS } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_foreign ",
		CONV: long, NAME: PFC.F_NUMA_FOREIGN } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_interleave ",
		CONV: long, NAME: PFC.F_NUMA_INTERLEAVE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_local ",
		CONV: long, NAME: PFC.F_NUMA_LOCAL } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " numa_other ",
		CONV: long, NAME: PFC.F_NUMA_OTHER } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " workingset_refault ",
		CONV: long, NAME: PFC.F_WKSET_REFAULT } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " workingset_activate ",
		CONV: long, NAME: PFC.F_WKSET_ACTIVATE } )
        PBR.add_parse_rule(self, { PREFIX: " ",
                AFTER: " workingset_nodereclaim ",
		CONV: long, NAME: PFC.F_WKSET_NODEREC } )
        PBR.add_parse_rule(self, { PREFIX: " ",
                AFTER: " nr_anon_transparent_hugepages ",
		CONV: long, NAME: PFC.F_NR_ANON_TRANS_HUGE } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " nr_free_cma ",
		CONV: long, NAME: PFC.F_NR_FREE_CMA } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " protection: (",
                SUFFIX: ")", NAME: PFC.F_PROTECTION } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " all_unreclaimable: ",
                CONV: long, NAME: PFC.F_ALL_UNRECLAIM } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " start_pfn: ",
                CONV: long, NAME: PFC.F_START_PFN } )
        PBR.add_parse_rule(self, { PREFIX: " ", AFTER: " inactive_ratio: ",
                CONV: long, NAME: PFC.F_INACTIVE_RATIO } )

        self.add_eor_rule( "  inactive_ratio", { BEFORE: ":" } )
        return


    def extra_next(self, sio):

        self.field[PFC.F_ZONE] = self.field[PFC.F_ZONE].strip()

        __per_cpu = dict()
        for __subrec in sorted(self.unused_recs):
            __line = self.unused_recs[__subrec].strip()
            if __line.startswith(self.__cpu_pref):
                __cpu = PBR.conv_by_rules( __line, { AFTER: self.__cpu_pref,
                        CONV: long } )
                __per_cpu[__cpu] = dict()
            else:
                __val = PBR.conv_by_rules( __line, { AFTER: ":",
                        CONV: long } )
                if __line.startswith(self.__count_pref):
                    __per_cpu[__cpu][self.__count_key] = __val
                elif __line.startswith(self.__high_pref):
                    __per_cpu[__cpu][self.__high_key] = __val
                elif __line.startswith(self.__batch_pref):
                    __per_cpu[__cpu][self.__batch_key] = __val
                elif __line.startswith(self.__vm_stats_pref):
                    __per_cpu[__cpu][self.__vm_stats_key] = __val

        self.field[PFC.F_CPU_PAGESETS] = __per_cpu

        __pl = self.field[PFC.F_PROTECTION].split(",")
        __nums = [0] * len(__pl)
        for __off in range(0, len(__pl)):
            __nums[__off] = PBR.conv_by_rules(__pl[__off], { CONV: long } )

        self.field[PFC.F_PROTECTION] = __nums

        return self.field

REGISTER_FILE("/proc/zoneinfo", ProcRootZONEINFO)
REGISTER_PARTIAL_FILE("zoneinfo", ProcRootZONEINFO)




#
class ProcRootSCHEDSTAT(PBR.TaggedMultiLineFile):
    """
    Parse /proc/schedstat file
    """

# source: kernel/sched_stats.h
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 2
        self.__cpu_count = 9
        self.__domain_count = 36
        self.__no_cpu = -1
        self.__cpu_pref = "cpu"
        self.__dom_pref = "domain"
        self.all_parsed = dict()
        self.cpu_order = dict()
        self.__cpu_seq = 0

        PBR.add_parse_rule(self, { PREFIX: "version", CONV: long,
                NAME: PFC.F_VERSION } )
        PBR.add_parse_rule(self, { PREFIX: "timestamp", CONV: long,
                NAME: PFC.F_TIMESTAMP } )
        return


    def parse_cpu_line(self, words):
        """Dissect a 'cpuX # # ...' subrecord"""

        __res = dict()
        __nums = PBR.array_of_longs(words[1:])

        if len(__nums) == self.__cpu_count:
            __res[PFC.F_SCH_YIELD] = __nums[0]
            __res[PFC.F_SCH_SW_EXP_Q] = __nums[1]
            __res[PFC.F_SCH_CALLS] = __nums[2]
            __res[PFC.F_SCH_IDLE] = __nums[3]
            __res[PFC.F_WUP_CALLS] = __nums[4]
            __res[PFC.F_WUP_LOC_CPU] = __nums[5]
            __res[PFC.F_RUNNING_SUM] = __nums[6]
            __res[PFC.F_WAITING_SUM] = __nums[7]
            __res[PFC.F_SLICES] = __nums[8]
        return __res


    def parse_domain_line(self, words):
        """Dissect a 'domainX # # ...' subrecord"""

        __res = dict()
        __res[PFC.F_CPU_MASK] = words[1]
        __nums = PBR.array_of_longs(words[2:])
        if len(__nums) == self.__domain_count:
            __res[PFC.F_IDLE_LB] = __nums[0]
            __res[PFC.F_IDLE_LB_PASS] = __nums[1]
            __res[PFC.F_IDLE_LB_FAIL] = __nums[2]
            __res[PFC.F_IDLE_LB_IMBAL] = __nums[3]
            __res[PFC.F_IDLE_PT] = __nums[4]
            __res[PFC.F_IDLE_PT_CACHE_HOT] = __nums[5]
            __res[PFC.F_IDLE_LB_NO_QUEUE] = __nums[6]
            __res[PFC.F_IDLE_LB_NO_GROUP] = __nums[7]
            __res[PFC.F_BUSY_LB] = __nums[8]
            __res[PFC.F_BUSY_LB_PASS] = __nums[9]
            __res[PFC.F_BUSY_LB_FAIL] = __nums[10]
            __res[PFC.F_BUSY_LB_IMBAL] = __nums[11]
            __res[PFC.F_BUSY_PT] = __nums[12]
            __res[PFC.F_BUSY_PT_CACHE_HOT] = __nums[13]
            __res[PFC.F_BUSY_LB_NO_QUEUE] = __nums[14]
            __res[PFC.F_BUSY_LB_NO_GROUP] = __nums[15]
            __res[PFC.F_JBEI_LB] = __nums[16]
            __res[PFC.F_JBEI_LB_PASS] = __nums[17]
            __res[PFC.F_JBEI_LB_FAIL] = __nums[18]
            __res[PFC.F_JBEI_LB_IMBAL] = __nums[19]
            __res[PFC.F_JBEI_PT] = __nums[20]
            __res[PFC.F_JBEI_PT_CACHE_HOT] = __nums[21]
            __res[PFC.F_JBEI_LB_NO_QUEUE] = __nums[22]
            __res[PFC.F_JBEI_LB_NO_GROUP] = __nums[23]
            __res[PFC.F_ACT_LB] = __nums[24]
            __res[PFC.F_ACT_LB_FAIL] = __nums[25]
            __res[PFC.F_ACT_LB_MOVED] = __nums[26]
            __res[PFC.F_SBE_COUNT] = __nums[27]
            __res[PFC.F_SBE_BALANCED] = __nums[28]
            __res[PFC.F_SBE_PUSHED] = __nums[29]
            __res[PFC.F_SBF_COUNT] = __nums[30]
            __res[PFC.F_SBF_BALANCED] = __nums[31]
            __res[PFC.F_SBF_PUSHED] = __nums[32]
            __res[PFC.F_TRWUP_AWOKE_DIFF_CPU] = __nums[33]
            __res[PFC.F_TRWUP_MOVE_CACHE_COLD] = __nums[34]
            __res[PFC.F_TRWUP_PASSIVE_BAL] = __nums[35]

        return __res

    def next(self):
        if len(self.all_parsed) == 0:
            self.all_parsed = super(ProcRootSCHEDSTAT, self).next()
            self.__cpu_seq = 0

        if len(self.all_parsed) == 0:
            raise StopIteration

        __pthru = dict()
        __pthru[PFC.F_VERSION] = self.field[PFC.F_VERSION]
        __pthru[PFC.F_TIMESTAMP] = self.field[PFC.F_TIMESTAMP]
        self.field = __pthru

        __cpu = self.cpu_order[self.__cpu_seq]
        self.__cpu_seq += 1
        __vals = self.all_parsed.pop(__cpu, ("cpuX", {}) )
        self.field[PFC.F_CPU_ID] = __cpu
        for __key in __vals:
            self.field[__key] = __vals[__key]

        return self.field


    def extra_next(self, sio):
        __per_cpu = dict()
        __cpu = self.__no_cpu

        for __subrec in sorted(self.unused_recs):
            __line = self.unused_recs[__subrec].split()
            __tag = __line[0]

            if __tag.startswith(self.__cpu_pref):
                self.cpu_order[self.__cpu_seq] = __tag
                self.__cpu_seq += 1
                __per_cpu[__tag] = self.parse_cpu_line(__line)
                __per_cpu[__tag][PFC.F_DOM_ORDER] = dict()
                __dom_seq = 0
                __cpu = __tag
            elif __cpu != self.__no_cpu and __tag.startswith(self.__dom_pref):
                __dinfo = self.parse_domain_line(__line)
                __per_cpu[__cpu][__tag] = __dinfo
                __per_cpu[__cpu][PFC.F_DOM_ORDER][__dom_seq] = __tag
                __dom_seq += 1

        return __per_cpu

REGISTER_FILE("/proc/schedstat", ProcRootSCHEDSTAT)
REGISTER_PARTIAL_FILE("pr/schedstat", ProcRootSCHEDSTAT)




#
class ProcRootCRYPTO(PBR.TaggedMultiLineFile):
    """
    Parse /proc/crypto file
    """

# source: crypto/proc.c  (primary code source)
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        # "minfields" has to be set to "0" since blank lines are the
        # EOR indicators
        self.minfields = 0

        __rpl = (PREFIX, SUFFIX, AFTER, BEFORE)
        PBR.add_parse_rule(self, { PREFIX: "name", AFTER: ": ",
                NAME: PFC.F_NAME }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "driver", AFTER: ": ",
                NAME: PFC.F_DRIVER }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "module", AFTER: ": ",
                NAME: PFC.F_MODULE }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "priority", AFTER: ": ", CONV: long,
                NAME: PFC.F_PRIORITY }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "refcnt", AFTER: ": ", CONV: long,
                NAME: PFC.F_REFCOUNT }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "selftest", AFTER: ": ",
                NAME: PFC.F_SELFTEST }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "flags", AFTER: ": 0x", CONV: long,
                NAME: PFC.F_FLAGS, BASE: 16 }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "digestsize", AFTER: ": ",
                NAME: PFC.F_DIGEST_SIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "maxauthsize", AFTER: ": ",
                NAME: PFC.F_MAX_AUTH_SIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "max keysize", AFTER: ": ",
                NAME: PFC.F_MAX_KEYSIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "min keysize", AFTER: ": ",
                NAME: PFC.F_MIN_KEYSIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "async", AFTER: ": ",
                NAME: PFC.F_ASYNC }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "geniv", AFTER: ": ",
                NAME: PFC.F_GENIV }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "ivsize", AFTER: ": ",
                NAME: PFC.F_IVSIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "blocksize", AFTER: ": ",
                NAME: PFC.F_BLOCKSIZE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "type", AFTER: ": ",
                NAME: PFC.F_TYPE }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "seedsize", AFTER: ": ",
                NAME: PFC.F_SEEDSIZE, CONV: long }, __rpl )

        self.add_eor_rule( "", { WORDS: 0, CONV: str, ERRVAL: "continue" } )
        return


    def extra_next(self, sio):

        for __key in self.field:
            if type(self.field[__key]) is str:
                self.field[__key] = self.field[__key].strip()

        return self.field

REGISTER_FILE("/proc/crypto", ProcRootCRYPTO)
REGISTER_PARTIAL_FILE("crypto", ProcRootCRYPTO)




#
class ProcRootLATENCYSTATS(PBR.FixedWhitespaceDelimRecs):
    """
    Handler for /proc/latency_stats and /proc/self/latency files
    """

# source: kernel/latencytop.c
#
#static int lstats_show(struct seq_file *m, void *v)
#{
#    int i;
#
#    seq_puts(m, "Latency Top version : v0.1\n");
#
#    for (i = 0; i < MAXLR; i++) {
#        struct latency_record *lr = &latency_record[i];
#
#        if (lr->backtrace[0]) {
#            int q;
#            seq_printf(m, "%i %lu %lu",
#                   lr->count, lr->time, lr->max);
#            for (q = 0; q < LT_BACKTRACEDEPTH; q++) {
#                unsigned long bt = lr->backtrace[q];
#                if (!bt)
#                    break;
#                if (bt == ULONG_MAX)
#                    break;
#                seq_printf(m, " %ps", (void *)bt);
#            }
#            seq_printf(m, "\n");
#        }
#    }
#    return 0;
#}
#

    def extra_init(self, *opts):
        self.minfields = 4
        self.skipped = "Latency"

        PBR.add_parse_rule(self, { POS: 0, CONV: long, NAME: PFC.F_HITS } )
        PBR.add_parse_rule(self, { POS: 1, CONV: long,
                NAME: PFC.F_ACCUM_LATENCY } )
        PBR.add_parse_rule(self, { POS: 2, CONV: long,
                NAME: PFC.F_MAX_LATENCY } )
        return

    def extra_next(self, sio):

# -- Sample records
#
# Latency Top version : v0.1
# 5 1113 256 do_fork sys_vfork stub_vfork
# 5 707 159 do_wait sys_wait4 system_call_fastpath
# 1 93 93 ep_poll sys_epoll_wait system_call_fastpath

        self.field[PFC.F_BACKTRACE] = sio.lineparts[3:]
        __hits = self.field[PFC.F_HITS]
        __accum = self.field[PFC.F_ACCUM_LATENCY]
        __max = self.field[PFC.F_MAX_LATENCY]
        __trace = " ".join(self.field[PFC.F_BACKTRACE])

        return(__hits, __accum, __max, __trace)

REGISTER_FILE("/proc/latency_stats", ProcRootLATENCYSTATS)
REGISTER_PARTIAL_FILE("latency_stats", ProcRootLATENCYSTATS)
REGISTER_PARTIAL_FILE("latency", ProcRootLATENCYSTATS)




#
class ProcRootIOPORTS(PBR.FixedWhitespaceDelimRecs):
    """
    Handler for /proc/ioports files
    """

# source: kernel/resource.c
#
# for (depth = 0, p = r; depth < MAX_IORES_LEVEL; depth++, p = p->parent)
#     if (p->parent == root)
#         break;
# seq_printf(m, "%*s%0*llx-%0*llx : %s\n",
#         depth * 2, "",
#         width, (unsigned long long) r->start,
#         width, (unsigned long long) r->end,
#         r->name ? r->name : "<BAD>");
#

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, CONV: long, BEFORE: "-", BASE: 16,
                NAME: PFC.F_START } )
        PBR.add_parse_rule(self, { POS: 0, CONV: long, AFTER: "-", BASE: 16,
                NAME: PFC.F_END } )
        return

    def extra_next(self, sio):

# -- Sample records
#
#03b0-03df : PCI Bus 0000:00
#03e0-0cf7 : PCI Bus 0000:00
#  03f8-03ff : serial
#  0400-0453 : pnp 00:09
#    0400-0403 : ACPI PM1a_EVT_BLK
#    0404-0405 : ACPI PM1a_CNT_BLK
#    0408-040b : ACPI PM_TMR

        __desc = " ".join(sio.lineparts[2:])
        self.field[PFC.F_PORT_NAME] = __desc

        __level = (len(sio.buff) - len(sio.buff.lstrip(" "))) / 2
        self.field[PFC.F_LEVEL] = __level

        __low = self.field[PFC.F_START]
        __high = self.field[PFC.F_END]

        return(__low, __high, __level, __desc)

REGISTER_FILE("/proc/ioports", ProcRootIOPORTS)
REGISTER_PARTIAL_FILE("ioports", ProcRootIOPORTS)




#
class ProcRootIOMEM(PBR.FixedWhitespaceDelimRecs):
    """
    Handler for /proc/iomem files
    """

# source: kernel/resource.c
#
# for (depth = 0, p = r; depth < MAX_IORES_LEVEL; depth++, p = p->parent)
#     if (p->parent == root)
#         break;
# seq_printf(m, "%*s%0*llx-%0*llx : %s\n",
#         depth * 2, "",
#         width, (unsigned long long) r->start,
#         width, (unsigned long long) r->end,
#         r->name ? r->name : "<BAD>");
#

    def extra_init(self, *opts):
        self.minfields = 3

        PBR.add_parse_rule(self, { POS: 0, CONV: long, BEFORE: "-", BASE: 16,
                NAME: PFC.F_START } )
        PBR.add_parse_rule(self, { POS: 0, CONV: long, AFTER: "-", BASE: 16,
                NAME: PFC.F_END } )
        return

    def extra_next(self, sio):

# -- Sample records
#
#ceff7000-ceffffff : System RAM
#cf000000-cfffffff : RAM buffer
#d0000000-fbffffff : PCI Bus 0000:00
#  d0000000-dfffffff : PCI Bus 0000:01
#    d0000000-dfffffff : 0000:01:00.0
#      d0000000-d01effff : efifb
#  e0000000-efffffff : PCI MMCONFIG 0000 [bus 00-ff]
#    e0000000-efffffff : reserved

        __desc = " ".join(sio.lineparts[2:])
        self.field[PFC.F_MEM_DESC] = __desc

        __level = (len(sio.buff) - len(sio.buff.lstrip(" "))) / 2
        self.field[PFC.F_LEVEL] = __level

        __low = self.field[PFC.F_START]
        __high = self.field[PFC.F_END]

        return(__low, __high, __level, __desc)

REGISTER_FILE("/proc/iomem", ProcRootIOMEM)
REGISTER_PARTIAL_FILE("iomem", ProcRootIOMEM)




#
class ProcRootTIMERSTATS(PBR.FixedWhitespaceDelimRecs):
    """
    Handler for /proc/timer_stats files
    """

# --- File: /proc/timer_stats
#
# source: kernel/time/timer_stats.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.

    def extra_init(self, *opts):
#        self.minfields = 4
        self.minfields = 2
        self.__timer_tag = "Timer"
        self.__sample_tag = "Sample"
        self.__total_tag = "total"
        self.__overflow_tag = "Overflow:"
        self.__collection_tag = "Collection:"

        self.__hold = dict()
        self.__hold[PFC.F_VERSION] = ""
        self.__hold[PFC.F_SAMPLE_PERIOD] = 0.0
        self.__hold[PFC.F_EVENT_TOTAL] = 0
        self.__hold[PFC.F_EVENT_RATE] = 0.0
        self.__hold[PFC.F_OVERFLOW] = PDC.NAN
        self.__hold[PFC.F_COLLECTION] = ""

        PBR.add_parse_rule(self, { POS: 0, BEFORE: ",",
                NAME: PFC.F_DEFERRABLE } )
        PBR.add_parse_rule(self, { POS: 1, CONV: long, NAME: PFC.F_PID } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_PROC_NAME } )
#        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_INIT_ROUT } )
#        PBR.add_parse_rule(self, { POS: 4, AFTER: "(", BEFORE: ")",
#                NAME: PFC.F_CBACK_ROUT } )
        PBR.add_parse_rule(self, { POS: 99, NAME: PFC.F_INIT_ROUT } )
        PBR.add_parse_rule(self, { POS: 99, NAME: PFC.F_CBACK_ROUT } )
        PBR.add_parse_rule(self, { POS: 99, CONV: long, NAME: PFC.F_COUNT } )
        PBR.add_parse_rule(self, { POS: 99, CONV: str, NAME: PFC.F_VERSION } )
        PBR.add_parse_rule(self, { POS: 99, CONV: float,
                NAME: PFC.F_SAMPLE_PERIOD } )
        PBR.add_parse_rule(self, { POS: 99, CONV: long,
                NAME: PFC.F_EVENT_TOTAL } )
        PBR.add_parse_rule(self, { POS: 99, CONV: float,
                NAME: PFC.F_EVENT_RATE } )
        PBR.add_parse_rule(self, { POS: 99, CONV: long,
                NAME: PFC.F_OVERFLOW } )
        return

    def extra_next(self, sio):

# -- Sample records
#
#Timer Stats Version: v0.2
#Sample period: 17.263 s
#   18,  1947 varnishd         hrtimer_start_range_ns (hrtimer_wakeup)
#  478,     0 swapper/6        hrtimer_start_range_ns (tick_sched_timer)
# 1460, 16314 Timer            hrtimer_start_range_ns (hrtimer_wakeup)
#   26,     0 swapper/0        hrtimer_start (tick_sched_timer)
#  172,  1945 varnishd         hrtimer_start_range_ns (hrtimer_wakeup)
#  201,     0 swapper/0        hrtimer_start_range_ns (tick_sched_timer)
# 149D, 11069 kworker/0:1      schedule_delayed_work_on (delayed_work_timer_fn)

        __first = sio.get_word(0)
        __sec = sio.get_word(1)

        if __first == self.__timer_tag:
            self.__hold[PFC.F_VERSION] = sio.get_word(3)
            return self.next()

        if __first == self.__sample_tag:
            __val = PBR.conv_by_rules(sio.get_word(2), { CONV: float } )
            self.__hold[PFC.F_SAMPLE_PERIOD] = __val
            return self.next()

        if __first == self.__overflow_tag:
            __val = PBR.conv_by_rules(sio.get_word(1), { CONV: long } )
            self.__hold[PFC.F_OVERFLOW] = __val
            return self.next()

        if __first == self.__collection_tag:
            self.__hold[PFC.F_COLLECTION] = sio.get_word(1)
            return self.next()

        if __sec == self.__total_tag:
            self.field[PFC.F_DEFERRABLE] = ""
            self.field[PFC.F_PID] = 0
            self.field[PFC.F_PROC_NAME] = ""
            self.field[PFC.F_INIT_ROUT] = ""
            self.field[PFC.F_CBACK_ROUT] = ""

            __val = PBR.conv_by_rules(sio.get_word(0), { CONV: long } )
            self.field[PFC.F_EVENT_TOTAL] = __val
            __val = PBR.conv_by_rules(sio.get_word(3), { CONV: float,
                    ERRVAL: PDC.NAN } )
            self.field[PFC.F_EVENT_RATE] = __val

        else:
            __first = self.field[PFC.F_DEFERRABLE]
            if __first[-1:] == "D":
                __first = __first[:-1]
                __val = "D"
            else:
                __val = ""
            self.field[PFC.F_DEFERRABLE] = __val
            self.field[PFC.F_COUNT] = PBR.conv_by_rules(__first,
                    { CONV: long } )

            __proc = self.field[PFC.F_PROC_NAME]
            __split = sio.buff.partition(__proc)
            __tail = "{proc:s}{rest:s}".format(proc=__proc, rest=__split[2])
            self.field[PFC.F_PROC_NAME] = __tail[:16].rstrip()
            __tail = __tail[17:]
            self.field[PFC.F_INIT_ROUT] = PBR.conv_by_rules(__tail,
                    { BEFORE: " " } )
            self.field[PFC.F_CBACK_ROUT] = PBR.conv_by_rules(__tail,
                    { AFTER: "(", BEFORE: ")" } )

        self.field[PFC.F_VERSION] = self.__hold[PFC.F_VERSION]
        self.field[PFC.F_SAMPLE_PERIOD] = self.__hold[PFC.F_SAMPLE_PERIOD]
        self.field[PFC.F_OVERFLOW] = self.__hold[PFC.F_OVERFLOW]
        self.field[PFC.F_COLLECTION] = self.__hold[PFC.F_COLLECTION]

        return self.field

REGISTER_FILE("/proc/timer_stats", ProcRootTIMERSTATS)
REGISTER_PARTIAL_FILE("timer_stats", ProcRootTIMERSTATS)




#
class ProcRootPAGETYPEINFO(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/pagetypeinfo file
    """

# source: mm/vmstat.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 4
        self.__in_numbers = False
        self.__block_order_pref = "Page"
        self.__per_block_pref = "Pages"
        self.__order_pref = "Free"
        self.__number_pref = "Number"
        self.__order_start_data = 8
        self.__migrate_start_data = 4
        self.__start_ord_num = 6
        self.__start_agg_num = 4
        self.__order_colname = "order-"

        self.order_list = []
        self.migtype_list = []

        self.__hold = dict()
        self.__hold[PFC.F_BLOCK_ORDER] = 0
        self.__hold[PFC.F_PAGES_PER_BLOCK] = 0

        PBR.add_parse_rule(self, { POS: 1, CONV: long, SUFFIX: ",",
                NAME: PFC.F_NODE } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_ZONE } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_TYPE } )
        return

    def extra_next(self, sio):

        __first = sio.get_word(0)

        if __first == self.__block_order_pref:
            __val = PBR.conv_by_rules(sio.get_word(3), { CONV: long } )
            self.__hold[PFC.F_BLOCK_ORDER] = __val
            self.next()
            __first = sio.get_word(0)

        if __first == self.__per_block_pref:
            __val = PBR.conv_by_rules(sio.get_word(3), { CONV: long } )
            self.__hold[PFC.F_PAGES_PER_BLOCK] = __val
            self.next()
            __first = sio.get_word(0)

        if __first == self.__order_pref:
            __off = self.__order_start_data
            __ord = [""] * (sio.linewords - __off)
            for __num in range(0, len(__ord)):
                __ord[__num] = "{pref}{num}".format(pref=self.__order_colname,
                        num=sio.get_word(__off))
                __off += 1
            self.order_list = __ord
            self.next()
            __first = sio.get_word(0)

        if __first == self.__number_pref:
            self.__in_numbers = True
            __off = self.__migrate_start_data
            __mig = [""] * (sio.linewords - __off)
            for __num in range(0, len(__mig)):
                __mig[__num] = sio.get_word(__off)
                __off += 1
            self.migtype_list = __mig
            self.next()
            __first = sio.get_word(0)

        self.field[PFC.F_MIGR_BRKOUT] = dict()
        self.field[PFC.F_MIGR_AGG] = dict()

        if self.__in_numbers:
            self.field[PFC.F_TYPE] = ""
            __mig = self.migtype_list
            __off = self.__start_agg_num
            for __num in range(0, len(__mig)):
                __name = __mig[__num]
                self.field[PFC.F_MIGR_AGG][__name] = PBR.conv_by_rules(
                        sio.get_word(__off), { CONV: long } )
                __off += 1
        else:
            __ord = self.order_list
            __off = 0
            for __num in range(self.__start_ord_num, sio.linewords):
                __name = __ord[__off]
                __off += 1
                self.field[PFC.F_MIGR_BRKOUT][__name] = PBR.conv_by_rules(
                        sio.get_word(__num), { CONV: long } )

        self.field[PFC.F_BLOCK_ORDER] = self.__hold[PFC.F_BLOCK_ORDER]
        self.field[PFC.F_PAGES_PER_BLOCK] = self.__hold[PFC.F_PAGES_PER_BLOCK]

        return self.field

REGISTER_FILE("/proc/pagetypeinfo", ProcRootPAGETYPEINFO)
REGISTER_PARTIAL_FILE("pagetypeinfo", ProcRootPAGETYPEINFO)




#
class ProcRootDEVICES(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/devices file
    """

# source: mm/vmstat.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 2
        self.__type_char = "character"
        self.__type_block = "block"
        self.__char_pref = "Character"
        self.__block_pref = "Block"
        self.__dev_type = "unknown"

        PBR.add_parse_rule(self, { POS: 0, CONV: long,
                NAME: PFC.F_MAJOR_DEV } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_DEVICE_NAME } )
        return

    def extra_next(self, sio):

        __first = sio.get_word(0)

        if __first == self.__char_pref:
            self.__dev_type = self.__type_char
            self.next()
            __first = sio.get_word(0)

        if __first == self.__block_pref:
            self.__dev_type = self.__type_block
            self.next()

        self.field[PFC.F_DEVICE_TYPE] = self.__dev_type

        return(self.field[PFC.F_DEVICE_TYPE], self.field[PFC.F_MAJOR_DEV],
                self.field[PFC.F_DEVICE_NAME])

REGISTER_FILE("/proc/devices", ProcRootDEVICES)
REGISTER_PARTIAL_FILE("devices", ProcRootDEVICES)



#
class ProcRootTIMERLIST(PBR.TaggedMultiLineFile):
    """
    Parse /proc/timer_list file
    """

# source: kernel/time/timer_list.c
#
# The kernel source snippets that generate this file are stored in
# "README.ProcRootHandlers" to reduce the size of this module.
#

    def extra_init(self, *opts):
        self.minfields = 0

        self.__no_clock = -1
        self.__no_timer = -1
        self.__empty_tag = ""
        self.__empty_rec = ""
        self.__act_timer_clue = ", S:"
        self.__glinfo = ("v0.0", 0, 0)
        self.__bcast_clue = "Broadcast device"

        __rpl = (HAS, PREFIX, SUFFIX, PSUB, AFTER, BEFORE)

        PBR.add_parse_rule(self, { PREFIX: "Timer List Version:",
                NAME: PFC.F_VERSION } )
        PBR.add_parse_rule(self, { PREFIX: "HRTIMER_MAX_CLOCK_BASES:",
                NAME: PFC.F_HRT_MAX_CL_BASES, CONV: long } )
        PBR.add_parse_rule(self, { PREFIX: "now at", SUFFIX: "nsecs",
                NAME: PFC.F_TIME_NOW, CONV: long } )

        PBR.add_parse_rule(self, { PREFIX: "cpu:",
                NAME: PFC.F_CPU, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .expires_next", AFTER: ":",
                NAME: PFC.F_NEXT_EXPIRE, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .hres_active", AFTER: ":",
                NAME: PFC.F_HRES_ACTIVE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .nr_events", AFTER: ":",
                NAME: PFC.F_NR_EVENTS, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .nr_retries", AFTER: ":",
                NAME: PFC.F_NR_RETRIES, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .nr_hangs", AFTER: ":",
                NAME: PFC.F_NR_HANGS, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .max_hang_time", AFTER: ":",
                NAME: PFC.F_MAX_HANG_TIME, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .nohz_mode", AFTER: ":",
                NAME: PFC.F_NOHZ_MODE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .last_tick", AFTER: ":",
                NAME: PFC.F_LAST_TICK, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_tick", AFTER: ":",
                NAME: PFC.F_IDLE_TICK, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .tick_stopped", AFTER: ":",
                NAME: PFC.F_TICK_STOP, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_jiffies", AFTER: ":",
                NAME: PFC.F_IDLE_JIFFIES, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_calls", AFTER: ":",
                NAME: PFC.F_IDLE_CALLS, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_sleeps", AFTER: ":",
                NAME: PFC.F_IDLE_SLEEPS, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_entrytime", AFTER: ":",
                NAME: PFC.F_IDLE_ENTRY, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_waketime", AFTER: ":",
                NAME: PFC.F_IDLE_WAKE, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_exittime", AFTER: ":",
                NAME: PFC.F_IDLE_EXIT, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_sleeptime", AFTER: ":",
                NAME: PFC.F_IDLE_SLEEPTIME, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .iowait_sleeptime", AFTER: ":",
                NAME: PFC.F_IOWAIT_SLEEP, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .last_jiffies", AFTER: ":",
                NAME: PFC.F_LAST_JIFFIES, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .next_jiffies", AFTER: ":",
                NAME: PFC.F_NEXT_JIFFIES, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "  .idle_expires", AFTER: ":",
                NAME: PFC.F_IDLE_EXPIRES, CONV: long, SUFFIX: "nsecs" },
                __rpl )
        PBR.add_parse_rule(self, { PREFIX: "jiffies:",
                NAME: PFC.F_JIFFIES, CONV: long }, __rpl )

        PBR.add_parse_rule(self, { PREFIX: "Tick Device: mode:",
                NAME: PFC.F_TICK_DEV, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "Per CPU device:",
                NAME: PFC.F_PER_CPU_DEV, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "Clock Event Device: ",
                NAME: PFC.F_CLOCK_EV_DEV }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " max_delta_ns:",
                NAME: PFC.F_MAX_DELTA, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " min_delta_ns:",
                NAME: PFC.F_MIN_DELTA, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " mult:",
                NAME: PFC.F_MULT, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " shift:",
                NAME: PFC.F_SHIFT, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " mode:",
                NAME: PFC.F_MODE, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " next_event:", CONV: long,
                NAME: PFC.F_NEXT_EVENT, SUFFIX: "nsecs" },  __rpl )
        PBR.add_parse_rule(self, { PREFIX: " set_next_event:",
                NAME: PFC.F_SET_NEXT_EVENT }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " set_mode:",
                NAME: PFC.F_SET_MODE }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " event_handler:",
                NAME: PFC.F_EVENT_HANDLER }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: " retries:",
                NAME: PFC.F_RETRIES, CONV: long }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "tick_broadcast_mask:",
                NAME: PFC.F_TICK_BCAST_MASK }, __rpl )
        PBR.add_parse_rule(self, { PREFIX: "tick_broadcast_oneshot_mask:",
                NAME: PFC.F_TICK_BCAST_ONESHOT }, __rpl )
        PBR.add_parse_rule(self, { HAS: self.__bcast_clue,
                NAME: PFC.F_BCAST_DEVICE }, __rpl )

        self.add_eor_rule( "", { WORDS: 0, CONV: str, ERRVAL: "continue" } )

        __rs = []
        __rs = __rs + [ (PFC.F_CLOCK_ID, { PREFIX: " clock", SUFFIX: ":",
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_CLOCK_BASE, { PREFIX: "  .base:", BASE: 16,
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_CLOCK_INDEX, { PREFIX: "  .index:",
                CONV: long }) ]
        __rs = __rs + [ (PFC.F_CLOCK_RES, { PREFIX: "  .resolution:",
                SUFFIX: "nsecs", CONV: long }) ]
        __rs = __rs + [ (PFC.F_CLOCK_GETTIME, { PREFIX: "  .get_time:", }) ]
        __rs = __rs + [ (PFC.F_CLOCK_OFFSET, { PREFIX: "  .offset:",
                SUFFIX: "nsecs",  CONV: long }) ]

        __rs = __rs + [ (PFC.F_ACTIVE_TIMERS, { HAS: "active timers:",
                CONV: str }) ]

        __rs = __rs + [ (PFC.F_TIMER_NUM, { HAS: ", S:",
                CONV: long, PSUB: 0, AFTER: "#", BEFORE: ":" }, __rpl) ]
        __rs = __rs + [ (PFC.F_TIMER_ADDR, { HAS: ", S:",
                CONV: long, BASE: 16, PSUB: 1, AFTER: "<", BEFORE: ">" },
                __rpl) ]
        __rs = __rs + [ (PFC.F_TIMER_ADDR_TEXT, { HAS: ", S:",
                BEFORE: ",", PSUB: 1 },
                __rpl) ]
        __rs = __rs + [ (PFC.F_TIMER_FUNC, { HAS: ", S:",
                CONV: str, PSUB: 2, BEFORE: "," }, __rpl) ]
#        __rs = __rs + [ (PFC.F_TIMER_STATE, { HAS: ", S:",
#                CONV: long, BASE: 16, PSUB: 3, AFTER: "S:", BEFORE: "," },
#                __rpl) ]
        __rs = __rs + [ (PFC.F_TIMER_STATE, { HAS: ", S:",  PSUB: 3,
                AFTER: "S:" },
                __rpl) ]
        __rs = __rs + [ (PFC.F_START_SITE, { HAS: ", S:",
                CONV: str, PSUB: 4, BEFORE: "," }, __rpl) ]

        __rs = __rs + [ (PFC.F_SOFT_EXP, { HAS: " # expires at ",
                CONV: long, PSUB: 3, BEFORE: "-"}, __rpl) ]
        __rs = __rs + [ (PFC.F_EXP, { HAS: " # expires at ",
                CONV: long, PSUB: 3, AFTER: "-" }, __rpl) ]
        __rs = __rs + [ (PFC.F_SOFT_EXP_DIFF, { HAS: " # expires at ",
                CONV: long, PSUB: 6 }, __rpl) ]
        __rs = __rs + [ (PFC.F_EXP_DIFF, { HAS: " # expires at ",
                CONV: long, PSUB: 8 }, __rpl) ]

        self.__rset = __rs

        self.__active_tag = PFC.F_ACTIVE_TIMERS
        self.__clock_tag = PFC.F_CLOCK_ID

        return

    def parse_by_ruleset(self, buff):
        """Match records with the appropriate parse rule"""

        __matched = False
        __result = dict()

        __tag = self.__empty_tag
        __val = self.__empty_tag

        for __cset in self.__rset:
            __key = __cset[0]
            __rule = __cset[1]
            try:
                __rpl = __cset[2]
            except IndexError:
                __rpl = ""
            if PBR.matches_all_crit(buff, __rule, __rpl):
                __matched = True
                __tag = __key
                __val = PBR.conv_by_rules(buff, __rule, __rpl)
                if type(__val) is str:
                    __val = __val.strip()
                __result[__tag] = __val

        return(__matched, __result)

# pylint: disable=R0914
    def extra_next(self, sio):

        try:
            if self.field[PFC.F_BCAST_DEVICE] == self.__bcast_clue:
                self.field[PFC.F_BCAST_DEVICE] = True
            else:
                self.field[PFC.F_BCAST_DEVICE] = False
        except KeyError:
            self.field[PFC.F_BCAST_DEVICE] = False

        if self.field[PFC.F_VERSION] != "":
            __ver = self.field[PFC.F_VERSION].strip()
            __clb = self.field[PFC.F_HRT_MAX_CL_BASES]
            __now = self.field[PFC.F_TIME_NOW]
            self.__glinfo = (__ver, __clb, __now)
            self.next()

        self.field[PFC.F_VERSION] = self.__glinfo[0]
        self.field[PFC.F_HRT_MAX_CL_BASES] = self.__glinfo[1]
        self.field[PFC.F_TIME_NOW] = self.__glinfo[2]

        __clock = self.__no_clock
        __clock_list = dict()
        __in_active = False
        __detail = dict()
        __actnum = self.__no_timer
        __st_comm = ""
        __st_pid = PDC.NO_PID

        for __subrec in sorted(self.unused_recs):
            __line = self.unused_recs[__subrec]
            __hit, __plist = self.parse_by_ruleset(__line)

            if __line.find(self.__act_timer_clue) != -1:
                __last = __line.split(",")[-1:][0].strip()
                __parts = __last.rpartition("/")
                if len(__parts) == 3:
                    __st_comm = __parts[0]
                    __st_pid = PBR.conv_by_rules(__parts[2], { CONV: long } )

            for __tag in __plist:
                __val = __plist[__tag]
                if __tag == self.__clock_tag:
                    if len(__detail) > 0:
                        try:
                            __active = __detail[self.__active_tag]
                            try:
                                __notimer = __active[self.__no_timer]
                                if len(__notimer) == 0:
                                    __active.pop(self.__no_timer, None)
                            except KeyError:
                                pass
                        except KeyError:
                            __detail[self.__active_tag] = dict()

                    __in_active = False
                    __detail = dict()
                    __seq = len(__clock_list)
                    __clock_list[__seq] = __detail
                    __clock = __val
                elif __tag == self.__active_tag:
                    __in_active = True
                    __active = dict()
                    __detail[__tag] = __active
                    __actnum = self.__no_timer

                if __in_active:
                    if __plist.has_key(PFC.F_TIMER_NUM):
                        __actnum = __plist[PFC.F_TIMER_NUM]

                    if __actnum != self.__no_timer:
                        try:
                            __act = __active[__actnum]
                        except KeyError:
                            __act = dict()
                            __active[__actnum] = __act

                        if __st_pid != PDC.NO_PID:
                            __act[PFC.F_START_COMM] = __st_comm
                            __act[PFC.F_START_PID] = __st_pid
                            __st_comm = ""
                            __st_pid = PDC.NO_PID

                    if __tag != self.__active_tag:
                        __act[__tag] = __val

                elif __clock != self.__no_clock:
                    __detail[__tag] = __val

        self.field[PFC.F_CLOCK_LIST] = __clock_list

        for __key in self.field:
            if type(self.field[__key]) is str:
                self.field[__key] = self.field[__key].strip()

        return self.field

# pylint: enable=R0914

REGISTER_FILE("/proc/timer_list", ProcRootTIMERLIST)
REGISTER_PARTIAL_FILE("timer_list", ProcRootTIMERLIST)




#
class ProcRootKEYS(PBR.FixedWhitespaceDelimRecs):
    """
    Parse /proc/keys file
    """

# security/keys/proc.c
#
##define showflag(KEY, LETTER, FLAG) \
#  (test_bit(FLAG, &(KEY)->flags) ? LETTER : '-')
#
#  seq_printf(m, "%08x %c%c%c%c%c%c%c %5d %4s %08x %5d %5d %-9.9s ",
#         key->serial,
#         showflag(key, 'I', KEY_FLAG_INSTANTIATED),
#         showflag(key, 'R', KEY_FLAG_REVOKED),
#         showflag(key, 'D', KEY_FLAG_DEAD),
#         showflag(key, 'Q', KEY_FLAG_IN_QUOTA),
#         showflag(key, 'U', KEY_FLAG_USER_CONSTRUCT),
#         showflag(key, 'N', KEY_FLAG_NEGATIVE),
#         showflag(key, 'i', KEY_FLAG_INVALIDATED),
#         atomic_read(&key->usage),
#         xbuf,
#         key->perm,
#         from_kuid_munged(seq_user_ns(m), key->uid),
#         from_kgid_munged(seq_user_ns(m), key->gid),
#         key->type->name);

    def extra_init(self, *opts):
        self.minfields = 8

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_SERIAL, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_FLAGS } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_USAGE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_EXPIRES } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_PERMS, CONV: long,
                BASE: 16 } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_KEY_NAME } )
        return

    def extra_next(self, sio):
        __desc = " ".join(sio.lineparts[8:])
        __ff = self.field
        __ff[PFC.F_DESCRIPTION] = __desc

        return(__ff[PFC.F_SERIAL], __ff[PFC.F_FLAGS], __ff[PFC.F_USAGE],
                __ff[PFC.F_EXPIRES], __ff[PFC.F_PERMS], __ff[PFC.F_UID],
                __ff[PFC.F_GID], __ff[PFC.F_KEY_NAME], __desc)

REGISTER_FILE("/proc/keys", ProcRootKEYS)
REGISTER_PARTIAL_FILE("keys", ProcRootKEYS)



if __name__ == "__main__":

    print "Collection of handlers to parse file in the root /proc directory"
