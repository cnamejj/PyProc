#!/usr/bin/env python

# ---
# (C) 2012-2013 Jim Jones <cnamejj@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.


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


