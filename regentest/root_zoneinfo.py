#!/usr/bin/env python

"""Handle records from /proc/zoneinfo data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_zoneinfo(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __leadtemp = "Node {node:d}, zone {zone:>8s}\n\
  pages free     {free:d}\n\
        min      {min:d}\n\
        low      {low:d}\n\
        high     {hi:d}\n\
        scanned  {scan:d}\n\
        spanned  {span:d}\n\
        present  {pres:d}"

    __managetemp = "        managed  {man:d}"

    __zonestattemp = "    {name:<12s} {val:d}"

    __nextpref = ", "
    __prlisttemp = "{acc:s}{delim:s}{next:d}"
    __protecttemp = "        protection: ({prlist:s})"

    __pagesetlead = "  pagesets"
    __pageinfotemp = "    cpu: {cpu:d}\n\
              count: {count:d}\n\
              high:  {high:d}\n\
              batch: {batch:d}"

    __vmstatstemp = "  vm stats threshold: {vmstats:d}"

    __finishtemp = "  all_unreclaimable: {unrec:d}\n\
  start_pfn:         {spfn:d}\n\
  inactive_ratio:    {inrat:d}"

    __lab = { PFC.F_NR_FREE_PAGES: "nr_free_pages",
            PFC.F_NR_INACTIVE_ANON: "nr_inactive_anon",
            PFC.F_NR_ACTIVE_ANON: "nr_active_anon",
            PFC.F_NR_INACTIVE_FILE: "nr_inactive_file",
            PFC.F_NR_ACTIVE_FILE: "nr_active_file",
            PFC.F_NR_UNEVICTABLE: "nr_unevictable",
            PFC.F_NR_MLOCK: "nr_mlock",
            PFC.F_NR_ANON_PAGES: "nr_anon_pages",
            PFC.F_NR_MAPPED: "nr_mapped",
            PFC.F_NR_FILE_PAGES: "nr_file_pages",
            PFC.F_NR_DIRTY: "nr_dirty",
            PFC.F_NR_WRITEBACK: "nr_writeback",
            PFC.F_NR_SLAB_RECLAIM: "nr_slab_reclaimable",
            PFC.F_NR_SLAB_UNRECLAIM: "nr_slab_unreclaimable",
            PFC.F_NR_PAGE_TABLE_PAGES: "nr_page_table_pages",
            PFC.F_NR_KERNEL_STACK: "nr_kernel_stack",
            PFC.F_NR_UNSTABLE: "nr_unstable",
            PFC.F_NR_BOUNCE: "nr_bounce",
            PFC.F_NR_VMSCAN_WRITE: "nr_vmscan_write",
            PFC.F_NR_VMSCAN_IMM_RECLAIM: "nr_vmscan_immediate_reclaim",
            PFC.F_NR_WRITEBACK_TEMP: "nr_writeback_temp",
            PFC.F_NR_ISOLATED_ANON: "nr_isolated_anon",
            PFC.F_NR_ISOLATED_FILE: "nr_isolated_file",
            PFC.F_NR_SHMEM: "nr_shmem",
            PFC.F_NR_DIRTIED: "nr_dirtied",
            PFC.F_NR_WRITTEN: "nr_written",
            PFC.F_NUMA_HIT: "numa_hit",
            PFC.F_NUMA_MISS: "numa_miss",
            PFC.F_NUMA_FOREIGN: "numa_foreign",
            PFC.F_NUMA_INTERLEAVE: "numa_interleave",
            PFC.F_NUMA_LOCAL: "numa_local",
            PFC.F_NUMA_OTHER: "numa_other",
            PFC.F_NR_ANON_TRANS_HUGE: "nr_anon_transparent_hugepages",
            PFC.F_NR_FREE_CMA: "nr_free_cma"
            }

    __fence = PFC.F_PAGES_PRESENT
    __stop = PFC.F_PROTECTION

    __count_key = "count"
    __high_key = "high"
    __batch_key = "batch"
    __vm_stats_key = "vm-stats-thresh"

    for __hilit in inprecs:
        __ff = inprecs.field
        __hits = inprecs.hit_order

        print __leadtemp.format(node=__ff[PFC.F_NODE], zone=__ff[PFC.F_ZONE],
                free=__ff[PFC.F_PAGES_FREE], min=__ff[PFC.F_PAGES_MIN],
                low=__ff[PFC.F_PAGES_LOW], hi=__ff[PFC.F_PAGES_HIGH],
                scan=__ff[PFC.F_PAGES_SCANNED], span=__ff[PFC.F_PAGES_SPANNED],
                pres=__ff[PFC.F_PAGES_PRESENT])

        for __off in range(0, len(__hits)):
            if __hits[__off] == PFC.F_PAGES_MANAGED:
                print __managetemp.format(man=__ff[PFC.F_PAGES_MANAGED])
           
        for __off in range(0, len(__hits)):
            __key = __hits[__off]

            if __lab.has_key(__key):
                print __zonestattemp.format(name=__lab[__key], val=__ff[__key])

        __prlist = ""
        __sep = ""
        for __lowmem in __ff[PFC.F_PROTECTION]:
            __prlist = __prlisttemp.format(acc=__prlist, delim=__sep,
                    next=__lowmem)
            __sep = __nextpref

        print __protecttemp.format(prlist=__prlist)

        print __pagesetlead
        __cpusets = __ff[PFC.F_CPU_PAGESETS]
        for __cpu in __cpusets:
            __pageset = __cpusets[__cpu]

            print __pageinfotemp.format(cpu=__cpu, count=__pageset[__count_key],
                    high=__pageset[__high_key], batch=__pageset[__batch_key])

            if __pageset.has_key(__vm_stats_key):
                print __vmstatstemp.format(vmstats=__pageset[__vm_stats_key])

        print __finishtemp.format(unrec=__ff[PFC.F_ALL_UNRECLAIM],
                spfn=__ff[PFC.F_START_PFN], inrat=__ff[PFC.F_INACTIVE_RATIO])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/zoneinfo")] = re_root_zoneinfo
