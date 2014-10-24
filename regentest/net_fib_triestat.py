#!/usr/bin/env python

"""Handler records from /proc/net/fib_triestat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_net_fib_triestat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __main = "Main"
    __local = "Local"

    __head = "Basic info: size of leaf: {leaf:d} bytes, size of tnode: \
{tnode:d} bytes."

    __leadtemp = "{table:s}:\n\
\tAver depth:     {avgdep:.2f}\n\
\tMax depth:      {maxdep:d}\n\
\tLeaves:         {leaves:d}\n\
\tPrefixes:       {prefix:d}\n\
\tInternal nodes: {intnod:d}\n\
\t"

    __nodestemp = "{agg:s}  {nn:s}: {nsize:s}"

    __finishtemp = "\tPointers: {ptrs:d}\n\
Null ptrs: {nullp:d}\n\
Total size: {tsize:d}  kB\n\
\n\
Counters:\n\
---------\n\
gets = {gets:d}\n\
backtracks = {btrack:d}\n\
semantic match passed = {spass:d}\n\
semantic match miss = {smiss:d}\n\
null node hit= {nulln:d}\n\
skipped node resize = {skip:d}\n"

    __template = "{p1}{p2}\n{p3}"

    for __hilit in inprecs:
        __ff = inprecs.field

        # --- First times gets a header, but it needs data from the record
        if __head != "":
            print __head.format(leaf=__ff[PFC.F_LEAF_SIZE],
                    tnode=__ff[PFC.F_TNODE_SIZE])
            __head = ""

        # ---
        __id = __ff[PFC.F_NODE_NAME]
        if __id != __main and __id != __local:
            __id = "Id {id}".format(id=__id)

        __lead = __leadtemp.format(table=__id, avgdep=__ff[PFC.F_AVER_DEPTH], 
                maxdep=__ff[PFC.F_MAX_DEPTH], leaves=__ff[PFC.F_LEAVES], 
                prefix=__ff[PFC.F_PREFIXES], intnod=__ff[PFC.F_INT_NODES]
                )


        # --- build the list of node size info
        __nodes = ""
        __nlist = __ff[PFC.F_INT_NODE_LIST]

        for __off in range(0, len(__nlist)):
            __key, __val = __nlist[__off]
            __nodes = __nodestemp.format(agg=__nodes, nn=__key, nsize=__val)


        # --- 
        __finish = __finishtemp.format(ptrs=__ff[PFC.F_POINTERS], 
                nullp=__ff[PFC.F_NULL_PTRS], tsize=__ff[PFC.F_TOTAL_SIZE], 
                gets=__ff[PFC.F_GETS], btrack=__ff[PFC.F_BACKTRACKS], 
                spass=__ff[PFC.F_SEM_PASS], smiss=__ff[PFC.F_SEM_MISS], 
                nulln=__ff[PFC.F_NULL_NODE], skip=__ff[PFC.F_SKIPPED]
                )

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8
        print __template.format(p1=__lead, p2=__nodes, p3=__finish)

RG.RECREATOR[PH.GET_HANDLER("/proc/net/fib_triestat")] = re_net_fib_triestat
