#!/usr/bin/env python

"""Handle records from /proc/net/fib_trie files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC 

__NODETEMP = "{pad:s}+-- {net:s}/{mask:d} {bits:d} {full:d} {empty:d}"
__LEAFTEMP = "{pad:s}|-- {net:s}"
__SCOPETEMP = "{pad:s}/{mask:d} {scope:s} {styp:s}"

# ---

def print_leaf(lev, leaf):

    """Print info for this leaf node any any scope subrecords"""

    __pad = " " * (lev * 3)
    print __LEAFTEMP.format(pad=__pad[1:], net=leaf[PFC.F_NETWORK])

    if leaf.has_key(PFC.F_SCOPE):
        lev += 1
        __pad = " " * (lev * 3)

        for __seq in range(0, len(leaf[PFC.F_SCOPE])):
            __sc = leaf[PFC.F_SCOPE][__seq]
            print __SCOPETEMP.format(pad=__pad[1:], mask=__sc[PFC.F_NETMASK],
                    scope=__sc[PFC.F_SCOPE], styp=__sc[PFC.F_TYPE])

# ---

def print_node_and_dive(lev, node):

    """
    Print info on the current node and if there are other nodes or
    leaves in the structure, push the level and call a method to
    handle them before returning.
    """

    __pad = " " * (lev*3)
    print __NODETEMP.format(pad=__pad[1:], net=node[PFC.F_NETWORK],
       mask=node[PFC.F_NETMASK], bits=node[PFC.F_FIB_BITS],
       full=node[PFC.F_FULL_CHILDREN], empty=node[PFC.F_EMPTY_CHILDREN])
 
    lev += 1

    if node.has_key(PFC.F_NODE):
        for __seq in range(0, len(node[PFC.F_NODE])):
            print_node_and_dive(lev, node[PFC.F_NODE][__seq])

    if node.has_key(PFC.F_FIB_LEAF):
        for __seq in range(0, len(node[PFC.F_FIB_LEAF])):
            print_leaf(lev, node[PFC.F_FIB_LEAF][__seq])
    
# ---

def re_net_fib_trie(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __toptemp = "{node:s}:"

    for __hilit in inprecs:
        __ff = inprecs.field
        __fib = __ff[PFC.F_FIB_TRIE]

        print __toptemp.format(node=__ff[PFC.F_NODE_NAME])

        __level = 1
        for __seq in range(0, len(__fib[PFC.F_NODE])):
            print_node_and_dive(__level, __fib[PFC.F_NODE][__seq])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/net/fib_trie")] = re_net_fib_trie
