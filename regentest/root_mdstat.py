#!/usr/bin/env python

"""Handle records from /proc/mdstat files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.PFC

__MDPREF_TEMP = "{rec:s} : {stat:s}"
__READONLY_TEMP = "{acc:s} {stat:s}"
__PERS_TEMP = "{acc:s} {pers:s}"
__PART_TEMP = "{acc:s} {part:s}[{pnum:d}]{wrmostly:s}{faulty:s}{spare:s}"

__BLOCKPREF_TEMP = "      {blocks:d} blocks"
__SUPER_TEMP = "{acc:s} super {stype:s}"
__CHUNK_TEMP = "{acc:s} {size:d}K chunks"
__NEAR_TEMP = "{acc:s} {size:d} near-copies"
__OFFSET_TEMP = "{acc:s} {size:d} offset-copies"
__FAR_TEMP = "{acc:s} {size:d} far-copies"
__RPARTS_TEMP = "{acc:s} [{tot:d}/{act:d}] {use:s}"

__RESYNC_TEMP = "resync={stat:s}"

__REBUILD_TEMP = "      {prog:s}  {action:s} ={pc:5.1f}% ({done:d}/{tot:d}) \
finish={fin:.1f}min speed={speed:d}K/sec"

__BITMAP_TEMP = "      bitmap: {pgnom:d}/{pgtot:d} pages [{pgnomkb:d}KB], \
{chunk:d}{un:s} chunk{path:s}"
__BITMAPPATH_TEMP = ", file: {path:s} \t"

__NORMAL_SPACER = "      "
__BITMAP_SPACER = ""

__READONLY_DESC = { 1: "(read-only)", 2: "(auto-read-only)" }
__WRMOSTLY_DESC = { 1: "(W)", 0: "" }
__FAULTY_DESC = { 1: "(F)", 0: "" }
__SPARE_DESC = { 1: "(S)", 0: "" }

# ---

def gen_bitmap_subrec_info(pdata, pmap):
    """If we have bitmap subrec info, regenerate that raw line"""

    __show_as_kb = "KB"
    __show_as_b = "B"

    if pmap.has_key(PFC.F_PAGES_NOMISS):
        if pdata[PFC.F_BITMAP_CHUNK_TUNITS] == __show_as_kb:
            __chunk = pdata[PFC.F_BITMAP_CHUNK] / 1024
            __units = __show_as_kb
        else:
            __chunk = pdata[PFC.F_BITMAP_CHUNK]
            __units = __show_as_b

        if pmap.has_key(PFC.F_FILEPATH):
            __path = __BITMAPPATH_TEMP.format(path=pdata[PFC.F_FILEPATH])
        else:
            __path = ""

        print __BITMAP_TEMP.format(pgnom=pdata[PFC.F_PAGES_NOMISS],
                pgtot=pdata[PFC.F_PAGES_TOTAL],
                pgnomkb=pdata[PFC.F_PAGES_NOMISS_KB], chunk=__chunk,
                un=__units, path=__path)

# ---

def gen_rebuild_subrec_info(pdata, pmap):
    """For a subrec _DESCribing a rebuild in progress, regen the line"""

    if pmap.has_key(PFC.F_REBUILD_PROG):
        print __REBUILD_TEMP.format(prog=pdata[PFC.F_REBUILD_PROG],
                action=pdata[PFC.F_REBUILD_ACTION], pc=pdata[PFC.F_PERCENT],
                done=pdata[PFC.F_REBUILD_DONE], tot=pdata[PFC.F_REBUILD_TOTAL],
                fin=pdata[PFC.F_FIN_TIME], speed=pdata[PFC.F_SPEED])

# ---

def gen_resync_subrec_info(pdata, pmap):
    """For subrec's w/ summary resync status, regenerate the original line"""

    if pmap.has_key(PFC.F_RESYNC_STAT):
        print __RESYNC_TEMP.format(stat=pdata[PFC.F_RESYNC_STAT])

# ---

def gen_blocks_subrec_info(pdata, pmap):
    """If we have block subrec info, regenerate that raw line"""

    if not pmap.has_key(PFC.F_BLOCKS):
        return

    __out = __BLOCKPREF_TEMP.format(blocks=pdata[PFC.F_BLOCKS])

    if pmap.has_key(PFC.F_SUPER):
        __out = __SUPER_TEMP.format(acc=__out, stype=pdata[PFC.F_SUPER])

    if pmap.has_key(PFC.F_CHUNK):
        __out = __CHUNK_TEMP.format(acc=__out, size=pdata[PFC.F_CHUNK])

    if pmap.has_key(PFC.F_NEAR_COPY):
        __out = __NEAR_TEMP.format(acc=__out, size=pdata[PFC.F_NEAR_COPY])

    if pmap.has_key(PFC.F_OFFSET_COPY):
        __out = __OFFSET_TEMP.format(acc=__out, size=pdata[PFC.F_OFFSET_COPY])

    if pmap.has_key(PFC.F_FAR_COPY):
        __out = __FAR_TEMP.format(acc=__out, size=pdata[PFC.F_FAR_COPY])

    __out = __RPARTS_TEMP.format(acc=__out, tot=pdata[PFC.F_TOTAL_PARTS],
            act=pdata[PFC.F_ACTIVE_PARTS], use=pdata[PFC.F_PART_USEMAP])

    print __out


# ---

def gen_mdstat_info(inprecs):
    """Regenerate raw data for a 'md device status' record"""

    __ff = inprecs.field
    __pmap = inprecs.parse_map
    __order = inprecs.partition_order

    __out = __MDPREF_TEMP.format(rec=__ff[PFC.F_REC_TYPE],
            stat=__ff[PFC.F_ACTIVE_STAT])

    if __pmap.has_key(PFC.F_READONLY):
        __out = __READONLY_TEMP.format(acc=__out,
                stat=__READONLY_DESC[__ff[PFC.F_READONLY]])

    __out = __PERS_TEMP.format(acc=__out, pers=__ff[PFC.F_PERS_NAME])

    for __seq in range(0, len(__order)):
        __pnum = __order[__seq]

        __out = __PART_TEMP.format(acc=__out,
                part=__ff[PFC.F_PARTITION_LIST][__pnum], pnum=__pnum,
                wrmostly=__WRMOSTLY_DESC[__ff[PFC.F_WRMOSTLY_LIST][__pnum]],
                faulty=__FAULTY_DESC[__ff[PFC.F_FAULTY_LIST][__pnum]],
                spare=__SPARE_DESC[__ff[PFC.F_SPARE_LIST][__pnum]])

    print __out

    gen_blocks_subrec_info(__ff, __pmap)

    gen_rebuild_subrec_info(__ff, __pmap)

    gen_resync_subrec_info(__ff, __pmap)

    gen_bitmap_subrec_info(__ff, __pmap)

    if __pmap.has_key(PFC.F_PAGES_NOMISS):
        print __BITMAP_SPACER
    else:
        print __NORMAL_SPACER

# ---

def re_root_mdstat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __perstemp = "Personalities : {plist:s}{trail:s}"
    __unusedtemp = "unused devices: {devs:s}"

    __rec_personality = "Personalities"
    __rec_unused = "unused"

    for __hilit in inprecs:
        __ff = inprecs.field
        __rec = __ff[PFC.F_REC_TYPE]

        if __rec == __rec_personality:
            __plist = " ".join(__ff[PFC.F_PERSONALITIES])
            if __plist != "":
                __trail = " "
            else:
                __trail = ""
            print __perstemp.format(plist=__plist, trail=__trail)

        elif __rec == __rec_unused:
            print __unusedtemp.format(devs=" ".join(__ff[PFC.F_DEVICE_LIST]))

        else:
            gen_mdstat_info(inprecs)

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

RG.RECREATOR[PH.GET_HANDLER("/proc/mdstat")] = re_root_mdstat
