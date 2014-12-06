#!/usr/bin/env python

"""Handle records from /proc/schedstat data files"""

import regentest as RG
import ProcHandlers as PH

PFC = PH.ProcFieldConstants

# ---

def re_root_schedstat(inprecs):

    """Iterate through parsed records and re-generate data file"""

    __headtemp = "version {vers:d}\ntimestamp {stamp:d}"

    __cputemp = "{cpu:s} {yld:d} {switch:d} {calls:d} {idle:d} {wupcalls:d} \
{wuploc:d} {runsum:d} {waitsum:d} {slice:d}"

    __domaintemp = "{dom:s} {mask:s} {id_lb:d} {id_lb_pass:d} {id_lb_fail:d} \
{id_lb_imb:d} {id_pt:d} {id_pt_hot:d} {id_lb_noqu:d} {id_lb_nogr:d} {bu_lb:d} \
{bu_lb_pass:d} {bu_lb_fail:d} {bu_lb_imb:d} {bu_pt:d} {bu_pt_hot:d} \
{bu_lb_noqu:d} {bu_lb_nogr:d} {jb_lb:d} {jb_lb_pass:d} {jb_lb_fail:d} \
{jb_lb_imb:d} {jb_pt:d} {jb_pt_hot:d} {jb_lb_noqu:d} {jb_lb_nogr:d} {act_lb:d} \
{act_lb_fail:d} {act_lb_mov:d} {sbe_ct:d} {sbe_bal:d} {sbe_psh:d} {sbf_ct:d} \
{sbf_bal:d} {sbf_psh:d} {wup_dcpu:d} {wup_cold:d} {wup_pbal:d}"

    first = True

    for __hilit in inprecs:
        __ff = inprecs.field

        if first:
            first = False
            print __headtemp.format(vers=__ff[PFC.F_VERSION],
                    stamp=__ff[PFC.F_TIMESTAMP])

        print __cputemp.format(cpu=__ff[PFC.F_CPU_ID],
                yld=__ff[PFC.F_SCH_YIELD], switch=__ff[PFC.F_SCH_SW_EXP_Q],
                calls=__ff[PFC.F_SCH_CALLS], idle=__ff[PFC.F_SCH_IDLE],
                wupcalls=__ff[PFC.F_WUP_CALLS], wuploc=__ff[PFC.F_WUP_LOC_CPU],
                runsum=__ff[PFC.F_RUNNING_SUM], waitsum=__ff[PFC.F_WAITING_SUM],
                slice=__ff[PFC.F_SLICES])

#...+....1....+....2....+....3....+....4....+....5....+....6....+....7....+....8

        __dlist = __ff[PFC.F_DOM_ORDER]
        for __key in __dlist:
            __dom = __ff[__dlist[__key]]
            print __domaintemp.format(dom=__dlist[__key],
                    mask=__dom[PFC.F_CPU_MASK],
                    id_lb=__dom[PFC.F_IDLE_LB],
                    id_lb_pass=__dom[PFC.F_IDLE_LB_PASS],
                    id_lb_fail=__dom[PFC.F_IDLE_LB_FAIL],
                    id_lb_imb=__dom[PFC.F_IDLE_LB_IMBAL],
                    id_pt=__dom[PFC.F_IDLE_PT],
                    id_pt_hot=__dom[PFC.F_IDLE_PT_CACHE_HOT],
                    id_lb_noqu=__dom[PFC.F_IDLE_LB_NO_QUEUE],
                    id_lb_nogr=__dom[PFC.F_IDLE_LB_NO_GROUP],
                    bu_lb=__dom[PFC.F_BUSY_LB],
                    bu_lb_pass=__dom[PFC.F_BUSY_LB_PASS],
                    bu_lb_fail=__dom[PFC.F_BUSY_LB_FAIL],
                    bu_lb_imb=__dom[PFC.F_BUSY_LB_IMBAL],
                    bu_pt=__dom[PFC.F_BUSY_PT],
                    bu_pt_hot=__dom[PFC.F_BUSY_PT_CACHE_HOT],
                    bu_lb_noqu=__dom[PFC.F_BUSY_LB_NO_QUEUE],
                    bu_lb_nogr=__dom[PFC.F_BUSY_LB_NO_GROUP],
                    jb_lb=__dom[PFC.F_JBEI_LB],
                    jb_lb_pass=__dom[PFC.F_JBEI_LB_PASS],
                    jb_lb_fail=__dom[PFC.F_JBEI_LB_FAIL],
                    jb_lb_imb=__dom[PFC.F_JBEI_LB_IMBAL],
                    jb_pt=__dom[PFC.F_JBEI_PT],
                    jb_pt_hot=__dom[PFC.F_JBEI_PT_CACHE_HOT],
                    jb_lb_noqu=__dom[PFC.F_JBEI_LB_NO_QUEUE],
                    jb_lb_nogr=__dom[PFC.F_JBEI_LB_NO_GROUP],
                    act_lb=__dom[PFC.F_ACT_LB],
                    act_lb_fail=__dom[PFC.F_ACT_LB_FAIL],
                    act_lb_mov=__dom[PFC.F_ACT_LB_MOVED],
                    sbe_ct=__dom[PFC.F_SBE_COUNT],
                    sbe_bal=__dom[PFC.F_SBE_BALANCED],
                    sbe_psh=__dom[PFC.F_SBE_PUSHED],
                    sbf_ct=__dom[PFC.F_SBF_COUNT],
                    sbf_bal=__dom[PFC.F_SBF_BALANCED],
                    sbf_psh=__dom[PFC.F_SBF_PUSHED],
                    wup_dcpu=__dom[PFC.F_TRWUP_AWOKE_DIFF_CPU],
                    wup_cold=__dom[PFC.F_TRWUP_MOVE_CACHE_COLD],
                    wup_pbal=__dom[PFC.F_TRWUP_PASSIVE_BAL])

RG.RECREATOR[PH.GET_HANDLER("/proc/schedstat")] = re_root_schedstat
