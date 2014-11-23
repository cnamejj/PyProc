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
Handlers for files in the /proc/sysvipc directory
"""

import ProcBaseRoutines
import ProcFieldConstants
import ProcDataConstants

PBR = ProcBaseRoutines
PFC = ProcFieldConstants
PDC = ProcDataConstants

PREFIX = PBR.PREFIX_VAL
SUFFIX = PBR.SUFFIX_VAL
CONV = PBR.CONVERSION
NAME = PBR.FIELD_NAME
POS = PBR.FIELD_NUMBER
BEFORE = PBR.BEFORE_VAL
AFTER = PBR.AFTER_VAL
ERRVAL = PBR.ERROR_VAL
HAS = PBR.HAS_VAL
WORDS = PBR.WORDS_VAL
CONV = PBR.CONVERSION
BASE = PBR.NUM_BASE

REGISTER_FILE = PBR.register_file
REGISTER_PARTIAL_FILE = PBR.register_partial_file



# ---
class ProcSysvipcSHM(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/sysvipc/shm
    """

# source: ipc/shm.c
#
# static int sysvipc_shm_proc_show(struct seq_file *s, void *it)
# {
#     struct shmid_kernel *shp = it;
#     unsigned long rss = 0, swp = 0;
# 
#     shm_add_rss_swap(shp, &rss, &swp);
# 
# #if BITS_PER_LONG <= 32
# #define SIZE_SPEC "%10lu"
# #else
# #define SIZE_SPEC "%21lu"
# #endif
# 
#     return seq_printf(s,
#            "%10d %10d  %4o " SIZE_SPEC " %5u %5u  "
#            "%5lu %5u %5u %5u %5u %10lu %10lu %10lu "
#            SIZE_SPEC " " SIZE_SPEC "\n",
#            shp->shm_perm.key,
#            shp->shm_perm.id,
#            shp->shm_perm.mode,
#            shp->shm_segsz,
#            shp->shm_cprid,
#            shp->shm_lprid,
#            shp->shm_nattch,
#            shp->shm_perm.uid,
#            shp->shm_perm.gid,
#            shp->shm_perm.cuid,
#            shp->shm_perm.cgid,
#            shp->shm_atim,
#            shp->shm_dtim,
#            shp->shm_ctim,
#            rss * PAGE_SIZE,
#            swp * PAGE_SIZE);
# }
#

    def extra_init(self, *opts):
        self.minfields = 16
        self.skipped = "key"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_KEY, CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MODE, CONV: long, BASE: 8 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SIZE, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_CPID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_LPID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_ATTACH, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_OW_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_OW_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_CR_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_CR_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_ACC_TIME,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_DEST_TIME,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_CHAN_TIME,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 14, NAME: PFC.F_RSS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 15, NAME: PFC.F_SWAP, CONV: long } )
        return

    def extra_next(self, sio):

# -- Sample records
#
# The lines are too long to include here

        __id = self.field[PFC.F_ID]
        __key = self.field[PFC.F_KEY]
        __mode = self.field[PFC.F_MODE]
        __size = self.field[PFC.F_SIZE]
        __pid = self.field[PFC.F_CPID]
        __att = self.field[PFC.F_ATTACH]
        __uid = self.field[PFC.F_OW_UID]
        __gid = self.field[PFC.F_OW_GID]
        __access = self.field[PFC.F_ACC_TIME]
        __destroy = self.field[PFC.F_DEST_TIME]
        __change = self.field[PFC.F_CHAN_TIME]

        return(__id, __key, __mode, __size, __att, __pid, __uid, __gid,
                __access, __destroy, __change)

#
REGISTER_FILE("/proc/sysvipc/shm", ProcSysvipcSHM)
REGISTER_PARTIAL_FILE("shm", ProcSysvipcSHM)



# ---
class ProcSysvipcSEM(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/sysvipc/sem
    """

# source: ipc/sem.c
#
# static int sysvipc_sem_proc_show(struct seq_file *s, void *it)
# {
#    struct sem_array *sma = it;
# 
#    return seq_printf(s,
#         "%10d %10d  %4o %10u %5u %5u %5u %5u %10lu %10lu\n",
#         sma->sem_perm.key,
#         sma->sem_perm.id,
#         sma->sem_perm.mode,
#         sma->sem_nsems,
#         sma->sem_perm.uid,
#         sma->sem_perm.gid,
#         sma->sem_perm.cuid,
#         sma->sem_perm.cgid,
#         sma->sem_otime,
#         sma->sem_ctime);
# }
#

    def extra_init(self, *opts):
        self.minfields = 10
        self.skipped = "key"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_KEY, CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MODE, CONV: long, BASE: 8 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_SEMS, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_OW_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_OW_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_CR_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_CR_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_UPD_TIME, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_CHAN_TIME,
                CONV: long } )
        return

    def extra_next(self, sio):

# -- Sample records
#
#      key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime
#  3121959      32768   666          2     0     0     0     0 1396450035 1395779560
#        0     131073   600          1    33    33     0     0 1396474718 1396190194
# 59918130      98306   600          1   501   501   501   501 1396390845 1395797851
#

        __id = self.field[PFC.F_ID]
        __key = self.field[PFC.F_KEY]
        __mode = self.field[PFC.F_MODE]
        __nsems = self.field[PFC.F_SEMS]
        __uid = self.field[PFC.F_OW_UID]
        __gid = self.field[PFC.F_OW_GID]
        __update = self.field[PFC.F_UPD_TIME]
        __change = self.field[PFC.F_CHAN_TIME]

        return(__id, __key, __mode, __nsems, __uid, __gid,
                __update, __change)

#
REGISTER_FILE("/proc/sysvipc/sem", ProcSysvipcSEM)
REGISTER_PARTIAL_FILE("sem", ProcSysvipcSEM)



# ---
class ProcSysvipcMSG(PBR.FixedWhitespaceDelimRecs):
    """
    Pull records from /proc/sysvipc/msg
    """

# source: ipc/msg.c
#
# static int sysvipc_msg_proc_show(struct seq_file *s, void *it)
# {
#    struct msg_queue *msq = it;
#
#    return seq_printf(s,
#       "%10d %10d  %4o  %10lu %10lu %5u %5u %5u %5u %5u %5u %10lu %10lu %10lu\n",
#       msq->q_perm.key,
#       msq->q_perm.id,
#       msq->q_perm.mode,
#       msq->q_cbytes,
#       msq->q_qnum,
#       msq->q_lspid,
#       msq->q_lrpid,
#       msq->q_perm.uid,
#       msq->q_perm.gid,
#       msq->q_perm.cuid,
#       msq->q_perm.cgid,
#       msq->q_stime,
#       msq->q_rtime,
#       msq->q_ctime);
# }
#

    def extra_init(self, *opts):
        self.minfields = 14
        self.skipped = "key"

        PBR.add_parse_rule(self, { POS: 0, NAME: PFC.F_KEY, CONV: long } )
        PBR.add_parse_rule(self, { POS: 1, NAME: PFC.F_ID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 2, NAME: PFC.F_MODE, CONV: long, BASE: 8 } )
        PBR.add_parse_rule(self, { POS: 3, NAME: PFC.F_BYTES, CONV: long } )
        PBR.add_parse_rule(self, { POS: 4, NAME: PFC.F_QUEUES, CONV: long } )
        PBR.add_parse_rule(self, { POS: 5, NAME: PFC.F_SEND_PID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 6, NAME: PFC.F_RECV_PID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 7, NAME: PFC.F_OW_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 8, NAME: PFC.F_OW_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 9, NAME: PFC.F_CR_UID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 10, NAME: PFC.F_CR_GID, CONV: long } )
        PBR.add_parse_rule(self, { POS: 11, NAME: PFC.F_SEND_TIME,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 12, NAME: PFC.F_RECV_TIME,
                CONV: long } )
        PBR.add_parse_rule(self, { POS: 13, NAME: PFC.F_CHAN_TIME,
                CONV: long } )
        return

    def extra_next(self, sio):

        __id = self.field[PFC.F_ID]
        __key = self.field[PFC.F_KEY]
        __mode = self.field[PFC.F_MODE]
        __bytes = self.field[PFC.F_BYTES]
        __queues = self.field[PFC.F_QUEUES]
        __spid = self.field[PFC.F_SEND_PID]
        __rpid = self.field[PFC.F_RECV_PID]
        __uid = self.field[PFC.F_OW_UID]
        __gid = self.field[PFC.F_OW_GID]
        __stime = self.field[PFC.F_SEND_TIME]
        __rtime = self.field[PFC.F_RECV_TIME]
        __change = self.field[PFC.F_CHAN_TIME]

        return(__id, __key, __mode, __bytes, __queues, __uid, __gid, __spid,
                __rpid, __stime, __rtime, __change)

#
REGISTER_FILE("/proc/sysvipc/msg", ProcSysvipcMSG)
REGISTER_PARTIAL_FILE("msg", ProcSysvipcMSG)



if __name__ == "__main__":

    print "Collection of handlers to parse files in the /proc/sysvpic \
directory"

