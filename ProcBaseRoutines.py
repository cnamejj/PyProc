#!/usr/bin/env python

"""
Base classes and general purpose utility methods
"""

import os
import SeqFileIO
import ProcFieldConstants
import ProcDataConstants
#import numpy

PFC = ProcFieldConstants
F_NULL_HANDLER = PFC.F_NULL_HANDLER
F_PROTOCOL = PFC.F_PROTOCOL
F_TERM_LIST = PFC.F_TERM_LIST

PDC = ProcDataConstants

# --

CONVERSION = "convtype"
FIELD_NAME = "fieldname"
FIELD_NUMBER = "fieldnumber"
ERROR_VAL = "errval"
NUM_BASE = "base"
PREFIX_VAL = "prefix"
SUFFIX_VAL = "suffix"
BEFORE_VAL = "before"
AFTER_VAL = "after"
HAS_VAL = "has"
WORDS_VAL = "words"
SUBWORD = "subword"

# --
PROC_PATH_PREFIX_LIST = ( "/proc", "/proc/", "/proc/net/", "/proc/self/net/",
        "/proc/self/", "/proc/sysvipc/" )

FILE_HANDLER_REGISTRY = dict()
PARTIAL_HANDLER_REGISTRY = dict()
HANDLER_TO_PATH = dict()


# ---
def hilo_pair_from_str(raw):
    """
    Convert '%d.%6d' float to long by shifting decimal places
    """

    __parts = raw.partition(".")
    if len(__parts) == 3:
        try:
            __res = long(__parts[0]) * 1000000 + long(__parts[2])
        except ValueError:
            __res = 0
    else:
        __res = 0

    return __res


# ---

def error_by_rule(rule):
    """Return an appropriate error value based on the ruleset supplied."""

    try:
        __conv = rule[CONVERSION]
    except KeyError:
        __conv = str

    try:
        __err = rule[ERROR_VAL]
    except KeyError:
        if __conv == int:
            __err = 0
        elif __conv == long:
            __err = 0L
        elif __conv == float:
            __err = 0.0
        else:
            __err = ""

    return __err

def apply_string_check(rawdata, check, val):
    """
    Apply the selection criteria and return hit/miss and transformed string
    """

    __hit = True
    __trans = rawdata

    if check is WORDS_VAL:
        __hit = val == len(__trans.split())

    elif check is HAS_VAL:
        __hit = __trans.find(val) != -1

    elif check is SUBWORD:
        __split = __trans.split()
        __hit = val < len(__split)
        if __hit:
            __trans = __split[val]

    elif check is PREFIX_VAL:
        __hit = __trans.startswith(val)
        if __hit:
            __trans = __trans[len(val):]

    elif check is SUFFIX_VAL:
        __hit = __trans.endswith(val)
        if __hit:
            __trans = __trans[:-len(val)]

    elif check is BEFORE_VAL:
        __split = __trans.partition(val)
        if len(__split) == 3:
            if len(__split[1]) > 0:
                __trans = __split[0]
            else:
                __hit = False
        else:
            __hit = False

    elif check is AFTER_VAL:
        __split = __trans.partition(val)
        if len(__split) != 3:
            __hit = False
        elif len(__split[1]) == 0:
            __hit = False
        else:
            __trans = __split[2]

    return(__hit, __trans)

def matches_all_crit(rawdata, rule, order = ""):
    """
    Test to see if 'rawdata' passes all selection tests in the given 
    parse rule.
    """

    __result = True
    __raw = rawdata
    __crit = dict()
    __def_order = ( WORDS_VAL, HAS_VAL, PREFIX_VAL, SUFFIX_VAL, BEFORE_VAL,
            AFTER_VAL )

    if order == "":
        order = __def_order

#    print "dbg:: MAC: order({olist})".format(olist=str(order))

    for __check in order:
        __crit[__check] = True
        if __result and rule.has_key(__check):
            __val = rule[__check]
            __result, __raw = apply_string_check(__raw, __check, __val)
#            print "dbg:: MAC: L1: rc({rc}) ch({ch}) v({val}) buf({raw})".format(ch=__check, rc=__result, raw=__raw, val=__val)

#    print "dbg:: MAC: break: crit({crit})".format(crit=str(__crit))

    for __check in rule:
#        print "dbg:: MAC: L2.1: rc({rc}) ch({ch}) has({has})".format(ch=__check, rc=__result, has=__crit.has_key(__check))
 
        if not __result:
            __need = False
        elif __crit.has_key(__check): 
            __need = not __crit[__check]
        else:
            __need = True
      
        if __need:
            __val = rule[__check]
            __result, __raw = apply_string_check(__raw, __check, __val)
#            print "dbg:: MAC: L2.2: rc({rc}) ch({ch}) v({val}) buf({raw})".format(ch=__check, rc=__result, raw=__raw, val=__val)

    return __result

def conv_by_rules(rawdata, rule, order=""):
    """Apply ruleset to string, by order if given, return parsed result"""

# see if we can use a different default without breaking too many things...
#    __def_order = ( SUBWORD, BEFORE_VAL, AFTER_VAL, PREFIX_VAL, SUFFIX_VAL )
    __def_order = ( PREFIX_VAL, SUFFIX_VAL, SUBWORD, AFTER_VAL, BEFORE_VAL )

    if order == "":
        order = __def_order

#    print "dbg:: CBR: order({order})".format(order=str(order))

    try:
        __conv = rule[CONVERSION]
    except KeyError:
        __conv = str

    try:
        __base = rule[NUM_BASE]
    except KeyError:
        __base = 10

    __hit = True
    __val = rawdata
    __used = dict()

    for __cr in order:
        __used[__cr] = True
        if __hit and rule.has_key(__cr):
            __hit, __val = apply_string_check(__val, __cr, rule[__cr])

    for __cr in rule:
#        print "dbg:: CBR: L2.1: rc({rc}) ch({ch}) has({has})".format(ch=__cr, rc=__hit, has=__used.has_key(__cr))
        if not __hit:
            __need = False
        elif __used.has_key(__cr):
            __need = not __used[__cr]
        else:
            __need = True

        if __need:
            __hit, __val = apply_string_check(__val, __cr, rule[__cr])
#            print "dbg:: CBR: L2.2: rc({rc}) ch({ch}) v({val}) buf({raw})".format(ch=__cr, rc=__hit, raw=__val, val=rule[__cr])

    try:
        if not __hit:
            __val = error_by_rule(rule)
        elif __conv == int:
            __val = int(__val, __base)
        elif __conv == long:
            __val = long(__val, __base)
        elif __conv == float:
            __val = float(__val)
    except ValueError:
        __val = error_by_rule(rule)

    return __val

# ---

def number_or_unlimited(buff):
    """Convert a string to a long, or set to an error value"""


    if buff.strip() == "unlimited":
        result = PDC.INF
    else:
        try:
            result = long(buff)
        except ValueError:
            result = PDC.NAN

    return result


def array_of_longs(wordlist):
    """Convert a list of strings to long's"""

    __nums = dict()

    for __off in range(0, len(wordlist)):
        __nums[__off] = long(wordlist[__off])

    return(__nums)


def breakout_option_list(combined, delim = ",", assign = "="):
    """Convert a string of name=value pairs to a dictionary"""

    __optlist = dict()
    __entries = combined.split(delim)

    for __off in range(0, len(__entries)):
        __part = __entries[__off].partition(assign)
        if len(__part) == 3:
            __optlist[__part[0]] = __part[2]
        else:
            __optlist[__entries[__off]] = ""
    return(__optlist)

# ---


def get_file_registry():
    """Return the file handler registry"""

    return(FILE_HANDLER_REGISTRY)

def get_partial_file_registry():
    """Return the file handler registry for partial file path matches"""

    return(PARTIAL_HANDLER_REGISTRY)

def proc_file_to_path(proc_file):
    """
    If the arg passed in doesn't exist, try prepending well known directories
    to find the file.
    """

    __path = ""

    if os.path.isfile(proc_file):
        __path = proc_file
    else:
        for __pref in PROC_PATH_PREFIX_LIST:
            __trial = "{prefix}{file}".format(prefix=__pref, file=proc_file)
            if __path == "" and os.path.isfile(__trial):
                __path = __trial

    return __path

def proc_file_to_symlink(proc_file):
    """
    If the arg passed in doesn't exist, try prepending well known directories
    to find the file.
    """

    __path = ""

    if os.path.islink(proc_file):
        __path = proc_file
    else:
        for __pref in PROC_PATH_PREFIX_LIST:
            __trial = "{prefix}{file}".format(prefix=__pref, file=proc_file)
            if __path == "" and os.path.islink(__trial):
                __path = __trial

    return __path

def get_handler(proc_file):
    """
    Lookup routine to find the code that knows how to parse the requested
    /proc/net/ datafile
    """

    __handler = 0
    __append_list = PROC_PATH_PREFIX_LIST

    if proc_file in FILE_HANDLER_REGISTRY:
        __handler = FILE_HANDLER_REGISTRY[proc_file]
    else:
        for __prefix in __append_list:
            __exp_file = "{prefix}{procfile}".format(prefix=__prefix,
                             procfile=proc_file)
            if __exp_file in FILE_HANDLER_REGISTRY:
                __handler = FILE_HANDLER_REGISTRY[__exp_file]

    if __handler == 0:
        __matchlen = 0
        for __patt in PARTIAL_HANDLER_REGISTRY:
            if len(__patt) <= __matchlen:
                pass

            elif __patt.endswith("/"):
                __parts = proc_file.split(__patt)
                if(len(__parts) > 1):
                    if __parts[-1:][0].find("/") == -1:
                        __matchlen = len(__patt)
                        __handler = PARTIAL_HANDLER_REGISTRY[__patt]

            elif proc_file.endswith(__patt):
                __matchlen = len(__patt)
                __handler = PARTIAL_HANDLER_REGISTRY[__patt]

    if __handler == 0:
        __handler = FILE_HANDLER_REGISTRY[F_NULL_HANDLER]

    return __handler

def register_file(proc_file, handler):
    """Associate the given code object with a specific /proc/net datafile"""

    FILE_HANDLER_REGISTRY[proc_file] = handler
    HANDLER_TO_PATH[str(handler)] = proc_file

def register_partial_file(end_of_path, handler):
    """
    Associate the given code object with a filename pattern to allow partial
    matches
    """

    PARTIAL_HANDLER_REGISTRY[end_of_path] = handler

def show_proc_file_handlers():
    """Print a list of all the known file to handler mappings"""

    for __file in FILE_HANDLER_REGISTRY:
        print "For {file} use {handler}".format(file=__file,
               handler=str(FILE_HANDLER_REGISTRY[__file].__name__))

def show_partial_proc_file_handlers():
    """
    Print a list of all the known 'end of path' file patterns and their handler
    mappings
    """

    for __patt in PARTIAL_HANDLER_REGISTRY:
        print "Path {patt} matches {handler}".format(patt=__patt,
                handler=str(PARTIAL_HANDLER_REGISTRY[__patt]))

def show_handler_file_path(cl_instance):
    """
    Return the fullpath of the /proc file associated with the base class of the
    instance provided
    """

    __key = "<class '{tmod}.{tcl}'>".format(
                tmod=cl_instance.__class__.__module__,
                tcl=cl_instance.__class__.__name__)
    return HANDLER_TO_PATH[__key]

def add_parse_rule(handler, rule, order=""):
    """
    Append the supplied ruleset to the list of parsing rules defined
    for the instance of the file parser.
    """

    __rn = len(handler.parse_rule)
#    print "dbg:: apr: n:{rn:d} r({rule})".format(rn=__rn, rule=str(rule))

    if rule.has_key(FIELD_NUMBER) or not rule.has_key(FIELD_NAME):
        handler.floating_rule[__rn] = False
    elif rule.has_key(PREFIX_VAL) or rule.has_key(SUFFIX_VAL):
        # -- rules without a field number, but that have a prefix
        # -- and/or suffix check are parsed separately
        handler.floating_rule[__rn] = True
    else:
        handler.floating_rule[__rn] = False

    handler.parse_rule[__rn] = (rule, order)

# ---
class ProcNetNULL(object):
    """
    Dummy class that just acts like reading from an empty file, returned as the
    handler for unrecognized files.
    """

    def __init__(self, *opts):
        """For the dummy handler, just need to make an empty results field."""
        self.field = dict()

    def __iter__(self):
        """Standard component of an iterator class"""
        return(self)

    def next(self):
        """The dummy iterator signals EOF when a record is requested."""    
        raise StopIteration
#
register_file(F_NULL_HANDLER, ProcNetNULL)



# ---
class FixedWhitespaceDelimRecs(object):
    """
    Base class to read simple files with whitespace delimited columns,
    consistent record format
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def extra_next(self, sio):
        """No-op version of optional call-out from 'next' method"""

#        print "base:extra_next: {this}".format(this=str(self))
        return(sio.buff)

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#               file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 0
        self.skipped = ""
        self.parse_rule = dict()
        self.floating_rule = dict()
        self.fixpos_hits = dict()
        self.floating_hits = dict()

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

 

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

#        print "base:next: {this}".format(this=str(self))
        self.field = dict()
        sio = self.curr_sio
        sio.read_line()

        __hit_rule = dict()
        self.fixpos_hits = dict()
        self.floating_hits = dict()
        __fix_seq = 0
        __flo_seq = 0

        # -- for each word, see if a floating (pos independent) rule applies
        for __off in range(0, sio.linewords):
            __val = sio.lineparts[__off]
            for __rulenum in self.parse_rule:
                if self.floating_rule[__rulenum]:
                    __rinfo = self.parse_rule[__rulenum]
                    __cr = __rinfo[0]
                    try:
                        __ord = __rinfo[1]
                    except IndexError:
                        __ord = ""
                    __name = __cr[FIELD_NAME]
                    __match = True

                    if __cr.has_key(PREFIX_VAL):
                        __match = __match and __val.startswith(
                                __cr[PREFIX_VAL])

                    if __cr.has_key(SUFFIX_VAL):
                        __match = __match and __val.endswith(__cr[SUFFIX_VAL])

                    if __match:
                        self.field[__name] = conv_by_rules(__val, __cr, __ord)
                        __hit_rule[__rulenum] = 1
                        self.floating_hits[__flo_seq] = __name
                        __flo_seq += 1

        # -- run through the rules and convert fixed columns as directed, this
        # -- has to be done separately to make sure error values are set for
        # -- fields that match columns past the ones we got in the last read.
        for __rulenum in self.parse_rule:
            __rinfo = self.parse_rule[__rulenum]
            __cr = __rinfo[0]
            try:
                __ord = __rinfo[1]
            except IndexError:
                __ord = ""
            if __cr.has_key(FIELD_NUMBER) and __cr.has_key(FIELD_NAME):
                __hit_rule[__rulenum] = 1
                __off = __cr[FIELD_NUMBER]
                __name = __cr[FIELD_NAME]
                self.fixpos_hits[__fix_seq] = __name
                __fix_seq += 1

                if __off >= sio.linewords:
                    self.field[__name] = error_by_rule(__cr)
                else:
#                    print "dbg:: nx/fixed: v({val}) r({rule})".format(
#                            val=sio.lineparts[__off], rule=str(__cr))
                    self.field[__name] = conv_by_rules(sio.lineparts[__off],
                                             __cr, __ord)

        for __rulenum in self.parse_rule:
            __rinfo = self.parse_rule[__rulenum]
            __cr = __rinfo[0]
            if __cr.has_key(FIELD_NAME) and not __hit_rule.has_key(__rulenum):
                self.field[__cr[FIELD_NAME]] = error_by_rule(__cr)
#                print "dbg:: nx/nohit: n:{rn:d} f({field}) r({rule})".format(
#                        rn=__rulenum, rule=str(__cr), field=__cr[FIELD_NAME])

        return(self.extra_next(sio))



# ---
class SingleNameValueList(object):
    """
    Base class to read files where each line is two fields, one name and an
    associated value
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#                file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 2
        self.skipped = ""
        self.trim_tail = ""
        self.debug_level = 0

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        if self.debug_level >= 5:
            print "dbg:: {name:s} reading '{infile}'".format(name=str(self),
                    infile=self.infile)
        return

    def __iter__(self):
        return(self)

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

        if self.debug_level > 0:
            print "base:next: {this}".format(this=str(self))
        __lines = self.curr_sio.read_all_lines()

        if len(__lines) == 0:
            raise StopIteration
        else:
            __hits = dict()
            __seq = 0
            for __keyval in __lines:
                if len(__keyval) > 0:
                    __words = __keyval.split()
                    if len(__words) == 2:
                        __name = __words[0]
                        if __name[-1:] == self.trim_tail:
                            __name = __name[:-1]
                        if len(__name) > 0:
                            self.field[__name] = __words[1]
                            __hits[__seq] = __name
                            __seq += 1

            self.field[PFC.F_HITS] = __hits
        return(self.field)



# ---
class TwoLineLogicalRecs(object):
    """
    Base class to read 'netstat', 'snmp' and any others with the same two-line
    logical record format
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#                file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 1
        self.skipped = ""
        self.protocol_type = ""

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

#        print "base:next: {this}".format(this=str(self))

# Note: Only a couple of the /proc/net files use this format and it can't
#       be parsed with the existing code.  This one consists of a series
#       of logical records, each one of which is two-lines in the file.
#       The first line of each logical record starts with an id that names
#       the logical record type, then has a list of field names that apply
#       to that type.  The second line starts with the same "type" field
#       followed by the values for each of the fields.  Both lines are
#       blank delimited.

        self.curr_sio.read_twoline_logical_record(self, F_PROTOCOL)

        try:
            self.protocol_type = self.field[F_PROTOCOL]
        except KeyError:
            self.protocol_type = ""

        return(self.protocol_type, self.field)



# ---
class LabelledPairList(object):
    """
    Base class to read 'sockstat', 'sockstat6' and others files w/ independent
    records of name/value pairs
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#                file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 1
        self.skipped = ""

        self.sock_type_list = ()

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

# -- Sample lines for reference...
# TCP: inuse 26 orphan 0 tw 1 alloc 30 mem 2
# UDP: inuse 3 mem 3
# UDPLITE: inuse 0
# RAW: inuse 0
# FRAG: inuse 0 memory 0

        __result = set()
        __unk_label = set()
        self.field = dict()
        for __sock_type in self.sock_type_list:
            self.field[__sock_type] = dict()

        __result, __unk_label = self.curr_sio.read_labelled_pair_list_file(
                                    self, self.sock_type_list)

        return(__result)



# ---
class ListOfTerms(object):
    """
    Base class to read files that are just a list of terms, one per line,
    like 'ip_tables_*' files
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#                file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 1
        self.skipped = ""

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# hl

        __lines = self.curr_sio.read_all_lines()

        if len(__lines) == 0:
            raise StopIteration

        self.field[F_TERM_LIST] = __lines

        return(__lines)
#



# ---
class FixedColumnRecs(object):
    """
    Class to read files whose fields are consistently in specific columns
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""

#        print "base:extra_init: {this}".format(this=str(self))
        return

    def extra_next(self, sio):
        """No-op version of optional call-out from 'next' method"""

#        print "base:extra_next: {this}".format(this=str(self))
        return(sio.buff)

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self),
#                file=show_handler_file_path(self))
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 0
        self.skipped = ""
        self.fixedcols = dict()

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        """Standard iterator method"""
        return(self)

    def next(self):
        """
        Called to process and return the next logical record in the
        currently open file.
        """

#        print "base:next: {this}".format(this=str(self))
        sio = self.curr_sio
        sio.read_line()

        if type(self.fixedcols) == dict:
            for __name in self.fixedcols:
                __stcol = self.fixedcols[__name][0]
                __encol = self.fixedcols[__name][1]
                self.field[__name] = sio.buff[__stcol:__encol]

        return(self.extra_next(sio))



#
class SymLinkFile(object):
    """
    Class to simulate an iterator that reads a file while
    just returning the target of a symlink as the first line.
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""
        return

    def __init__(self, *opts):
        if len(opts) > 0:
            __path = opts[0]
            self.infile = proc_file_to_symlink(__path)
        else:
            self.infile = show_handler_file_path(self)

        self.extra_init(*opts)

        try:
            self.symlink_target = os.readlink(self.infile)
            self.complete = False
        except OSError:
            self.symlink_target = ""
            self.complete = True

        self.field = dict()
        return

    def __iter__(self):
        """Standard iterator method"""
        return(self)

    def next(self):
        """
        Called to fetch a record, but for this class there's no
        data to read from the file.  The first call returns the
        target of the symlink.  All calls after that raise a
        'StopIteration' condition.
        """
        if self.complete:
            raise StopIteration

        self.complete = True
        self.field[PFC.F_SYMLINK] = self.symlink_target
        self.field[PFC.F_FILEPATH] = self.infile

        return(self.infile, self.symlink_target)



#
class TaggedMultiLineFile(object):
    """
    Read files where one logical records is made up of multiple physical recs
    each of which has can be parsed with a 'parse_rule'.  The call-out to the
    'extra_next' method, which is where the extended class can perform more
    complex parsing/transformations, is done only once the complete logical
    record has been built.
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""
        return

    def __init__(self, *opts):
        if len(opts) > 0:
            __path = opts[0]
            self.infile = proc_file_to_path(__path)
        else:
            self.infile = show_handler_file_path(self)

        self.at_eof = False
        self.minfields = 0
        self.skipped = ""
        self.eor_value = ""
        self.eor_rule = dict()
        self.eor_order = ""
        self.parse_rule = dict()
        self.floating_rule = dict()
        self.lines_read = 0
        self.hit_order = dict()

        self.extra_init(*opts)

        self.field = dict()
        self.unused_recs = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        """Standard iterator method"""
        return(self)

    def extra_next(self, sio):
        """No-op version of logical record post-processing method"""
        return(self.field)

    def add_eor_rule(self, eor, rule, order=""):
        """
        Define a parse rule for detecting an 'end of logical record'
        line in the target file.
        """
        self.eor_value = eor
        self.eor_rule = rule
        self.eor_order = order

    def next(self):
        """
        Call to fetch a logical record, which means reading and
        parsing multiple physical records until a specific tag
        is found indicating we're done, or EOF is reached.
        """

        if self.at_eof:
            raise StopIteration

        __done = False
        __empty = True
        self.lines_read = 0

        self.field = dict()
        self.unused_recs = dict()
        __subrec = 0
        sio = self.curr_sio
        self.hit_order = dict()
        __hit = 0

        for __rulenum in self.parse_rule:
            __rinfo = self.parse_rule[__rulenum]
            __cr = __rinfo[0]
            if __cr.has_key(FIELD_NAME):
                self.field[__cr[FIELD_NAME]] = error_by_rule(__cr)

        while not __done:
            try:
                sio.read_line()
                __subrec += 1
                self.lines_read += 1
#                __line = sio.buff[:-1]
                __line = sio.buff.strip("\n")
#                print "dbg:: Tagged: l({line})".format(line=__line)
                __matches = 0

                for __rulenum in self.parse_rule:
                    __rinfo = self.parse_rule[__rulenum]
                    __cr = __rinfo[0]
                    try:
                        __ord = __rinfo[1]
                    except IndexError:
                        __ord = ""
                    if __cr.has_key(FIELD_NAME):
                        if matches_all_crit(__line, __cr, __ord):
#                            print "dbg:: Tagged: pr.. hit r({rule}) o({ord})".format(rule=str(__cr), ord=str(__ord))
                            __empty = False
                            __parsed = conv_by_rules(__line, __cr, __ord)
                            self.field[__cr[FIELD_NAME]] = __parsed
                            __matches += 1
                            self.hit_order[__hit] = __cr[FIELD_NAME]
                            __hit += 1
#                            print "dbg:: Tagged: pr.. hit v({conv})".format(conv=__parsed)
#                        else:
#                            print "dbg:: Tagged: pr.. mis r({rule})".format(rule=str(__cr))

                if __matches == 0:
                    self.unused_recs[__subrec] = __line

#                print "dbg:: Tagged: eor: l:{line} v({val}) r({rule})".format(line=__line, val=self.eor_value, rule=str(self.eor_rule))
                __is_eor = conv_by_rules(__line, self.eor_rule, self.eor_order)
                if __is_eor == self.eor_value and not __empty:
                    __done = True
#                print "dbg:: Tagged: eor: done:{eor} v({val}) ch({ch})".format(eor=__done, val=__is_eor, ch=self.eor_value)
                    
            except StopIteration:
                self.at_eof = True
                __done = True

        if self.lines_read == 0:
            raise StopIteration

        return(self.extra_next(sio))



# ---
class SingleTextField(object):
    """
    Base class for files that are one line of text, not to be parsed
    """

    def extra_init(self, *opts):
        """No-op version of optional call-out from '__init__' method"""
        return

    def extra_next(self, sio):
        """No-op version of optional call-out from 'next' method"""

        __line = sio.buff.partition("\n")[0]
        self.field[PFC.F_DATA] = __line
        return(__line)

    def __init__(self, *opts):
        if len(opts) > 0:
            self.infile = proc_file_to_path(opts[0])
        else:
            self.infile = show_handler_file_path(self)
        self.minfields = 0
        self.skipped = ""
        self.parse_rule = dict()
        self.floating_rule = dict()

        self.extra_init(*opts)

        self.field = dict()
        self.curr_sio = SeqFileIO.SeqFileIO()
        self.curr_sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
        """
        First call return the contents of the file.  The next call raise a
        StopIteration condition.
        """

        self.field = dict()
        sio = self.curr_sio
        sio.read_line()

        return(self.extra_next(sio))
        
            

if __name__ == "__main__":

    print "A collection of routines for reading '/proc' files"
