#!/usr/bin/env python

import os
import SeqFileIO
import ProcFieldConstants
import ProcDataConstants

PFC = ProcFieldConstants
F_NULL_HANDLER = PFC.F_NULL_HANDLER
F_PROTOCOL = PFC.F_PROTOCOL
F_TERM_LIST = PFC.F_TERM_LIST

PDC = ProcDataConstants

# --
PROC_PATH_PREFIX_LIST = ( "/proc", "/proc/", "/proc/net/", "/proc/self/net/", "/proc/self/" )

proc_file_handler_registry = dict()
proc_partial_file_handler_registry = dict()
handler_to_path = dict()

def GetProcFileRegistry():
    return(proc_file_handler_registry)

def GetProcPartialFileRegistry():
    return(proc_partial_file_handler_registry)

def ProcFileToPath(proc_file):
    """If the arg passed in doesn't exist, try prepending well known directories to find the file."""

    __path = ""

    if os.path.isfile(proc_file):
        __path = proc_file
    else:
        for __pref in PROC_PATH_PREFIX_LIST:
            __trial = "{prefix}{file}".format(prefix=__pref, file=proc_file)
            if __path == "" and os.path.isfile(__trial):
                __path = __trial

    return __path

def GetProcFileHandler(proc_file):
    """Lookup routine to find the code that knows how to parse the requested /proc/net/ datafile"""

    __handler = 0
    __append_list = PROC_PATH_PREFIX_LIST

    if proc_file in proc_file_handler_registry:
        __handler = proc_file_handler_registry[proc_file]
    else:
        for __prefix in __append_list:
            __exp_file = "{prefix}{procfile}".format(prefix=__prefix, procfile=proc_file)
            if __exp_file in proc_file_handler_registry:
                __handler = proc_file_handler_registry[__exp_file]

    if __handler == 0:
        for __patt in proc_partial_file_handler_registry:
            if __patt == proc_file[-len(__patt):]:
                __handler = proc_partial_file_handler_registry[__patt]

    if __handler == 0:
        __handler = proc_file_handler_registry[F_NULL_HANDLER]

    return __handler

def RegisterProcFileHandler(proc_file, handler):
    """Associate the given code object with a specific /proc/net datafile"""

    proc_file_handler_registry[proc_file] = handler
    handler_to_path[str(handler)] = proc_file

def RegisterPartialProcFileHandler(end_of_path, handler):
    """Associate the given code object with a filename pattern to allow partial matches"""

    proc_partial_file_handler_registry[end_of_path] = handler

def ShowProcFileHandlers():
    """Print a list of all the known file to handler mappings"""

    for __file in proc_file_handler_registry:
        print "For {file} use {handler}".format(file=__file,  handler=str(proc_file_handler_registry[__file]))

def ShowPartialProcFileHandlers():
    """Print a list of all the known 'end of path' file patterns and their handler mappings"""

    for __patt in proc_partial_file_handler_registry:
        print "Path {patt} matches {handler}".format(patt=__patt,  handler=str(proc_partial_file_handler_registry[__patt]))

def ShowHandlerFilePath(cl_instance):
    """Return the fullpath of the /proc file associated with the base class of the instance provided"""

    __key = "{tmod}.{tcl}".format(tmod=cl_instance.__class__.__module__, tcl=cl_instance.__class__.__name__)
    return handler_to_path[__key]

# ---
class ProcNetNULL:
    """Dummy class that just acts like reading from an empty file, returned as the handler
       for unrecognized files."""
    def __init__(self, *opts):
        self.field = dict()

    def __iter__(self):
        return(self)

    def next(self):
        raise StopIteration
#
RegisterProcFileHandler(F_NULL_HANDLER, ProcNetNULL)



# ---
class fixed_delim_format_recs:
    """Base class to read simple files with whitespace delimited columns, consistent record format"""

    def extra_init(self, *opts):
#        print "base:extra_init: {this}".format(this=str(self))
        return

    def extra_next(self, sio):
#        print "base:extra_next: {this}".format(this=str(self))
        return(sio.buff)

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self), file=ShowHandlerFilePath(self))
        if len(opts) > 0:
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = ShowHandlerFilePath(self)
        self.minfields = 0
        self.skipped = ""

        self.extra_init( *opts)

        self.field = dict()
        self.__sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.__sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
#        print "base:next: {this}".format(this=str(self))
        sio = self.__sio
        sio.read_line()

        return(self.extra_next(sio))



# ---
class single_name_value_list:
    """Base class to read files where each line is two fields, one name and an associated value"""

    def extra_init(self, *opts):
#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self), file=ShowHandlerFilePath(self))
        if len(opts) > 0:
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = ShowHandlerFilePath(self)
        self.minfields = 2
        self.skipped = ""
        self.__keyval = ""
        self.__words = ()
        self.__lines = ()

        self.extra_init( *opts)

        self.field = dict()
        self.__sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.__sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
#        print "base:next: {this}".format(this=str(self))
        self.__lines = self.__sio.read_all_lines()

        if len(self.__lines) == 0:
            raise StopIteration
        else:
            for self.__keyval in self.__lines:
                self.__words = self.__keyval.split()
                if len(self.__words) == 2:
                    self.field[self.__words[0]] = self.__words[1]

        return(self.field)



# ---
class twoline_logical_records:
    """Base class to read 'netstat', 'snmp' and any others with the same two-line logical record format"""

    def extra_init(self, *opts):
#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self), file=ShowHandlerFilePath(self))
        if len(opts) > 0:
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = ShowHandlerFilePath(self)
        self.minfields = 1
        self.skipped = ""
        self.protocol_type = ""

        self.extra_init( *opts)

        self.field = dict()
        self.__sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.__sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):
#        print "base:next: {this}".format(this=str(self))

# Note: Only a couple of the /proc/net files use this format and it can't
#       be parsed with the existing code.  This one consists of a series
#       of logical records, each one of which is two-lines in the file.
#       The first line of each logical record starts with an id that names
#       the logical record type, then has a list of field names that apply
#       to that type.  The second line starts with the same "type" field
#       followed by the values for each of the fields.  Both lines are
#       blank delimited.

        self.__sio.read_twoline_logical_record(self, F_PROTOCOL)

        try:
            self.protocol_type = self.field[F_PROTOCOL]
        except KeyError:
            self.protocol_type = ""

        return( self.protocol_type, self.field)



# ---
class labelled_pair_list_records:
    """Base class to read 'sockstat', 'sockstat6' and others files w/ independent records of name/value pairs"""

    def extra_init(self, *opts):
#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self), file=ShowHandlerFilePath(self))
        if len(opts) > 0:
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = ShowHandlerFilePath(self)
        self.minfields = 1
        self.skipped = ""

        self.sock_type_list = ()
        self.__result = set()
        self.__unknown_label = set()
        self.__sock_type = ""

        self.extra_init( *opts)

        self.field = dict()
        self.__sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.__sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample lines for reference...
# TCP: inuse 26 orphan 0 tw 1 alloc 30 mem 2
# UDP: inuse 3 mem 3
# UDPLITE: inuse 0
# RAW: inuse 0
# FRAG: inuse 0 memory 0

        self.__result = set()
        self.__unknown_label = set()
        self.field = dict()
        for self.__sock_type in self.sock_type_list:
            self.field[self.__sock_type] = dict()

        self.__result, self.__unknown_label = self.__sio.read_labelled_pair_list_file(self, self.sock_type_list)

        return( self.__result)



# ---
class list_of_terms_format:
    """Base class to read files that are just a list of terms, one per line, like 'ip_tables_*' files"""

    def extra_init(self, *opts):
#        print "base:extra_init: {this}".format(this=str(self))
        return

    def __init__(self, *opts):
#        print "base:__init__: this{this} file{file}".format(this=str(self), file=ShowHandlerFilePath(self))
        if len(opts) > 0:
            self.infile = ProcFileToPath(opts[0])
        else:
            self.infile = ShowHandlerFilePath(self)
        self.minfields = 1
        self.skipped = ""

        self.__lines = ()

        self.extra_init( *opts)

        self.field = dict()
        self.__sio = SeqFileIO.SeqFileIO()
#        print "base:__init__: inp({infile})".format(infile=self.infile)
        self.__sio.open_file(self.infile, self.minfields, self.skipped)
        return

    def __iter__(self):
        return(self)

    def next(self):

# -- Sample records.  This file is only readable by root and is just
# -- a list of words, one per line.
# limit
# addrtype
# state
# hl

        self.__lines = self.__sio.read_all_lines()

        if len(self.__lines) == 0:
            raise StopIteration

        self.field[F_TERM_LIST] = self.__lines

        return( self.__lines)
#



if __name__ == "__main__":

    print "A collection of routines for reading '/proc' files in various file formats"
