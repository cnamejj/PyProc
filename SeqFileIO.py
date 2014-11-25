#!/usr/bin/env python
"""I/O routines for reading column oriented text data files"""

def pair_list_to_dictionary(line, start_pos):
    """Transform a list of word pairs to a dictionary."""

    __pairs = dict()

    __word_list = line.split()
    __word_count = len(__word_list)
    for __key_pos in range(start_pos - 1, __word_count, 2):
        __pairs[__word_list[__key_pos]] = __word_list[__key_pos+1]

    return __pairs


class SeqFileIO:
    """Utility routines to handle I/O to proc file system files"""

    def __init__(self):
        self.lineparts = dict()
        self.linewords = 0
        self.buff = ""
        self.is_open = False
        self.min_words = 0
        self.skip_line = ""

        # For pylint only...
        self.pnt_fd = file("/dev/null", "r")

    def open_file(self, procfile, *options):
        """Open the specified file and stash away basic status info"""

        try:
            self.pnt_fd = open(procfile)
            self.is_open = True
        except IOError:
            self.is_open = False

        if len(options) > 0:
            self.min_words = options[0]
            if len(options) > 1:
                self.skip_line = options[1]


    def get_word(self, which):
        """Return the specific word from the current parsed logical record"""

        if which < self.linewords:
            __word = self.lineparts[which]
        else:
            __word = ""

        return __word


    def close_file(self):
        """Used when the caller want to skip the rest of the file."""
        if self.is_open:
            self.is_open = False
            self.pnt_fd.close()
        return
        

    def read_line(self):
        """Read/Parse the next line in the open file."""

        self.lineparts = dict()
        self.linewords = 0
        self.buff = ""

        if not self.is_open:
            raise StopIteration

        else:
            try:
                self.buff = self.pnt_fd.readline()
            except IOError as err:
                self.pnt_fd.close()
                self.is_open = False
                raise StopIteration

            try:
                __min_words = self.min_words
            except AttributeError:
                __min_words = 0

            try:
                __skip_line = self.skip_line 
            except AttributeError:
                __skip_line = ""

            if self.buff == "":
                self.pnt_fd.close()
                self.is_open = False
                raise StopIteration

            else:
                self.lineparts = self.buff.split()
                self.linewords = len(self.lineparts)
                if self.linewords < __min_words:
                    self.read_line()
                elif __skip_line != "":
                    if self.lineparts[0] == __skip_line:
                        self.read_line()

        return(self.is_open)


    def read_all_lines(self):
        """Read all the lines in the file and return them all at once"""

        __lines = ()

        if not self.is_open:
            raise StopIteration

        if self.is_open:
            __lines = self.pnt_fd.readlines()

            try:
                __skip_pref = self.skip_line 
            except AttributeError:
                __skip_pref = ""

            if __lines != "":
                __skip_pref_len = len(__skip_pref) + 1

                for __off in range(len(__lines)-1, -1, -1):
                    if __lines[__off][-1:] == "\n":
                        __lines[__off] = __lines[__off][:-1]
                    if __skip_pref_len > 1:
#                        if __lines[__off][1:__skip_pref_len] == __skip_pref:
                        if __lines[__off].startswith(__skip_pref):
                            __lines[__off:__off+1] = []
                    elif __lines[__off] == "":
                        __lines[__off:__off+1] = []

            self.is_open = False

        return __lines


    def read_labelled_pair_list_file(self, handler, label_set):
        """
        Parse files formatted such that each pair of lines in the file
        is a set of variable names (line 1) and associated values
        (line 2)
        """

        if not self.is_open:
            raise StopIteration

        try:
            __result = set()
            __unknown_label = set()

            while self.read_line():
                __sock_type = self.lineparts[0]
                if __sock_type in label_set:
                    __result.add(__sock_type)
                    handler.field[__sock_type] = pair_list_to_dictionary(
                                                     self.buff, 2)
                else:
                    __unknown_label.add(__sock_type)
        except StopIteration:
            self.is_open = False

        return(__result, __unknown_label)


    def read_twoline_logical_record(self, handler, prot_field):
        """
        Read and parse files with two-physical line per logical line format
        """

        handler.field = dict()
        self.lineparts = dict()
        self.linewords = 0

        if not self.is_open:
            raise StopIteration

        try:
            self.read_line()
            __pss_varlist = self.lineparts
            __pss_varcount = self.linewords

            self.read_line()
            if self.linewords != __pss_varcount:
                self.lineparts = dict()
                self.linewords = 0
                raise StopIteration
            else:
                handler.field[prot_field] = self.lineparts[0][0:-1]
                handler.hit_order = dict()

                for __varnum in range(0, self.linewords, 1):
                    __field_name = __pss_varlist[__varnum] 
                    handler.field[__field_name] = self.lineparts[__varnum]
                    handler.hit_order[__varnum] = __field_name

        except StopIteration:
            self.lineparts = dict()
            self.linewords = 0
            self.is_open = False

        return



if __name__ == "__main__":

    print "A library providing access to text files via Python iterators"
