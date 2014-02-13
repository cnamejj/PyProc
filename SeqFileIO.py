#!/usr/bin/env python
"""I/O routines for reading column oriented text data files"""

def pair_list_to_dictionary(line, start_pos):

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
        self.is_open = 0
        self.MinWords = 0
        self.SkipLine = ""

#       For 'pylint'

    def open_file(self, procfile, *options):
        try:
            self.pnt_fd = open(procfile)
            self.is_open = 1
        except IOError:
            self.is_open = 0

        if len(options) > 0:
            self.MinWords = options[0]
            if len(options) > 1:
                self.SkipLine = options[1]


    def get_word(self, which):
        if which < self.linewords:
            __word = self.lineparts[which]
        else:
            __word = ""

        return __word


    def read_line(self):

        self.lineparts = dict()
        self.linewords = 0
        self.buff = ""

        if self.is_open == 0:
            raise StopIteration

        else:
            self.buff = self.pnt_fd.readline()

            try:
                __MinWords = self.MinWords
            except AttributeError:
                __MinWords = 0

            try:
                __SkipLine = self.SkipLine 
            except AttributeError:
                __SkipLine = ""

            if self.buff == "":
                self.pnt_fd.close()
                self.is_open = 0
                raise StopIteration

            else:
                self.lineparts = self.buff.split()
                self.linewords = len(self.lineparts)
                if self.linewords < __MinWords:
                    self.read_line()
                elif __SkipLine != "":
                    if self.lineparts[0] == __SkipLine:
                        self.read_line()

        return(self.is_open)


    def read_all_lines(self):

        __lines = ()

        if not self.is_open:
            raise StopIteration

        if self.is_open != 0:
            __lines = self.pnt_fd.readlines()

            try:
                __SkipPref = self.SkipLine 
            except AttributeError:
                __SkipPref = ""

            if __lines != "":
                __SkipPrefLen = len(__SkipPref) + 1

                for __off in range(len(__lines)-1, -1, -1):
                    if __lines[__off][-1:] == "\n":
                        __lines[__off] = __lines[__off][:-1]
                    if __SkipPrefLen > 1:
                        if __lines[__off][1:__SkipPrefLen] == __SkipPref:
                            __lines[__off:__off+1] = []
                    elif __lines[__off] == "":
                        __lines[__off:__off+1] = []

            self.is_open = 0

        return __lines


    def read_labelled_pair_list_file(self, handler, label_set):

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
            self.is_open = 0

        return(__result, __unknown_label)


    def read_twoline_logical_record(self, handler, prot_field):

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

                for __varnum in range(0, self.linewords, 1):
                    __field_name = __pss_varlist[__varnum] 
                    handler.field[__field_name] = self.lineparts[__varnum]

        except StopIteration:
            self.lineparts = dict()
            self.linewords = 0
            self.is_open = 0

        return



if __name__ == "__main__":

    print "A library providing access to text files via Python iterators"
