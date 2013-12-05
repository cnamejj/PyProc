#!/usr/bin/env python
"""I/O routines for reading column oriented text data files

Describe what's in this module and put that info here...
"""

#import socket
#import binascii
#import sys
#
#unknown_state = "UNRECOGNIZED"
#
#ANY_HW_ADDR = "00:00:00:00:00:00"
#ANY_INTERFACE = "any"
#ANY_IPV6_ADDR = "::"
#ANY_IP_ADDR = "0.0.0.0"
#ANY_IP_ADDR_HEX = "00000000"
#ANY_IPV6_ADDR_HEX = "00000000000000000000000000000000"
#ANY_MASK_HEX = "FFFFFFFF"
#NULL_MASK_HEX = "00000000"
#PRESENT_ANY_IPV6_ADDR = "::0"
#PRESENT_ANY_IP_ADDR = "0.0.0.0"
#ANY_DEVICE = "any"

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
        self.__pss_varcount = 0
        self.__unknown_label = set()
        self.__result = set()
        self.__pss_varlist = ()
        self.__sock_type = ""

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

        return __lines


    def read_labelled_pair_list_file(self, handler, label_set):

        if not self.is_open:
            raise StopIteration

        try:
            self.__result = set()
            self.__unknown_label = set()

            while self.read_line():
                self.__sock_type = str(self.lineparts[0])
                if self.__sock_type in label_set:
                    self.__result.add(self.__sock_type)
                    handler.field[self.__sock_type] = pair_list_to_dictionary(self.buff, 2)
                else:
                    self.__unknown_label.add(self.__sock_type)
        except StopIteration:
            self.is_open = 0

        return(self.__result, self.__unknown_label)


    def read_twoline_logical_record(self, handler, prot_field):

        handler.field = dict()
        self.lineparts = dict()
        self.linewords = 0

        if not self.is_open:
            raise StopIteration

        try:
            self.read_line()
            self.__pss_varlist = self.lineparts
            self.__pss_varcount = self.linewords

            self.read_line()
            if self.linewords != self.__pss_varcount:
                self.lineparts = dict()
                self.linewords = 0
                raise StopIteration
            else:
#                handler.field[F_PROTOCOL] = self.lineparts[0][0:-1]
                handler.field[prot_field] = self.lineparts[0][0:-1]

                for __varnum in range(0, self.linewords, 1):
                    handler.field[self.__pss_varlist[__varnum]] = self.lineparts[__varnum]

        except StopIteration:
            self.lineparts = dict()
            self.linewords = 0
            self.is_open = 0

        return


#    def pair_list_to_dictionary(self, line, start_pos):
#
#        __pairs = dict()
#
#        __word_list = line.split()
#        __word_count = len(__word_list)
#
#        for __key_pos in range(start_pos - 1, __word_count, 2):
#            __pairs[__word_list[__key_pos]] = __word_list[__key_pos+1]
#
#        return __pairs
