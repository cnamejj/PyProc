PyProc
======

Python modules providing a simple, consistent method of pulling data from
files in the /proc filesystem

----------

## Sample Code

Most of the Python code included in this repository is useful as building
blocks for other scripts/applications.  As a result, they can't really be used
asis.  But there are some sample programs included that make use of the core
library.  Here's a list of those pieces and a brief description of how to use
them.  They were included both as scripts that might be useful as written and
also to serve as sample code for anyone interesting in writing their own
scripts.

### Scripts to disply "/proc" data in different formats

There are a couple of scripts that can be used to parse any of the supported
"/proc" dataset and convert them to another file format.  The resulting data
should be easier to load into another program, like a Google spreadheet, pull
into another program, or just to view.

All of these scripts take command line arguments that identify file to be
parsed.  It can be a file in the "/proc" filesystem or a copy of one of those
files stored in an arbitrary location.  But since the name of the file, and
not the contents, are used to figure out which "handler" (a class that knows
how to parse a specific dataset), if you save a copy of a file from the
"/proc" filesystem the path to that file should match the filename of the
original.

For instance, if you wanted to copy "/proc/net/tcp6" and wanted to extra data
from it later, copying it to "/tmp/copy-of-tcp6" would work.  But copying it
to "/tmp/tcp6-from-thursday" would not be recognized by the format conversion
scripts.  The underlying library routines would happily parse any file you
gave it, but the driver scripts are smart enough to connect the dots...

Here's a list of the scripts included to re-format "/proc" datasets:

#### proc2json

Reads logical records from the indicated file and converts the collection of
fields from each record to JSON format.

#### pro2csv

Writes each logical record out as a pipe ("|") delimited CSV record.  It will
also create a header record, printed as the first line, to label each column.

In cases where the fields returned change from logical record to logical
record, a blank link and new header record will be written out.  The handlers
included in this package attempt to standardize the fields returned for each
record, even if that requires including empty fields on some records.  So only
a few handlers generate multiple header lines.

#### ShowProcFields

This is mostly useful as a test program.  **ShowProcFields** generates a
user-friendly display of the fields in each logical record read from the
indicated dataset.  It's display the results of almost all the handlers
gracefully.  But some datasets produce complex structures that this script
can't fully decode.  For instance parsing **fib_trie** yields deeply
structured records that **ShowProcFields** only decodes down two levels.


----------

## Files Currently Supported

Code to parse the following file format are included in this package.


### In the root of the "/proc" filesystem tree:

|File | Notes
|:---- |:----
|partitions | 
|diskstats | 
|crypto | 
|key-users | 
|version_signature | 
|softirqs | 
|version | 
|uptime | 
|stat | 
|meminfo | 
|loadavg | 
|interrupts | 
|devices | 
|consoles | 
|cmdline | 
|locks | 
|filesystems | 
|slabinfo | File is only readable by root, other UID's get an empty dataset
|swaps | 
|vmallocinfo | File is only readable by root, other UID's get an empty dataset
|zoneinfo 
|vmstat | 
|pagetypeinfo | 
|buddyinfo | 
|latency_stats | 
|kallsyms | HUGE file!
|modules | 
|dma | 
|timer_stats | 
|timer_list | 
|iomem | 
|ioports | 
|execdomains | 
|schedstat | structured output, dictionaries within dictionaries
|mdstat | structured output, dictionaries within dictionaries
|misc | 
|fb | 
|mtrr | 
|cgroups | 
|mounts | the "mounts" file appears both in the root and the PID directories



### In "/proc/net" and subdirectories:

|File |Notes
|:---- |:----
|arp 
|connector 
|dev 
|dev_mcast 
|dev_snmp6 
|dev_snmp6/eth0 | since it's one handler for all files in "dev_snmp6" is a bit of a pain to use
|dev_snmp6/lo | since it's one handler for all files in "dev_snmp6" is a bit of a pain to use
|fib_trie | parsed data represented as a tree, dictionaries within dictionaries
|fib_triestat 
|if_inet6 
|igmp DONE 
|igmp6 DONE 
|ip6_tables_matches | only root can read the file, other UID's get an empty dataset
|ip6_tables_names | only root can read the file, other UID's get an empty dataset
|ip6_tables_targets | only root can read the file, other UID's get an empty dataset
|ip_conntrack | only root can read the file, other UID's get an empty dataset
|ip_tables_matches | only root can read the file, other UID's get an empty dataset
|ip_tables_names | only root can read the file, other UID's get an empty dataset
|ip_tables_targets | only root can read the file, other UID's get an empty dataset
|ipv6_route 
|netfilter/nf_log 
|netfilter/nf_queue 
|netlink 
|netstat 
|nf_conntrack | only root can read the file, other UID's get an empty dataset
|packet 
|protocols 
|psched 
|ptype 
|route 
|rt6_stats 
|rt_cache 
|snmp 
|snmp6 
|sockstat 
|sockstat6 
|softnet_stat 
|stat/arp_cache 
|stat/ip_conntrack 
|stat/ndisc_cache 
|stat/nf_conntrack 
|stat/rt_cache 
|tcp 
|tcp6 
|udp
|udp6 
|unix 



### In "/proc/self" tree and "/proc/###" PID specific trees

|File |Notes
|:---- |:----
|fd/### | The files in the "fd" subdir are symlinks, parsed value is the name of the real file
|cwd | This one is a symlink to another file or dir, the parsed value is the name of the real file
|root | This one is a symlink to another file or dir, the parsed value is the name of the real file
|exe | This one is a symlink to another file or dir, the parsed value is the name of the real file
|environ | Parsed value is a dictionary of name/value pairs describing all the ENV variables
|status 
|personality 
|limits 
|sched 
|autogroup 
|comm 
|syscall 
|cmdline 
|stat 
|statm 
|maps 
|numa_maps 
|mounts | the "mounts" file appears both in the root and the PID directories
|mountinfo 
|mountstats 
|smaps 
|wchan 
|stack 
|schedstat 
|latency 
|cpuset 
|oom_score 
|oom_adj 
|oom_score_adj 
|loginuid 
|sessionid 
|coredump_filter 
|io 




----------

## Files Not Supported

Here are a list of "/proc" files that I've seen in the dev/test systems I use
that are not handled by the code in this repository at the moment.  Some may
be added later, others aren't good candidates for the reasons listed below.


First of all, NOTHING in the "/proc/sys" tree is handled since those files are
primarily used for setting/unsetting system parameters.



### In the "/proc" root directory:

|File |Status
|:---- |:----
|sysrq-trigger |Skipping, it's a "write only" file (and only by root)
|kpageflags|Skipping, it's a binary file only readable by root
|kpagecount|  Skipping, it's a binary file only readable by root
|kmsg|Skipping, it's a binary file only readable by root
|kcore| Skipping, it's a binary file only readable by root
|cpuinfo| Unlikely, every HW plaform uses a unique format
|sched_debug| Planned, the format is a PITA but will add eventually
 
 
 
### In "/proc/self" and other "/proc/###" pid-specific directories:

|File |Status
|:---- |:----
|fdinfo/###|TBD, not sure what, if any, useful info is in theses files
|ns/net|TBD, files in the "ns" subdir need to be researched
|ns/uts|TBD, files in the "ns" subdir need to be researched
|ns/ipc|TBD, files in the "ns" subdir need to be researched
|auxv|Skipping, it's a binary file
|mem| Skipping, it's not a normal data file
|clear_refs|Skipping, it's "write only" and not a normal data file
|pagemap| Skipping, it's a binary file
|attr/current|TBD, files in the "attr" subdir need to be researched
|attr/prev NEED|TBD, files in the "attr" subdir need to be researched
|attr/exec NEED|TBD, files in the "attr" subdir need to be researched
|attr/fscreate| TBD, files in the "attr" subdir need to be researched
|attr/keycreate|TBD, files in the "attr" subdir need to be researched
|attr/sockcreate| TBD, files in the "attr" subdir need to be researched
|cgroup|TBD, it's an empty file, no idea what it's for yet



### In "/proc/net" and subdirectories

|File |Status
|:---- |:----
|anycast6|TBD, the file is empty on all the systems I develop/test on
|bnep|Planned, but only present on my Fedora system
|hci| Planned, but only present on my Fedora system
|icmp|TBD, the file is empty on all the systems I develop/test on
|icmp6| Planned, but only present on my Fedora system, and it's empty there
|ip6_flowlabel| TBD, the file is empty on all the systems I develop/test on
|ip6_mr_cache|TBD, the file is empty on all the systems I develop/test on
|ip6_mr_vif|TBD, the file is empty on the systems I have, plus it only readable by root
|ip_conntrack_expect |TBD, the file is empty on the systems I have, plus it only readable by root
|ip_mr_cache| TBD, the file is empty on all the systems I develop/test on
|ip_mr_vif| TBD, the file is empty on all the systems I develop/test on
|l2cap| Planned, but only present on my Fedora system
|mcfilter|TBD, the file is empty on all the systems I develop/test on
|mcfilter6| TBD, the file is empty on all the systems I develop/test on
|nf_conntrack_expect |TBD, the file is empty on the systems I have, plus it only readable by root
|raw| TBD, the file is empty on all the systems I develop/test on
|raw6|TBD, the file is empty on all the systems I develop/test on
|rt_acct| TBD, the file is empty on all the systems I develop/test on
|sco| Planned, but only present on my Fedora system
|tr_rif|TBD, the file is empty on all the systems I develop/test on
|udplite| TBD, the file is empty on all the systems I develop/test on
|udplite6|TBD, the file is empty on all the systems I develop/test on
|wireless|TBD, the file is empty on all the systems I develop/test on
|xfrm_stat| Planned, but only present on my Fedora system


### In "/proc/sysvipc"

|File|Status
|:----|:----
|msg|Planned, haven't looked into "sysvipc" file yet, and it's empty on my systems
|sem|Planned, haven't looked into "sysvipc" file yet, looks really straightforward though
|shm|Planned, haven't looked into "sysvipc" file yet, looks really straightforward though
