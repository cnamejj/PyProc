PyProc
======

Python modules providing a simple, consistent method of pulling data from
files in the /proc filesystem

----------

## The Basic Idea

The code provided in this repository strives to make it possible to read
information from any dataset in the "/proc" filesystem via a Python iterator.
There are classes available to parse a variety of different file formats and
each of them attempts to return a "logical record" that makes sense in the
context of the dataset it's reading.

The fields returned vary by dataset, obviously.  But if the code achieves it's
goals, the method of fetching the data will be consistent.

In the end the following high level steps should work to pull "records" of
data from any "/proc" dataset.

```python
import ProcHandlers

# -- Find the "handler" class for the dataset we want
handler = ProcHandlers.GET_HANDLER("/proc/net/arp")

# -- get an active instance of that handler, open the file
# -- passed or the canonical path for that handler if no
# -- filename is given.
act = handler()

for hilit in act:
    # -- print the dictionary listing all the field in the record
    print act.field
```

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
from it later, copying it to "/tmp/copy/tcp6" would work.  But copying it to
"/tmp/tcp6-from-thursday" would not be recognized by the format conversion
scripts.  The underlying library routines would happily parse any file you
gave it, but the driver scripts aren't smart enough to connect the dots
without a little help...

You can try specifying the archetypal filename as the first command line
option and the copy you want parsed as the second name.  The code will try to
determine which handler to use by looking up the first argument in a registry
of handlers.  Then it will direct the matching handler to read the file listed
in the second command line argument.

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

### Scripts that display system status

#### watch-tcp-connections

This script runs through the socket connections found in the "/proc/net/tcp"
and "/proc/net/tcp6" datasets, waits for a few seconds and repeats the
process.  Any new network connections are displayed as they are found.  In
addition to summary information about the endpoints of the connection, the
process id that owns the socket and it's associated command line are shown.
When the program is interrupted with a '^c' the code will display summary
stats showing the number of connections each IP address seen was associated
with.

#### watch-net-connections

Minor variation on the previous script.  This one shows both UDP and TCP
connections as well as a bit more information about each socket.

#### show-active-timers

The **show-active-timers** script pulls information from the
"/proc/timer_list" dataset and lists all the processes that are waiting for
timer to expire.  It also reads the "/proc/###/cmdline" file for each process
found while scanning the list of timers.  So this script provides an example
of how to pull information from a "/proc" dataset and how to perform secondary
lookups for process specific information as well.

#### alt-conn-mon-proc.py, conn-mon-proc-ipv6.py, conn-mon-proc.py

Very similar to **watch-tcp-connections** but they only monitor one dataset.
The "ipv6" variant monitoring "/proc/net/tcp6" for new IPv6 connections.  The
other two monitor "/proc/net/tcp" so they only check for IPv4 connections.

The difference between **conn-mon-proc.py** and the "alt-" version of the
script is in how they pull the information they want from each logical record.
One uses the selected fields returned by the iterator directly.  And the other
pulls data from the dictionary decribing all the fields in the record.

#### alt-conn-curr-proc.py, conn-curr-proc.py

Similar to scripts whose names they resemble.  The difference is that these
scripts show summary information about IPv4 socket connections on the system
when the script is run only.  They don't iterate and check for new connections.

#### show-current-sockets

Yet another sample script to run through sockets currently tracked by the
kernel.  It demonstrates that the handler for tcp, tcp6, udp, and udp6
datasets return the same parsed fields.  The local/remote ip and port are
displayed as well as info about the the process that owns the socket.

#### show-memory-delta

An example of a simple monitoring script.  It tracks the change in system
level memory utilization metrics, pulled from /proc/meminfo, from iteration to
iteration.  If any measurement increases or decreases by at least 20% the
script logs before/after values.

#### show-open-files

Just what it sounds like...  The script walks through the directory describing
open file descriptors for every process running on the system.  It displays
summary information for each open file descriptor.  In other words, it shows
what each of the /proc/#PID#/fd/* symlinks reference.  For any that point to a
socket instead of a file, basic socket information is included.  And unlike
other PyProc sample scripts that check socket related info, this script
handles unix domain sockets as well as tcp, tcp6, udp and udp6 sockets.

#### watch-process-smaps

Similar to "show-memory-delta" but for a specific process id, which must be
given as the first command line argument.  The dataset this script uses, from
the "/proc/#PID#/smaps" file for the PID in question, includes usage counters
by memory segments within process address space.  So the script shows deltas
between iterations in more detail, as well as an aggregated "total".  It
supports CLI options to control which fields to monitor, whether or not to
display totals, breakdowns or both.  The minimum thresholds before a change is
displayed can be set, both as an absolute number and as a percentage change.
Finally, the amount of time the script waits between checks can also be
specificied via CLI options.

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
|version_signature |One line file, passed back unparsed
|softirqs |A dictionary of IRQ's, each a dictionary with one counter per CPU
|version | 
|uptime | 
|stat |One record of structured data returned, including two level of dictionaries, some per-CPU
|meminfo | 
|loadavg | 
|interrupts |Each logical record includes per-CPU counters.
|devices | 
|consoles | 
|cmdline | 
|locks | 
|filesystems | 
|slabinfo | File is only readable by root, other UID's get an empty dataset
|swaps | 
|vmallocinfo | File is only readable by root, other UID's get an empty dataset
|zoneinfo|Each record includes normal settings/counters, an array of counters, and a dictionary or per-CPU dictionaries
|vmstat | 
|pagetypeinfo |Each record includes some global settings, and either migration type breakouts, or zone type summary info
|buddyinfo | 
|latency_stats |Records include counters and a backtrace array
|kallsyms | HUGE file!
|modules | 
|dma | 
|timer_stats | 
|timer_list |Records are structured data, with some global data, and either per-CPU fields of data about a timer device
|iomem | 
|ioports | 
|execdomains | 
|schedstat |Structured output, each record includes information for one CPU, with per-domain dictionaries
|mdstat |Structured output, some of the fields are themselves dictionaries or arrays
|misc | 
|fb | 
|mtrr | 
|cgroups | 
|mounts |The "mounts" file appears both in the root and the PID directories.  The "mount options" field is returned as-is and not parsed
|keys |


### In "/proc/net" and subdirectories:

|File |Notes
|:---- |:----
|arp 
|bnep
|connector 
|dev 
|dev_mcast 
|dev_snmp6 
|dev_snmp6/eth0 | since it's one handler for all files in "dev_snmp6" is a bit of a pain to use
|dev_snmp6/lo | since it's one handler for all files in "dev_snmp6" is a bit of a pain to use
|fib_trie | parsed data represented as a tree, dictionaries within dictionaries
|fib_triestat|one field in logical record returned is a dictionary of inodes, the rest are simple values
|if_inet6|The IPv6 addresses in each logical record is provided as 32 character string (as listed in the file), and as converted to typical semicolon delimited display format
|hci
|igmp
|igmp6|The IPv6 field in the record is provided as-is, meaning a 32 character string, and in semicolon delimited display format
|ip6_tables_matches | only root can read the file, other UID's get an empty dataset
|ip6_tables_names | only root can read the file, other UID's get an empty dataset
|ip6_tables_targets | only root can read the file, other UID's get an empty dataset
|ip_conntrack | only root can read the file, other UID's get an empty dataset
|ip_tables_matches | only root can read the file, other UID's get an empty dataset
|ip_tables_names | only root can read the file, other UID's get an empty dataset
|ip_tables_targets | only root can read the file, other UID's get an empty dataset
|ipv6_route|IPv6 address fields are provided as-is (meaning 32 character strings) and as semicolon delimited display format
|l2cap
|netfilter/nf_log 
|netfilter/nf_queue 
|netlink 
|netstat|The fields returned vary from logical record to logical record since each represents a different network protocol
|nf_conntrack | only root can read the file, other UID's get an empty dataset
|packet 
|pnp|Shows DNS related config info
|protocols 
|psched 
|ptype 
|route|The IP addresses in the file are provided as-is, meaning an 8 digit hex string, and in period delimited display format
|rt6_stats 
|rt_cache|The IP addresses in the file are provided as-is, meaning an 8 digit hex string, and in period delimited display format
|sco
|snmp|The fields returned vary from logical record to logical record since each represents a different network protocol
|snmp6|One logical record with all the settings listed in the dataset is returned
|sockstat|One logical record is returned, each field identifies a protocol and it's value is a dictionary of counters
|sockstat6|One logical record is returned, each field identifies a protocol and it's value is a dictionary of counters
|softnet_stat 
|stat/arp_cache 
|stat/ip_conntrack 
|stat/ndisc_cache 
|stat/nf_conntrack 
|stat/rt_cache 
|tcp|IP addresses, port numbers, and socket state are provided as given the input file and also translated to display format (IP's), decimal (port), and text representation (socket state)
|tcp6|IP addresses, port numbers, and socket state are provided as given the input file and also translated to display format (IP's), decimal (port), and text representation (socket state)
|udp|IP addresses, port numbers, and socket state are provided as given the input file and also translated to display format (IP's), decimal (port), and text representation (socket state)
|udp6|IP addresses, port numbers, and socket state are provided as given the input file and also translated to display format (IP's), decimal (port), and text representation (socket state)
|unix|The "path" field in the returned logical records are presentes as they appear in the input file and may include binary characters, usually "\0" characters


### In the "/proc/sysvipc" directory

|File|Notes
|:----|:----
|msg|Coded based on a review of the kernel source, no real data to test with
|sem|
|shm|


### In "/proc/self" tree and "/proc/###" PID specific trees

|File |Notes
|:---- |:----
|fd/### | The files in the "fd" subdir are symlinks, parsed value is the name of the real file
|cwd | This one is a symlink to another file or dir, the parsed value is the name of the real file
|root | This one is a symlink to another file or dir, the parsed value is the name of the real file
|exe | This one is a symlink to another file or dir, the parsed value is the name of the real file
|environ | Parsed value is a dictionary of name/value pairs describing all the ENV variables
|status|The 'groups' field in the logical record is a list of values, all other fields are simple values
|personality 
|limits 
|sched 
|autogroup 
|comm 
|syscall|Results are a single line with a single field that contains the contents of the file
|cmdline|The input file has a list of command line arguments separated by '\0' chars, the handler reconstructs the command by joining the arguments with spaces between them
|stat 
|statm 
|maps 
|numa_maps|The "node-list" field in the logical record is a dictionary
|mounts|The "mounts" file appears both in the root and the PID directories.  The "mount-options" field is string showing the unparsed mount options field from the input file
|mountinfo|The "mount-options" and "superblock-options" fields are presented as given in the input file and are not parsed
|mountstats|For NFS volumes there are a number of extra field in the logical record, including dictionaries and dictionaries of dictionaries
|smaps 
|wchan 
|stack 
|schedstat 
|latency|The "backtrace" field in the logical record is a list
|cpuset 
|oom_score 
|oom_adj 
|oom_score_adj 
|loginuid 
|sessionid 
|coredump_filter 
|io 
|cgroup



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
|attr/prev|TBD, files in the "attr" subdir need to be researched
|attr/exec|TBD, files in the "attr" subdir need to be researched
|attr/fscreate| TBD, files in the "attr" subdir need to be researched
|attr/keycreate|TBD, files in the "attr" subdir need to be researched
|attr/sockcreate| TBD, files in the "attr" subdir need to be researched



### In "/proc/net" and subdirectories

|File |Status
|:---- |:----
|anycast6|TBD, the file is empty on all the systems I develop/test on
|icmp|TBD, the file is empty on all the systems I develop/test on
|icmp6| Planned, but only present on my Fedora system, and it's empty there
|ip6_flowlabel| TBD, the file is empty on all the systems I develop/test on
|ip6_mr_cache|TBD, the file is empty on all the systems I develop/test on
|ip6_mr_vif|TBD, the file is empty on the systems I have, plus it only readable by root
|ip_conntrack_expect |TBD, the file is empty on the systems I have, plus it only readable by root
|ip_mr_cache| TBD, the file is empty on all the systems I develop/test on
|ip_mr_vif| TBD, the file is empty on all the systems I develop/test on
|mcfilter|TBD, the file is empty on all the systems I develop/test on
|mcfilter6| TBD, the file is empty on all the systems I develop/test on
|nf_conntrack_expect |TBD, the file is empty on the systems I have, plus it only readable by root
|raw| TBD, the file is empty on all the systems I develop/test on
|raw6|TBD, the file is empty on all the systems I develop/test on
|rt_acct| TBD, the file is empty on all the systems I develop/test on
|tr_rif|TBD, the file is empty on all the systems I develop/test on
|udplite| TBD, the file is empty on all the systems I develop/test on
|udplite6|TBD, the file is empty on all the systems I develop/test on
|wireless|TBD, the file is empty on all the systems I develop/test on
|xfrm_stat| Planned, but only present on my Fedora system


----------

## Linux distros tested

This code was developed and tested on Ubuntu 12.04LTS and several older Fedora
releases.  Those systems had fairly complex configurations with multi-core
CPU's, multiple disks, software RAID, LVM's, and NFS.  The "/proc" files the
code processed on those systems were therefore more representative of what
might be found in the real world.

Verification tests have been run on other distros in order to make sure the
data in the supported "/proc" files on those systems could be parsed without
error.  Those configuration were very simple, VirtualBox VM's with a single
CPU and one disk.  But they did result in a number of fixes to make the code
capable of handling variations in a number of file.  The Linux distros that
passed those tests are as follows.

|Distro |Version
|:---- |:----
|OpenSuse|13.2 (Harlequin)
|Arch|N/A (kernel 3.17.6-1)
|CentOS|7.0.1406 (Core)
|Slackware|14.1
|Debian|7 (wheezy)
|Mageia|4 (Official) - thornicroft
|Mint|17.1 Rebecca
|Fedora|Fedora 21 (Twenty One)
|Ubuntu|14.04.1 LTS, Trusty Tahr

To verify that the PyProc code is able to parse, and then recreate verbatim,
all the recognized "/proc" files on a given system run the command in the
directory where you clone the repo:

```
./regentest-all-proc-files
```

Files that were parsed and then recreated exactly are given a "Pass" result.
And files that don't exist on your system, files that are not readable by the
user running the regenerator script, and files which can be parse but not
"regenerated" will get a "Skip" result.

The files that can be parse but not regenerated include any /proc files which
is just a symlink to another file/object.  For instance, /proc/self/exe or
/proc/self/fd/0 have no data they are just symlinks where the target of the
symlink is the relevant information.

There currenly only two "/proc" files that contain data which can be parse but
not regenerated.  Those are /proc/self/mountstats and /proc/self/mountinfo.
Both will be supported in the future, but interpretted the myriad of NFS
related data that can be presented in those files makes writing code to
regenerate all possible variants of the files rather tedious.
