# CVE-2022-0847 - Dirty Pipe vulnerability
Originaly written by [CM4all](https://dirtypipe.cm4all.com/)
Converted to Markdown by Peter (me)

Abstract[](#abstract "Permalink to this headline")
---------------------------------------------------

This is the story of CVE-2022-0847, a vulnerability in the Linux kernel since 5.8 which allows overwriting data in arbitrary read-only files. This leads to privilege escalation because unprivileged processes can inject code into root processes.

It is similar to [CVE-2016-5195 “Dirty Cow”](https://dirtycow.ninja/) but is easier to exploit.

The vulnerability [was fixed](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9d2231c5d74e13b2a0546fee6737ee4446017903) in Linux 5.16.11, 5.15.25 and 5.10.102.

Corruption pt. I[](#corruption-pt-i "Permalink to this headline")
------------------------------------------------------------------

It all started a year ago with a support ticket about corrupt files. A customer complained that the access logs they downloaded could not be decompressed. And indeed, there was a corrupt log file on one of the log servers; it could be decompressed, but gzip reported a CRC error. I could not explain why it was corrupt, but I assumed the nightly split process had crashed and left a corrupt file behind. I fixed the file’s CRC manually, closed the ticket, and soon forgot about the problem.

Months later, this happened again and yet again. Every time, the file’s contents looked correct, only the CRC at the end of the file was wrong. Now, with several corrupt files, I was able to dig deeper and found a surprising kind of corruption. A pattern emerged.

Access Logging[](#access-logging "Permalink to this headline")
---------------------------------------------------------------

Let me briefly introduce how our log server works: In the CM4all hosting environment, all web servers (running our [custom open source HTTP server](https://github.com/CM4all/beng-proxy/)) send UDP multicast datagrams with metadata about each HTTP request. These are received by the log servers running [Pond](https://github.com/CM4all/pond), our custom open source in-memory database. A nightly job splits all access logs of the previous day into one per hosted web site, each compressed with [zlib](https://zlib.net/).

Via HTTP, all access logs of a month can be downloaded as a single .gz file. Using a trick (which involves Z_SYNC_FLUSH), we can just concatenate all gzipped daily log files without having to decompress and recompress them, which means this HTTP request consumes nearly no CPU. Memory bandwidth is saved by employing the splice() system call to feed data directly from the hard disk into the HTTP connection, without passing the kernel/userspace boundary (“zero-copy”).

Windows users can’t handle .gz files, but everybody can extract ZIP files. A ZIP file is just a container for .gz files, so we could use the same method to generate ZIP files on-the-fly; all we needed to do was send a ZIP header first, then concatenate all .gz file contents as usual, followed by the central directory (another kind of header).

Corruption pt. II[](#corruption-pt-ii "Permalink to this headline")
--------------------------------------------------------------------

This is how a the end of a proper daily file looks:
```
000005f0  81 d6 94 39 8a 05 b0 ed  e9 c0 fd 07 00 00 ff ff
00000600  03 00 9c 12 0b f5 f7 4a  00 00
```
The 00 00 ff ff is the [sync flush](https://www.bolet.org/~pornin/deflate-flush-fr.html) which allows simple concatenation. 03 00 is [an empty “final” block](https://datatracker.ietf.org/doc/html/rfc1951#page-9), and is followed by a CRC32 (0xf50b129c) and the uncompressed file length (0x00004af7 = 19191 bytes).

The same file but corrupted:
```
000005f0  81 d6 94 39 8a 05 b0 ed  e9 c0 fd 07 00 00 ff ff
00000600  03 00 50 4b 01 02 1e 03  14 00
```
The sync flush is there, the empty final block is there, but the uncompressed length is now 0x0014031e = 1.3 MB (that’s wrong, it’s the same 19 kB file as above). The CRC32 is 0x02014b50, which does not match the file contents. Why? Is this an out-of-bounds write or a heap corruption bug in our log client?

I compared all known-corrupt files and discovered, to my surprise, that all of them had the same CRC32 and the same “file length” value. Always the same CRC - this implies that this cannot be the result of a CRC calculation. With corrupt data, we would see different (but wrong) CRC values. For hours, I stared holes into the code but could not find an explanation.

Then I stared at these 8 bytes. Eventually, I realized that 50 4b is ASCII for “P” and “K”. “PK”, that’s how all ZIP headers start. Let’s have a look at these 8 bytes again:
```
50 4b 01 02 1e 03 14 00
```
*   50 4b is “PK”
    
*   01 02 is the code for [central directory file header](https://en.wikipedia.org/wiki/ZIP_(file_format)#Central_directory_file_header).
    
*   “Version made by” = 1e 03; 0x1e = 30 (3.0); 0x03 = UNIX
    
*   “Version needed to extract” = 14 00; 0x0014 = 20 (2.0)
    

The rest is missing; the header was apparently truncated after 8 bytes.

This is really the beginning of a ZIP central directory file header, this cannot be a coincidence. But the process which writes these files has no code to generate such header. In my desperation, I looked at the zlib source code and all other libraries used by that process but found nothing. This piece of software doesn’t know anything about “PK” headers.

There is one process which generates “PK” headers, though; it’s the web service which constructs ZIP files on-the-fly. But this process runs as a different user which doesn’t have write permissions on these files. It cannot possibly be that process.

None of this made sense, but new support tickets kept coming in (at a very slow rate). There was some systematic problem, but I just couldn’t get a grip on it. That gave me a lot of frustration, but I was busy with other tasks, and I kept pushing this file corruption problem to the back of my queue.

Corruption pt. III[](#corruption-pt-iii "Permalink to this headline")
----------------------------------------------------------------------

External pressure brought this problem back into my consciousness. I scanned the whole hard disk for corrupt files (which took two days), hoping for more patterns to emerge. And indeed, there was a pattern:

*   there were 37 corrupt files within the past 3 months
    
*   they occurred on 22 unique days
    
*   18 of those days have 1 corruption
    
*   1 day has 2 corruptions (2021-11-21)
    
*   1 day has 7 corruptions (2021-11-30)
    
*   1 day has 6 corruptions (2021-12-31)
    
*   1 day has 4 corruptions (2022-01-31)
    

The last day of each month is clearly the one which most corruptions occur.

Only the primary log server had corruptions (the one which served HTTP connections and constructed ZIP files). The standby server (HTTP inactive but same log extraction process) had zero corruptions. Data on both servers was identical, minus those corruptions.

Is this caused by flaky hardware? Bad RAM? Bad storage? Cosmic rays? No, the symptoms don’t look like a hardware issue. A ghost in the machine? Do we need an exorcist?

Man staring at code[](#man-staring-at-code "Permalink to this headline")
-------------------------------------------------------------------------

I began staring holes into my code again, this time the web service.

Remember, the web service writes a ZIP header, then uses splice() to send all compressed files, and finally uses write() again for the “central directory file header”, which begins with 50 4b 01 02 1e 03 14 00, exactly the corruption. The data sent over the wire looks exactly like the corrupt files on disk. But the process sending this on the wire has no write permissions on those files (and doesn’t even try to do so), it only reads them. Against all odds and against the impossible, it **must** be that process which causes corruptions, but how?

My first flash of inspiration why it’s always the last day of the month which gets corrupted. When a website owner downloads the access log, the server starts with the first day of the month, then the second day, and so on. Of course, the last day of the month is sent at the end; the last day of the month is always followed by the “PK” header. That’s why it’s more likely to corrupt the last day. (The other days can be corrupted if the requested month is not yet over, but that’s less likely.)

How?

Man staring at kernel code[](#man-staring-at-kernel-code "Permalink to this headline")
---------------------------------------------------------------------------------------

After being stuck for more hours, after eliminating everything that was definitely impossible (in my opinion), I drew a conclusion: this must be a kernel bug.

Blaming the Linux kernel (i.e. somebody else’s code) for data corruption must be the last resort. That is unlikely. The kernel is an extremely complex project developed by thousands of individuals with methods that may seem chaotic; despite of this, it is extremely stable and reliable. But this time, I was convinced that it must be a kernel bug.

In a moment of extraordinary clarity, I hacked two C programs.

One that keeps writing odd chunks of the string “AAAAA” to a file (simulating the log splitter):
``` c
#include <unistd.h>
int main(int argc, char \*\*argv) {
  for (;;) write(1, "AAAAA", 5);
}
// ./writer >foo
```
And one that keeps transferring data from that file to a pipe using splice() and then writes the string “BBBBB” to the pipe (simulating the ZIP generator):
``` c
#define \_GNU\_SOURCE
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char \*\*argv) {
  for (;;) {
    splice(0, 0, 1, 0, 2, 0);
    write(1, "BBBBB", 5);
  }
}
// ./splicer <foo |cat >/dev/null
```
I copied those two programs to the log server, and… **bingo**! The string “BBBBB” started appearing in the file, even though nobody ever wrote this string to the file (only to the pipe by a process without write permissions).

So this really is a kernel bug!

All bugs become shallow once they can be reproduced. A quick check verified that this bug affects Linux 5.10 (Debian Bullseye) but not Linux 4.19 (Debian Buster). There are 185.011 git commits between v4.19 and v5.10, but thanks to git bisect, it takes just 17 steps to locate the faulty commit.

The bisect arrived at commit [f6dd975583bd](https://github.com/torvalds/linux/commit/f6dd975583bd8ce088400648fd9819e4691c8958), which refactors the pipe buffer code for anonymous pipe buffers. It changes the way how the “mergeable” check is done for pipes.

Pipes and Buffers and Pages[](#pipes-and-buffers-and-pages "Permalink to this headline")
-----------------------------------------------------------------------------------------

Why pipes, anyway? In our setup, the web service which generates ZIP files communicates with the web server over pipes; it talks the [Web Application Socket](https://github.com/CM4all/libwas/) protocol which we invented because we were not happy with CGI, FastCGI and AJP. Using pipes instead of multiplexing over a socket (like FastCGI and AJP do) has a major advantage: you can use splice() in both the application and the web server for maximum efficiency. This reduces the overhead for having web applications out-of-process (as opposed to running web services inside the web server process, like Apache modules do). This allows privilege separation without sacrificing (much) performance.

Short detour on [Linux memory management](https://www.kernel.org/doc/html/latest/admin-guide/mm/concepts.html): The smallest unit of memory managed by the CPU is a **page** (usually 4 kB). Everything in the lowest layer of Linux’s memory management is about pages. If an application requests memory from the kernel, it will get a number of (anonymous) pages. All file I/O is also about pages: if you read data from a file, the kernel first copies a number of 4 kB chunks from the hard disk into kernel memory, managed by a subsystem called the **page cache**. From there, the data will be copied to userspace. The copy in the page cache remains for some time, where it can be used again, avoiding unnecessary hard disk I/O, until the kernel decides it has a better use for that memory (“reclaim”). Instead of copying file data to userspace memory, pages managed by the page cache can be mapped directly into userspace using the mmap() system call (a trade-off for reduced memory bandwidth at the cost of increased page faults and TLB flushes). The Linux kernel has more tricks: the sendfile() system call allows an application to send file contents into a socket without a roundtrip to userspace (an optimization popular in web servers serving static files over HTTP). The splice() system call is kind of a generalization of sendfile(): It allows the same optimization if either side of the transfer is a **pipe**; the other side can be almost anything (another pipe, a file, a socket, a block device, a character device). The kernel implements this by passing **page** references around, not actually copying anything (zero-copy).

A **pipe** is a tool for unidirectional inter-process communication. One end is for pushing data into it, the other end can pull that data. The Linux kernel [implements this by a ring](https://github.com/torvalds/linux/blob/v5.8/include/linux/pipe_fs_i.h#L76) of [struct pipe\_buffer](https://github.com/torvalds/linux/blob/v5.8/include/linux/pipe_fs_i.h#L26-L32), each referring to a **page**. The first write to a pipe allocates a page (space for 4 kB worth of data). If the most recent write does not fill the page completely, a following write may append to that existing page instead of allocating a new one. This is how “anonymous” pipe buffers work ([anon\_pipe\_buf\_ops](https://github.com/torvalds/linux/blob/v5.8/fs/pipe.c#L217-L221)).

If you, however, splice() data from a file into the pipe, the kernel will first load the data into the **page cache**. Then it will create a struct pipe_buffer pointing inside the page cache (zero-copy), but unlike anonymous pipe buffers, additional data written to the pipe must not be appended to such a page because the page is owned by the page cache, not by the pipe.

History of the check for whether new data can be appended to an existing pipe buffer:

*   Long ago, struct pipe_buf_operations had a flag called can_merge.
    
*   [Commit 5274f052e7b3 “Introduce sys\_splice() system call” (Linux 2.6.16, 2006)](https://github.com/torvalds/linux/commit/5274f052e7b3dbd81935772eb551dfd0325dfa9d) featured the splice() system call, introducing page_cache_pipe_buf_ops, a struct pipe_buf_operations implementation for pipe buffers pointing into the page cache, the first one with can_merge=0 (not mergeable).
    
*   [Commit 01e7187b4119 “pipe: stop using ->can\_merge” (Linux 5.0, 2019)](https://github.com/torvalds/linux/commit/01e7187b41191376cee8bea8de9f907b001e87b4) converted the can_merge flag into a struct pipe_buf_operations pointer comparison because only anon_pipe_buf_ops has this flag set.
    
*   [Commit f6dd975583bd “pipe: merge anon\_pipe\_buf\*\_ops” (Linux 5.8, 2020)](https://github.com/torvalds/linux/commit/f6dd975583bd8ce088400648fd9819e4691c8958) converted this pointer comparison to per-buffer flag PIPE_BUF_FLAG_CAN_MERGE.
    

Over the years, this check was refactored back and forth, which was okay. Or was it?

Uninitialized[](#uninitialized "Permalink to this headline")
-------------------------------------------------------------

Several years before PIPE_BUF_FLAG_CAN_MERGE was born, [commit 241699cd72a8 “new iov\_iter flavour: pipe-backed” (Linux 4.9, 2016)](https://github.com/torvalds/linux/commit/241699cd72a8489c9446ae3910ddd243e9b9061b) added two new functions which allocate a new struct pipe_buffer, but initialization of its flags member was missing. It was now possible to create page cache references with arbitrary flags, but that did not matter. It was technically a bug, though without consequences at that time because all of the existing flags were rather boring.

This bug suddenly became critical in Linux 5.8 with [commit f6dd975583bd “pipe: merge anon\_pipe\_buf\*\_ops”](https://github.com/torvalds/linux/commit/f6dd975583bd8ce088400648fd9819e4691c8958). By injecting PIPE_BUF_FLAG_CAN_MERGE into a page cache reference, it became possible to overwrite data in the page cache, simply by writing new data into the pipe prepared in a special way.

Corruption pt. IV[](#corruption-pt-iv "Permalink to this headline")
--------------------------------------------------------------------

This explains the file corruption: First, some data gets written into the pipe, then lots of files get spliced, creating page cache references. Randomly, those may or may not have PIPE_BUF_FLAG_CAN_MERGE set. If yes, then the write() call that writes the central directory file header will be written to the page cache of the last compressed file.

But why only the first 8 bytes of that header? Actually, all of the header gets copied to the page cache, but this operation does not increase the file size. The original file had only 8 bytes of “unspliced” space at the end, and only those bytes can be overwritten. The rest of the page is unused from the page cache’s perspective (though the pipe buffer code does use it because it has its own page fill management).

And why does this not happen more often? Because the page cache does not write back to disk unless it believes the page is “dirty”. Accidently overwriting data in the page cache will not make the page “dirty”. If no other process happens to “dirty” the file, this change will be ephemeral; after the next reboot (or after the kernel decides to drop the page from the cache, e.g. reclaim under memory pressure), the change is reverted. This allows interesting attacks without leaving a trace on hard disk.

Exploiting[](#exploiting "Permalink to this headline")
-------------------------------------------------------

In my first exploit (the “writer” / “splicer” programs which I used for the bisect), I had assumed that this bug is only exploitable while a privileged process writes the file, and that it depends on timing.

When I realized what the real problem was, I was able to widen the hole by a large margin: it is possible to overwrite the page cache even in the absence of writers, with no timing constraints, at (almost) arbitrary positions with arbitrary data. The limitations are:

*   the attacker must have read permissions (because it needs to splice() a page into a pipe)
    
*   the offset must not be on a page boundary (because at least one byte of that page must have been spliced into the pipe)
    
*   the write cannot cross a page boundary (because a new anonymous buffer would be created for the rest)
    
*   the file cannot be resized (because the pipe has its own page fill management and does not tell the page cache how much data has been appended)
    

To exploit this vulnerability, you need to:

1.  Create a pipe.
    
2.  Fill the pipe with arbitrary data (to set the PIPE_BUF_FLAG_CAN_MERGE flag in all ring entries).
    
3.  Drain the pipe (leaving the flag set in all struct pipe_buffer instances on the struct pipe_inode_info ring).
    
4.  Splice data from the target file (opened with O_RDONLY) into the pipe from just before the target offset.
    
5.  Write arbitrary data into the pipe; this data will overwrite the cached file page instead of creating a new anomyous struct pipe_buffer because PIPE_BUF_FLAG_CAN_MERGE is set.
    

To make this vulnerability more interesting, it not only works without write permissions, it also works with immutable files, on read-only btrfs snapshots and on read-only mounts (including CD-ROM mounts). That is because the page cache is always writable (by the kernel), and writing to a pipe never checks any permissions.

Timeline[](#timeline "Permalink to this headline")
---------------------------------------------------

*   2021-04-29: first support ticket about file corruption
    
*   2022-02-19: file corruption problem identified as Linux kernel bug, which turned out to be an exploitable vulnerability
    
*   2022-02-20: bug report, exploit and patch sent to the [Linux kernel security team](https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html)
    
*   2022-02-21: bug reproduced on Google Pixel 6; bug report sent to the Android Security Team
    
*   2022-02-21: [patch sent to LKML (without vulnerability details)](https://lore.kernel.org/lkml/20220221100313.1504449-1-max.kellermann@ionos.com/) as suggested by Linus Torvalds, Willy Tarreau and Al Viro
    
*   2022-02-23: Linux stable releases with my bug fix ([5.16.11](https://lore.kernel.org/stable/1645618039140207@kroah.com/), [5.15.25](https://lore.kernel.org/stable/164561803311588@kroah.com/), [5.10.102](https://lore.kernel.org/stable/164561802556115@kroah.com/))
    
*   2022-02-24: [Google merges my bug fix into the Android kernel](https://android-review.googlesource.com/c/kernel/common/+/1998671)
    
*   2022-02-28: notified the [linux-distros](https://oss-security.openwall.org/wiki/mailing-lists/distros#how-to-use-the-lists) mailing list
    
*   2022-03-07: public disclosure
