# Changelog

All notable changes to `linux.ldpreload` are documented here. Versions follow the
plugin's `_version` tuple.

## 1.8.0 (2026-11-20)

- Changed: the dynamic symbol table is now located the way the loader locates it,
  through the program headers: `PT_DYNAMIC` gives `DT_SYMTAB`, `DT_STRTAB`,
  `DT_STRSZ` and `DT_SYMENT`, its addresses are mapped to file offsets through the
  `PT_LOAD` segments' file parts, and the symbol count comes from `DT_GNU_HASH`
  (one past the end of the chain the highest bucket starts) or `DT_HASH`
  (`nchain`). Closes the item left open in 1.7.0: section headers, which the loader
  never reads and anyone can rewrite, no longer decide what a library exports. A
  library stripped of its section headers (`sstrip`) is now read in full.
- Changed: the section headers' `.dynsym` is a cross-check. A different offset,
  symbol count or set of exported functions, or no `.dynsym` at all, is reported in
  `Notes` ("section headers disagree with the dynamic segment (...)", naming the
  functions only one of them lists) and makes the read incomplete, so the library is
  not assumed safe. Section headers that were not recovered (cut off, or on an
  uncached page) are not a disagreement. Without a readable dynamic segment the
  section headers are a fallback, as before, and never a complete read.
- Changed: a library is assumed safe (and hidden by `--filter-safe-env`) only if its
  table was read in full through the dynamic segment: hash table, symbol table and
  string table without an uncached page, at least one symbol, no contradiction
  between `DT_HASH` and `DT_GNU_HASH`, and a consistent cross-check.
- The reader stays defensive and never raises. Forged values are bounded: at most
  512 program headers (more marks the header table implausible), 4096 dynamic
  entries (no `DT_NULL` within them, or within the segment, is noted), 2^20 hash
  buckets and bloom words, and the GNU chain walk and the symbol read stop at 65536
  symbols. Segments whose file part wraps the address or offset range map nothing;
  an address that two `PT_LOAD` segments map to different file offsets, several
  `PT_DYNAMIC` segments or a `DT_SYMENT` other than the ELF class's are noted and
  the dynamic table is not used. Buckets and chains are read in blocks, not
  entry by entry.
- Performance: resolving a preload line or environment name compared it with every
  cached library path (suffix and basename matches). It is now compared only with
  the cached paths of the same basename, from an index built once per run; the first
  match, and so the result, is the same. Names with `$LIB`/`$PLATFORM` tokens still
  go through the full matcher.
- Tests: 24 new tests. The ELF ones build 32- and 64-bit, little- and big-endian images with
  `DT_HASH`, `DT_GNU_HASH` or both and cover forged section headers, the fallback,
  and forged dynamic data (pointers outside the file, no `DT_NULL`, huge counts,
  endless GNU chains, `e_phnum` 65535, wrapping segments, unmappable and ambiguous
  addresses, uncached pages in each table); one parses the shared objects of the
  Python running the tests (its `lib-dynload` modules, libc, the loader) and expects
  each to be read completely and consistently. Another checks the indexed library
  lookup against the linear one on random input. The test image builder now emits
  program headers and a dynamic segment; the existing tests that are about images
  with section headers only build them without (`dynamic=False`).
- CI: a job installs the minimum framework version, `volatility3==2.26.0`, on
  Python 3.12 and runs the byte-compile, load check and unit tests against it.

## 1.7.0 (2026-11-20)

- Fixed (review): the pattern deciding whether a token names a shared object
  backtracked exponentially on a token such as `/x.so.a.a.a[...]/z`. The content scan
  applies it to every small file in the page cache, so one 100-byte file written by
  any user of the imaged system hung the plugin. The pattern is now unambiguous and
  matches the same names.
- Fixed (review): a name with several `$LIB`/`$PLATFORM`/`$ORIGIN` tokens (from a
  preload file or an `LD_PRELOAD` value) was matched against every cached library
  with a regex that backtracks polynomially, the token count being the degree; ten
  adjacent tokens took seconds per library, fourteen never returned. The regex is
  replaced by a matcher that is linear in the path per token and gives the same
  results; a name with more than eight tokens is not matched at all.
- Fixed (review): an inode time the framework cannot convert (the epoch itself, as
  `touch -d @0` sets it, a negative or an out-of-range value) comes back as an
  absent-value object rather than a `datetime`. It reached the `mtime`/`ctime`
  comparison and raised `TypeError` in the middle of the output, and was handed to
  `timeliner` as a timestamp. Such a time is now shown as not available; an inode
  layout the framework does not know is handled the same way instead of raising.
- Fixed (review): preload files were not split the way the loader splits them. glibc
  separates entries at colons, spaces, tabs and newlines only and treats a `#`
  anywhere as the start of a comment. The plugin did not split at colons
  (`/lib/a.so:/lib/b.so` was one unresolvable name, and a disguised preload file
  written that way failed the confirmation gate), took a comment only at the start
  of a line (`/lib/a.so#x` was neither resolved nor recognised as preload content,
  `/lib/a.so # note` listed `#` and `note` as libraries), and split at every Unicode
  whitespace character, cutting a path the loader reads whole.
- Fixed (review): `LD_PRELOAD` is split at colons and spaces and `LD_AUDIT` at
  colons only, as the loader does; before, any whitespace split both.
- Fixed (review): only the file a patched loader names had a read budget. Preload
  files found by name, libraries, dynamic linkers and leftover loader copies were
  read up to whatever `i_size` declared, so a sparse file with one cached page at
  its end (`ld-2.17.so.tmp` in `/tmp` is enough) made the reader zero-fill
  everything before it, and the resulting `MemoryError` was not caught. Each now has
  a budget (`PRELOAD_FILE_MAX_SIZE` 1 MiB, `LOADER_MAX_SIZE` 32 MiB,
  `FILE_READ_MAX_SIZE` 256 MiB for a library; constants, not options). A larger file
  is read up to its budget and `Notes` say so; running out of memory skips the
  file's content with a note instead of ending the run. An unreadable `i_size` no
  longer unbounds the read. A loader cut at the budget is reported as inconclusive,
  never as patched.
- Fixed (review): the check for an uncached `.rodata` page of a loader counted its
  4 KiB chunks from the start of the section, which is rarely page aligned (it is
  not in `ld-2.17.so`). Each chunk then straddled the missing page, none was all
  zero, and a loader that merely was not fully cached was reported as patched. The
  check now looks at the file's pages.
- Fixed (review): a library whose symbol table could not be read was reported as
  overriding nothing: no section headers (stripped with `sstrip`, which the loader
  does not mind, or their page at the end of the file not cached), an uncached page
  of `.dynsym`/`.dynstr`, or more than the 65536 symbols that are parsed. `Overridden
  Functions` now shows not available (`-`) instead of `N/A` and `Notes` say that the
  symbol table was not fully readable.
- Changed: an `LD_PRELOAD` / `LD_AUDIT` library is assumed safe only if its symbol
  table was read in full. A library in a system directory that is not in the page
  cache, not recoverable or has no readable symbol table was marked as assumed safe
  (and hidden by `--filter-safe-env`) although nothing of it had been seen; it is now
  reported without that mark.
- Fixed (review): a symbol name was searched for its terminator through the whole
  string table, once per symbol; a crafted table without terminators made that
  65536 full scans. The search stops after 4096 bytes.
- Fixed (review): the dentry-name read of the process correlation was sized by the
  longest wanted basename, which an environment value can make as long as it likes;
  it is capped at a file name's maximum length.
- Fixed (review): the task list is walked defensively in the superblock enumeration
  and the process correlation too, as it already was in the environment check; a
  read error in the middle of the list ended the run.
- The plugin now declares its dependency on `LinuxUtilities` (2.x), whose
  `get_path_mnt()` and `path_for_file()` it calls.
- Tests: 28 new tests cover the above (27 of them fail against 1.6.0; the last
  checks the declared requirements against the installed framework). The two
  backtracking cases run under a deadline so that a regression fails instead of
  hanging the suite. CI also runs the plugin's load check (`vol -p . ... --help`)
  and adds Python 3.14.

Second review round (same version):

- Fixed (review): the shared-object pattern was still quadratic when searched
  unanchored. A 60 KiB `LD_PRELOAD` name made of `.so` repeated, ending in a tab
  (which the loader-exact splitting now leaves in the name), took 15 s to assess,
  and an environment block may be 1 MiB. The question is now answered with string
  operations in linear time; the answers are the same for every input.
- Fixed (review): the recovered content of a file ends with its last cached page.
  A dynamic linker whose tail (section headers included) was not cached, and whose
  cached part does not hold `/etc/ld.so.preload`, was reported as patched. A loader
  whose `.rodata` cannot be located (no section headers) or reaches past the
  recovered content is now inconclusive when it was recovered shorter than its
  `i_size`, its `i_size` cannot be read or it was cut at the read budget. A loader
  whose `.rodata` is located and lies wholly in the recovered content is still
  judged, whatever else of the file is missing: patched, or inconclusive only if
  a page inside `.rodata` is not cached.
- Fixed (review): the read budgets were per file, so any number of sparse files
  under names the plugin reads were each read and kept in full. All budgeted reads
  of one run now share a total of 1 GiB (`TOTAL_READ_MAX_SIZE`, a constant). Once
  it is used up, a file is read only up to what is left, or not at all; its row
  says so in `Notes` and a warning is logged once. Content-scan candidates that
  turn out not to be preload files do not count.
- Fixed (review, partial): a library with no `.dynsym`, or with one of zero
  entries, was taken as fully read and exporting nothing, and so could be assumed
  safe. Section headers are written by whoever wrote the file; such a table now
  counts as not fully readable (`-`, with a note, and never assumed safe). Symbols
  from a `.symtab` fallback are still listed. Open: the dynamic segment, which is
  what the loader goes by, is still not parsed, so headers pointing at a
  plausible but different table are not detected.
- Fixed (regression in 1.7.0): since names are split as the loader splits them,
  they can contain newlines, tabs and other control characters, which went into
  the output cells and log lines as they were and could fake rows or columns.
  Control characters (C0, DEL, C1, U+2028/U+2029) are now shown as `\n`, `\t`,
  `\r` or `\xNN` in every cell, timeline description and log message of the
  plugin, task names (`comm`) and symbol names included. Internally, and for
  resolving a library, the name is unchanged; so are the columns.
- Fixed (review): a task, mount or mapping walk that died on a read error ended
  silently. It now logs a warning naming the walk and the error, since the entries
  after that point are missing from the result.
- Fixed (review): a file whose `i_size` cannot be read was read up to its budget
  without any mark. Its note now says that the size was unreadable, and it counts
  as truncated when the content fills the budget (so the content scan discards
  it).
- Tests: 23 more (21 fail against the first 1.7.0 state, two are guards for
  behaviour that must not change). The 1 MiB inputs must finish within a second.

## 1.6.0 (2026-10-07)

- Fixed: the string scan of a patched loader skipped every second absolute path in
  `.rodata` (the pattern consumed the NUL terminator it then needed as the next
  string's start). The replacement path recovered "by elimination" could be missed
  or misattributed whenever no leftover loader copy was cached.
- Fixed: a file the patched loader names is now analysed as a preload file whatever
  its name or location. Before, a target named like a library (`*.so.*`), under an
  `ld.so.*` name, outside `--scan-dir` or larger than a scan candidate was reported
  as "cached but could not be analysed".
- Fixed: a library named by several entries under different spellings (a preload
  line and a bare `LD_PRELOAD` value, or `/lib` and `/usr/lib`) got its `Mapped PIDs`
  on one of the rows only.
- Fixed: the glibc loader pattern did not match the mips loader name `ld.so.1`.
- Fixed: a task without an `fs_struct` (exiting) no longer marks its whole mount
  namespace as enumerated, which could hide a container's filesystems.
- Fixed: `ld.so.cache` / `ld.so.conf` were indexed as libraries, so a scanned file
  naming only those could pass the confirmation gate; they are now excluded from the
  library index and from preload content.
- Fixed (review): that exclusion matched every basename starting with `ld.so.`, so a
  real shared object such as `/usr/lib/ld.so.evil.so` dropped out of the library
  index, and a preload file or patched-loader target naming it was rejected. Only
  the exact loader-owned names (`ld.so.cache`, `ld.so.cache~`, `ld.so.conf`,
  `ld.so.conf.d`, `ld.so.preload`) are excluded now.
- Fixed (review): the file a patched loader names was read without any size bound,
  so a large or smeared sparse inode could make the reader allocate up to its
  declared size (a `MemoryError` was not caught). It now has its own budget,
  `LOADER_TARGET_MAX_SIZE` (1 MiB, above the scan's 4 KiB), checked against `i_size`
  before any page is read. A target above it, or one whose read runs out of memory,
  is not analysed, and the loader row's `Notes` say the analysis is incomplete. Both
  page-cache readers (framework and compatibility) now refuse to place a page beyond
  `i_size` before allocating for it. For the loader target both are held to the
  size checked against the budget, not to a later `i_size` read; a page outside
  it (or at a negative offset) marks the target incomplete instead of keeping the
  bytes read so far or retrying unbounded. No new option.
- Fixed (review): the loader target was resolved by the first suffix match in cache
  enumeration order, so `/container/etc/x` could be read and attributed to the
  loader (`_confirmed_by`) although `/etc/x` itself was cached. An exact path now
  always wins. When only suffix matches remain and they are several distinct files,
  none is read or confirmed as the loader's target; the loader row's `Notes` list
  them as ambiguous. The same rule decides which content-scanned preload files a
  patched loader confirms.
- Fixed: a well-known preload name only counts as such with a numeric version
  suffix (`libasan.so.8`, not `libasan.so.8.txt`), and `libclang_rt.asan-x86_64.so`
  is recognised.
- A library that is named but not present in the page cache now says so in `Notes`
  instead of showing bare `-` cells.
- `timeliner` also receives the leftover loader copies.
- The overridden-function list covers `dlsym`/`dlopen`, the `*_r` account lookups,
  the utmp/wtmp functions, the remaining `stat`/`open`/`readlink` variants, the raw
  `syscall` wrapper and `recvmsg`/`sendmsg`/`shutdown`; duplicates removed.
- The ELF reader rejects an implausible section-header entry size instead of
  parsing the same header 512 times.
- Library classification uses the basename, so a file inside a directory whose name
  contains `.so.` still reaches the content scan.
- `_required_framework_version` is now `(2, 26, 0)`, the first release with the
  `PsList` 4.x and `InodePages` 3.x interfaces the plugin requires; the README said
  2.0.
- New: a unit-test suite (`tests/`) for the image-independent code (ELF reader,
  preload parsing and content test, path resolution, environment assessment, loader
  string recovery, name patterns, rendering helpers) and a GitHub Actions workflow
  that runs it.
- Tests (review): the section-header entry-size check is now probed directly on a
  non-null header, so the test fails without the fix (the earlier one passed either
  way: its first header is the null one). A loader target that lists a bare library
  name is pinned as not analysed; that is the current, documented limitation.

## 1.5.0 (2026-08-26)

- Every process carrying `LD_PRELOAD` / `LD_AUDIT` is now reported by default; a
  library assumed safe (in a system library directory with no suspicious trait, or a
  well-known preload such as a sanitiser, allocator, fakeroot or a vendor wrapper) is
  marked so in the note. The new `--filter-safe-env` option hides those rows; it
  replaces `--env-all`, which had the inverse default.

## 1.4.0 (2026-08-26)

- New: `LD_PRELOAD` / `LD_AUDIT` detection in process environments. Each task's
  exec-time environment block is read from its stack (a later `unsetenv` does not
  hide it), the named objects are resolved (absolute, bare and relative values), the
  library is recovered, parsed and correlated with the processes mapping it, and the
  row states which processes carry the variable, whether they map the library and why
  it is suspicious (outside the system library directories, relative path, hidden,
  not named like a shared object, overrides libc functions). `File` shows
  `LD_PRELOAD (environment)`; the library feeds `timeliner` and `--dump`.
- New options: `--no-env` disables the check; `--env-all` also shows libraries in a
  system library directory with no suspicious trait or well-known preload names
  (sanitisers, allocators, fakeroot, vendor wrappers), which are suppressed by default.
- The overridden-function list now also covers what credential stealers and backdoors
  hook: the stdio family (`fwrite`, `fgets`, ...), `execv*`, socket calls, more PAM
  and identity functions, `setuid`/`setgid`, `getenv`, `syslog`.
- An environment-named library that overrides no known function gets its exports
  listed in the note instead of a bare `N/A`.

## 1.3.4 (2026-08-21)

- Folding of long cells now applies only when the pretty renderer consumes the output;
  the tab-separated default renderer, JSON and CSV get single-line cells again.
  `--wrap N` forces folding for any renderer, `--wrap 0` disables it.

## 1.3.3 (2026-08-21)

- Long cells (function lists, PID lists, notes) are folded into lines of at most
  `--wrap` characters (default 48). The text renderers print such a cell as a block,
  the way `malfind` shows hexdumps, so the table stays narrow with `-r pretty`
  regardless of how many functions a library hooks. `--wrap 0` restores single-line
  cells for `-r json` / `-r csv`.

## 1.3.2 (2026-08-21)

- Columns `Preload File` / `Preload Modification Time` renamed to `File` /
  `File Modification Time`: for a dynamic-linker row they hold the loader's path and
  the time it was patched, which the old names obscured.
- A file whose inode change time is well after its modification time gets a note with
  the change time: the `mtime` was preserved from an original or set deliberately, and
  the change time is when the file really got its content.

## 1.3.1 (2026-08-20)

- Overridden-function matching knows the pre-glibc-2.33 export names of the `stat`
  family (`__xstat`, `__lxstat`, `__fxstat`, `__fxstatat` and their 64-bit variants),
  which rootkits built for enterprise Linux actually hook; added further common hook
  targets (`fstat64`, `lstat64`, `readdir_r`, `getdents(64)`, `statx`, the `execl`
  family, `system`, `popen`, `getpwuid`, `pam_acct_mgmt`, `pcap_next`/`pcap_dispatch`).
- Loader-copy detection (`ld-*.so.tmp` and the like) only accepts a version suffix
  between `.so` and the backup suffix and requires ELF content, so `ld.so.conf.bak`
  or `ld.so.cache~` are no longer reported.
- Renamed copies of the preload file (`/etc/ld.so.preload.bak`, `.orig`, `.rpmsave`,
  ...) are analysed as preload files and marked as copies not read by the loader.

## 1.3.0 (2026-08-20)

- Dynamic-linker integrity check: every glibc loader in the page cache is read and
  checked for its compiled-in `/etc/ld.so.preload` string. A patched loader is
  reported with the path it reads instead, recovered exactly from a leftover copy of
  the original when one is cached, otherwise from the loader's own strings and
  verified against the page cache. A disguised preload file named by a patched loader
  is confirmed by that alone.
- Page-cache reading works on kernels whose symbol table lacks `struct page`'s
  `mapping`/`index` fields (kABI-padded 4.18 distribution kernels): the layout is
  derived and validated against real pages.
- The compatibility page reader uses the XArray walker on XArray kernels.

## 1.2.0 (2026-08-20)

- Performance: the disguised-preload content scan inspects a candidate's first cached
  page through raw reads and constructs framework objects only for hits; the dentry
  walk reads each dentry once; the VMA walk reads each VMA once. Plugin runtime over
  Volatility's own start-up dropped from ~25 s to ~1 s on a 4 GB image, with identical
  output.

## 1.1.0 (2026-08-20)

- Multi-page files are readable on kABI-padded 3.10 distribution kernels, where the
  framework cannot resolve the radix-tree node height: a compatibility walker decodes
  it raw and self-validates the layout, so overridden-function lists are available
  there.

## 1.0.0 (2026-08-20)

- Initial public release: recovery of `/etc/ld.so.preload` from the page cache,
  library resolution (`$PLATFORM`/`$LIB`, usr-merge), `.dynsym` parsing for overridden
  functions, process correlation with `vm_file` recovery fallback, whole-page-cache
  content scan for disguised preload files with a confirmation gate, linker
  tamper-artifact detection, `timeliner` integration and `--dump`.
