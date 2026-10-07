# Changelog

All notable changes to `linux.ldpreload` are documented here. Versions follow the
plugin's `_version` tuple.

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
