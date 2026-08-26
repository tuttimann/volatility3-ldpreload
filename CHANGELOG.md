# Changelog

All notable changes to `linux.ldpreload` are documented here. Versions follow the
plugin's `_version` tuple.

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
