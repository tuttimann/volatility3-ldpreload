# linux.ldpreload: ld.so.preload rootkit detection for Volatility 3

A Volatility 3 plugin that finds `/etc/ld.so.preload` **userland rootkits** in a Linux
memory image and explains what they do.

`/etc/ld.so.preload` makes the dynamic loader map a shared object into *every*
dynamically linked process before libc. Any function the object exports wins over the
libc one, so a one-line file turns `readdir`, `open`, `accept` or `pam_authenticate`
into the attacker's versions for the whole userland. It is the persistence mechanism of
libprocesshider, Azazel, Jynx/Jynx2, bdvl, HiddenWasp and Symbiote, and it is absent on
a clean system.

On a compromised host the usual tools are dynamically linked themselves and therefore
lie. This plugin works from the **page cache** in the memory image: the file, the
library and the loader as the kernel holds them, which no userland hook can touch.

## Capabilities

- **Recovers `/etc/ld.so.preload`** from the page cache, including copies inside
  container root filesystems and renamed backups (`ld.so.preload.bak`, `.orig`, ...).
- **Resolves every library it names**, `$PLATFORM`/`$LIB` dynamic-string tokens and
  `/lib` → `/usr/lib` usr-merge aliases included, and recovers the library's content
  even when its directory entry is no longer cached (via the inode of a process that
  maps it).
- **Lists the libc/PAM/pcap functions each library overrides**, parsed from the
  recovered ELF's `.dynsym`; `--all-symbols` shows the complete export table.
- **Correlates with running processes**: which PIDs currently map the library,
  rendered as compact `first-last` ranges.
- **Defeats dynamic-linker patching.** Some rootkits never create
  `/etc/ld.so.preload`; they patch that string inside `ld-linux*.so` so the loader reads
  a file of any name in any directory. The plugin
  - finds such a file **by content** (a small file consisting only of absolute `.so`
    paths) anywhere in the page cache, with a confirmation gate that keeps the scan
    free of false positives;
  - **reads every glibc dynamic linker in the page cache and checks its compiled-in
    preload path**; a patched loader is reported together with the path it reads
    instead, recovered exactly by diffing against a leftover copy of the original or by
    elimination from the loader's own strings, verified against the page cache;
  - reports **leftover loader copies** (`ld-*.so.tmp`, `.bak`, ...) that an in-place
    patch leaves behind.
- **Feeds `timeliner`** with the modification and change times of preload files,
  libraries and patched loaders, and **extracts** all of them with `--dump`.
- **Runs on kernels the framework alone cannot read**: kABI-padded RHEL/CentOS 7 and 8
  kernels, whose symbol tables hide the radix-tree node height or `struct page`
  fields, are handled by a self-validating compatibility reader.

## Requirements

- Volatility 3 ≥ 2.0 (developed and tested with 2.28) and a symbol table (ISF) for the
  image's kernel, as for any Linux plugin.
- No third-party Python packages.

## Installation

Either copy the plugin into your Volatility 3 installation:

```bash
cp linux/ldpreload.py <volatility3>/volatility3/framework/plugins/linux/
```

or point Volatility at this repository without touching the installation (the
`linux/` directory layout is what `-p` expects):

```bash
vol -p /path/to/volatility3-ldpreload -f image.lime linux.ldpreload.LdPreload
```

## Usage

```bash
vol -f image.lime linux.ldpreload.LdPreload
```

With no options the plugin does everything: recovers `/etc/ld.so.preload`, scans the
whole page cache by content for a disguised preload file, verifies every glibc dynamic
linker, checks for linker tamper artifacts, analyses every library and correlates it
with running processes.

| Option | Effect |
|---|---|
| `--path GLOB [GLOB ...]` | Additional full-path glob patterns to treat as preload files (e.g. `'*/opt/app/etc/ld.so.preload'`). |
| `--scan-dir DIR [DIR ...]` | Restrict the disguised-preload content scan to these directories. Default: the whole page cache. |
| `--no-scan` | Disable the content scan, the dynamic-linker integrity check and the tamper-artifact check; only `/etc/ld.so.preload` is used. |
| `--all-symbols` | List every exported function of each library, not only those that shadow a known libc/PAM/pcap function. |
| `--skip-maps` | Do not walk process mappings (faster; `Mapped PIDs` stays empty). |
| `--dump` | Write the preload file(s), every resolved library, every patched loader and any linker artifact to the output directory (`-o`). |

Examples:

```bash
# Full analysis, extracting every recovered file to ./out
vol -f image.lime -o out linux.ldpreload.LdPreload --dump

# Complete export table of each library (shows the rootkit's own function names too)
vol -f image.lime linux.ldpreload.LdPreload --all-symbols

# Quick check of the standard file only
vol -f image.lime linux.ldpreload.LdPreload --no-scan --skip-maps

# Put the findings on the system timeline
vol -f image.lime timeliner.Timeliner --plugin-filter linux.ldpreload
```

## Output

One row per preload entry, plus one row per patched dynamic linker and per leftover
loader copy. Seven columns:

| Column | Meaning |
|---|---|
| Preload File | Path of the preload file as cached (`/etc/ld.so.preload`, a renamed copy, or the disguised name). For linker rows: the loader's path. |
| Preload Modification Time | Its `mtime`, i.e. when the persistence was installed or last changed. |
| Library | The shared object the line names, exactly as written (tokens such as `$PLATFORM` are kept). `(dynamic linker)` / `(dynamic linker copy)` for linker rows. |
| Library Modification Time | The recovered library's `mtime`. |
| Overridden Functions | Global `FUNC` symbols in the library's `.dynsym` that shadow a libc/PAM/pcap function of interest (or everything, with `--all-symbols`). |
| Mapped PIDs | Processes that currently map the library; consecutive PIDs collapsed into `first-last` ranges. |
| Notes | How the file was found, what a patched loader reads, and anything that limits the analysis. |

A classic infection (standard file, bdvl-style library name) on a RHEL 9 host:

```
Preload File        Preload Modification Time   Library              Library Modification Time   Overridden Functions                                   Mapped PIDs                              Notes
/etc/ld.so.preload  2026-08-14 18:13:07 UTC     /lib64/selinux.so.3  2026-08-14 18:12:53 UTC     __lxstat, __lxstat64, accept, access, execve,          1, 549, 571, 605, 607, 682, 685-691, ...   N/A
                                                                                                  fopen, fopen64, fstat, lstat, open, open64, openat,
                                                                                                  opendir, pam_authenticate, readdir, unlink, unlinkat
```

The same rootkit configured to patch the loader instead, on a CentOS 7 host. There is
no `/etc/ld.so.preload` at all; the plugin finds the file by content, lists the 38
functions its library overrides, proves that both the 64-bit and the 32-bit loader were
patched to read it, and reports the copy of the original loader the patch left behind:

```
Preload File               Library                                    Overridden Functions                    Mapped PIDs  Notes
/etc/shadowrddoqnf         /bin/opensslbn/libopensslbn.so.$PLATFORM   __fxstat, __fxstat64, __lxstat,         14548        disguised preload file: the dynamic linker
                                                                      __lxstat64, __xstat, __xstat64, accept,              /usr/lib64/ld-2.17.so is patched to read it
                                                                      access, execve, execvp, fopen, fopen64,              instead of /etc/ld.so.preload
                                                                      fstat, fstat64, fstatat, getpwnam, ...
/usr/lib/ld-2.17.so        (dynamic linker)                           -                                       N/A          patched dynamic linker: reads /etc/shadowrddoqnf
                                                                                                                           (analysed above) instead of /etc/ld.so.preload
/usr/lib64/ld-2.17.so      (dynamic linker)                           -                                       N/A          patched dynamic linker: reads /etc/shadowrddoqnf
                                                                                                                           (analysed above) instead of /etc/ld.so.preload
/usr/lib64/ld-2.17.so.tmp  (dynamic linker copy)                      -                                       N/A          leftover copy of the dynamic linker, consistent
                                                                                                                           with an in-place patch of ld.so
```

A clean system produces an empty table and an informational log line saying that no
preload file is present.

### Reading the result

- **Overridden Functions** is the finding. `readdir`/`readdir64`/`getdents` hide
  directory entries (processes, files); `accept`/`bind`/`connect` mean a network
  backdoor; `pam_authenticate`/`pam_open_session` mean credential theft or a magic
  password; `execve`/`fork`/`system` mean process-level control; `pcap_loop`/`pcap_next`
  hide traffic from sniffers; the `__xstat`/`__lxstat`/`__fxstat` family is how
  `stat()` is hooked on glibc before 2.33.
- **Mapped PIDs** is the blast radius. Mapped by almost every PID: in place since boot
  or the last mass restart. Mapped by nothing: installed moments before the capture
  (the file's `mtime` usually confirms it).
- A **`(dynamic linker)` row** means the loader itself is modified; removing the
  library is not enough, glibc has to be restored. Its note says which file the loader
  reads and whether that file was analysed above, is cached but unreadable, or is not
  in the page cache at all.

## How it works

1. **Page-cache walk.** Superblocks are enumerated once per mount namespace, pseudo
   filesystems are skipped, and every dentry is read once as raw bytes; sibling link,
   inode pointer and name come out of that one buffer. Every regular file's path and
   inode address is classified: preload file, `.so` library, glibc loader, loader copy,
   or content-scan candidate.
2. **Content scan.** A candidate's size and first cached page are read through raw
   reads of `inode.i_mapping`, the address space's page count and tree head, and the
   `struct page`; the page is tested for preload content (nothing but absolute `.so`
   paths) before any framework object exists. A hit is kept only if a library it names
   resolves to a cached object, is mapped by a process, or is named by a patched loader.
3. **Loader integrity.** Each glibc loader (`ld-linux*.so.N`, `ld-2.xx.so`, `ld64.so.N`,
   `ld.so.N`, any directory) is read and searched for `/etc/ld.so.preload`. If absent
   and its `.rodata` is fully cached, it is patched; the replacement is recovered from a
   same-directory leftover copy by byte diff, or from the loader's `/`-strings minus
   the stock ones, cross-checked against the page cache.
4. **ELF parsing.** A small defensive reader parses `.dynsym` from the recovered image
   (holes allowed) and keeps global `FUNC` definitions.
5. **Process correlation.** Each task's VMAs are followed with raw reads
   (`vma → vm_file → dentry`); a wanted library is recognised by inode address, and only
   a matching basename pays for full path reconstruction. A library no cached dentry
   leads to anymore is recovered from the mapping process's `vm_file` inode.
6. **Compatibility readers.** Where the framework's page-cache reader fails (the
   radix-tree node height on kABI-padded 3.10 kernels, `struct page` without
   `mapping`/`index` on 4.18), the plugin decodes the structures raw and validates the
   layout against real pages before trusting it.

## Tested on

| Distribution | Kernel | Page tree | VMA layout |
|---|---|---|---|
| CentOS 7 | 3.10.0-1127 | radix tree (kABI-padded) | `vm_next` list |
| CentOS 8 | 4.18.0-305 | XArray (symbol table lacks `page.mapping`) | `vm_next` list |
| RHEL 9 clones | 5.14.0-284 | XArray | `vm_next` list |
| Ubuntu 24.04 | 6.8.0 | XArray | maple tree |

with libprocesshider, bdvl (standard and linker-patching configuration), a second
linker-patching tool and custom preload libraries, plus clean images of the same hosts.

## Limitations

- Overridden functions come from `.dynsym`; a library that hooks purely by patching its
  own imports at runtime is still reported (with PIDs and timestamps) but with an empty
  function list.
- The loader check covers glibc; musl has no preload file. A loader whose `.rodata`
  pages are not all cached is reported as inconclusive, never guessed at.
- Physical-address translation of `struct page` in the fast paths uses the Intel
  `vmemmap` layout; on other architectures the plugin falls back to the framework's
  object-based reader (slower, same result).
- A preload library whose pages were never cached and that no process maps can be named
  but not analysed; the `Notes` column says so.

## Repository layout

```
linux/ldpreload.py   the plugin (single file)
CHANGELOG.md         version history
```

## License

Licensed under the [Volatility Software License 1.0](LICENSE). Copyright 2026 tuttimann.
