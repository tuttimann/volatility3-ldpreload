# This file is Copyright 2026 tuttimann and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Detects ``/etc/ld.so.preload`` userland rootkits in a Linux memory image.

``/etc/ld.so.preload`` names shared objects that the dynamic loader maps into *every*
dynamically linked process before libc. A symbol defined there wins over the libc one,
so a single line in a tiny file silently rewrites the behaviour of the whole userland.
It is the persistence mechanism behind libprocesshider, Azazel, Jynx/Jynx2, bdvl,
Symbiote and HiddenWasp, and it is normally absent on a clean system -- its mere
presence is worth investigating.

The plugin recovers the file from the page cache, resolves every library it lists,
parses the recovered ELF, and reports **which libc functions each library overrides**
and the PIDs currently mapping it. That is what turns "an odd file exists" into "this
library replaces ``readdir``, so it is hiding directory entries". Working from the page
cache rather than the live filesystem matters: a preload rootkit typically hooks
``readdir`` and ``open``, so on-host tools are lying -- the page cache is not subject
to those hooks, and neither is Volatility.

One row per preload entry: the preload file and its modification time, the library and
its modification time, the libc functions the library overrides, the PIDs mapping it,
and a note. Both timestamps also feed ``linux.timeliner``. A preload library is mapped
into essentially every process, so ``Mapped PIDs`` collapses consecutive PIDs into
inclusive ``first-last`` ranges (e.g. ``1, 549, 685-691, ...``); the rendering is
lossless.

Detecting dynamic-linker patching
---------------------------------
Some rootkits (e.g. bdvl) never create ``/etc/ld.so.preload``. They patch the literal
``"/etc/ld.so.preload"`` string *inside the dynamic linker* (``ld-*.so``) to a
different path, so the loader reads a differently named file -- under any name, in any
directory -- and a name-based search finds nothing. This is caught independently of
the chosen name and location:

* Disguised preload file: the page cache is scanned by content (``--scan-dir`` to
  restrict to given directories, ``--no-scan`` to disable) for a small file whose
  content is *exclusively* absolute shared-object paths -- which is what a preload
  file is and what ordinary config (prelink, sestatus, GSS-mech, ...) is not. Such a
  file is analysed like any preload file. ``$PLATFORM``/``$LIB`` dynamic-string tokens
  in the library path are expanded and matched token-agnostically, so the real cached
  object still resolves.
* Patched loader: every glibc dynamic linker in the page cache (any name, any
  directory, container roots included) is read and its built-in preload path is
  checked. A loader that no longer contains ``"/etc/ld.so.preload"`` is reported with
  the path it reads instead -- recovered exactly by diffing against a leftover copy of
  the original when one exists, otherwise from the loader's own strings and verified
  against the page cache. A disguised preload file whose name appears in a patched
  loader is thereby confirmed, and a patched loader is reported even when the file it
  points at is not cached.
* Linker tamper artifact: a leftover patched-loader copy (``ld-*.so.tmp``, ``.bak``,
  ``.orig``, ...) is reported. An in-place patch of ``ld.so`` typically writes such a
  copy and renames it over the original, so it is a strong indicator on its own.

A library whose dentry path is no longer cached (parent dentries evicted, or the file
unlinked after loading) is still recovered through the inode a mapping process's
``vm_file`` points at. Content is read through the framework's page-cache reader,
falling back to a compatibility reader on kernels whose symbol table does not let the
framework resolve the radix-tree node height or the ``struct page`` fields (kABI-padded
RHEL/CentOS kernels). Should neither succeed, the library is still located, named and
correlated to its mapping PIDs, but its overridden-function list cannot be read, which
the row's note states rather than showing a bare ``-``.

Design notes
------------
The page cache is walked directly rather than through ``pagecache.Files.get_inodes()``,
which dereferences and validates every inode before yielding it -- work this plugin
discards for all but a handful of paths. The direct walk reads each dentry once as raw
bytes and takes the sibling link, the inode pointer and the name (inline short names
included) from that buffer at symbol-table member offsets, tests the path string
first, and defers inode object construction and validation to the files actually
selected. Superblocks are enumerated once per mount namespace, and pseudo filesystems
(proc, sysfs, cgroup, ...) are skipped whole.

The content scan for a disguised preload file applies the same principle to file
content: a candidate's size and its first cached page are reached through raw reads
(``inode.i_mapping``, the address space's page count and tree head, the ``struct
page`` and its physical address) and tested before any object exists. Only a file
whose content passes is read and validated through the framework's page-cache
reader; a candidate the raw reads cannot decide on is handed to that reader as well.

Mapping correlation follows the raw pointer chain
``vma -> vm_file -> f_path.dentry -> d_name.name`` with direct layer reads instead of
constructing a ``vm_area_struct`` object per VMA. A wanted library is recognised by
inode address; only a matching dentry basename pays for full path reconstruction, and
every per-file result is cached across processes. Each per-VMA read is guarded
individually, which also sidesteps ``vm_area_struct.is_valid()`` dereferencing a
file-backed VMA's inode without a ``None`` check: one bad VMA costs one VMA, not the
rest of the task's mappings.

Plugin provided: ``linux.ldpreload.LdPreload``.
"""

import datetime
import fnmatch
import functools
import logging
import re
import stat
import struct
from dataclasses import dataclass, field
from io import BytesIO
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple, Union

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import architectures
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import linux as linux_symbols
from volatility3.plugins import timeliner
from volatility3.plugins.linux import pagecache, pslist

vollog = logging.getLogger(__name__)

# The loader only ever reads this one path, but the glob also catches the file inside
# container root filesystems, which appear as separate superblocks in the page cache.
PRELOAD_GLOBS = ("*/etc/ld.so.preload",)
# A renamed copy of the file (ld.so.preload.bak, .orig, .rpmsave, ...) is not read by
# the loader, but it records an earlier state of the persistence and is analysed too.
PRELOAD_COPY_GLOBS = ("*/etc/ld.so.preload.*",)

# Some rootkits never touch /etc/ld.so.preload. They patch the literal
# "/etc/ld.so.preload" string *inside the dynamic linker* to a different path, so
# the loader reads their file instead and a plugin globbing for the standard name
# sees nothing. That file is just an ordinary-looking regular file -- under any
# name, in any directory -- so it is found by content rather than name: the page
# cache is scanned for a small file that names only shared objects, which is what
# a preload file is and almost nothing else is. Being name and location
# independent, this also catches a later run that picks a different name or path.
PRELOAD_SCAN_MAX_SIZE = 4096  # a preload list is a few short paths; never a page+

# Returned by the scan's raw first-page reader for a file it cannot decide on
# (its page-tree head is not a direct page pointer); the caller then reads the
# file through the framework's object layer instead.
UNDECIDED = object()

# Loader-owned /etc files that would false-match the "names a .so" test:
# ld.so.cache lists every library on the system. ld.so.preload itself is handled
# by the glob above; ld.so.conf(.d) names directories, not objects.
SCAN_SKIP_PREFIXES = ("ld.so.",)

# A token naming a shared object, allowing the ld.so dynamic-string tokens
# ($PLATFORM/$LIB/$ORIGIN) that the loader expands at runtime.
SO_TOKEN_RE = re.compile(r"\.so(?:\.[^/\s]+)*$")
DYNAMIC_TOKEN_RE = re.compile(r"\$\{?(?:PLATFORM|LIB|ORIGIN)\}?")

# Dynamic linker file names with trailing junk that betrays an in-place patch left
# on disk: an in-place patch of ld.so typically writes the patched loader to a temp
# copy (ld-*.so.tmp) and renames it over the original, so such a leftover is a
# strong tamper indicator.
# The glibc loader proper, under every name it ships as: ld-linux-x86-64.so.2,
# ld-linux.so.2, ld-linux-aarch64.so.1, ld-linux-armhf.so.3, ld-2.17.so, ld64.so.1
# (ppc64/s390x), ld.so.1 (mips). musl has no preload file, so it is not checked.
GLIBC_LOADER_RE = re.compile(
    r"^ld-linux[\w-]*\.so(?:\.\d+)+$|^ld-\d+\.\d+(?:\.\d+)?\.so$|^ld64?\.so(?:\.\d+)+$"
)
# The preload path compiled into the glibc loader, and the other absolute paths a
# stock loader carries. A replacement for the former is recovered by elimination:
# a NUL-terminated string starting with "/" that is neither a search directory
# (trailing "/") nor one of these.
LOADER_PRELOAD_STRING = b"/etc/ld.so.preload"
LOADER_KNOWN_PATHS = frozenset(
    {
        "/etc/ld.so.cache",
        "/etc/suid-debug",
        "/proc/self/exe",
        "/proc/sys/kernel/osrelease",
        "/dev/full",
        "/dev/null",
        "/var/tmp",
        "/var/profile",
    }
)
LOADER_IGNORED_PREFIXES = ("/proc/", "/dev/", "/sys/")
LOADER_STRING_RE = re.compile(rb"\x00(/[\x21-\x7e]{1,254})\x00")
# Only a version suffix may sit between the ".so" and the junk: ld.so.conf.bak or
# ld.so.cache~ (ldconfig's own temporary name) are ordinary files, not loader copies.
LINKER_ARTIFACT_RE = re.compile(
    r"^ld-(?:linux[\w-]*|musl[\w-]*|\d[\d.]*)\.so(?:\.\d+)*"
    r"(?:\.tmp|\.new|\.orig|\.old|\.bak|\.swp|~|\.\d{3,})$"
    r"|^ld\.so(?:\.\d+)*(?:\.tmp|\.new|\.orig|\.old|\.bak|\.swp|~)$"
)

# Kernel-populated pseudo filesystems that cannot hold a preload file or a library:
# nothing can create a regular file on them. Their dentry caches are large (a dentry
# per visited /proc/<pid> entry, all of sysfs), so skipping the walk is a measurable
# saving. Writable RAM-backed filesystems (tmpfs, ramfs, devtmpfs, overlay) are
# deliberately NOT listed, and an unknown or unreadable type is walked.
PSEUDO_FILESYSTEMS = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "efivarfs",
        "fusectl",
        "mqueue",
        "nsfs",
        "proc",
        "pstore",
        "rpc_pipefs",
        "securityfs",
        "selinuxfs",
        "sysfs",
        "tracefs",
    }
)

# libc/PAM/pcap function names commonly interposed from a preload library. The set is
# used purely for matching: an exported symbol with one of these names overrides the
# original at load time. What that means is left to the analyst -- sanitisers and
# profilers interpose the same functions as rootkits do. Before glibc 2.33 the stat
# family was exported as __xstat/__lxstat/__fxstat/__fxstatat (and their 64-bit
# variants), which is what a rootkit built for those systems hooks.
INTERPOSED_LIBC_FUNCTIONS = frozenset(
    {
        "__fxstat",
        "__fxstat64",
        "__fxstatat",
        "__fxstatat64",
        "__lxstat",
        "__lxstat64",
        "__xstat",
        "__xstat64",
        "accept",
        "access",
        "acct",
        "bind",
        "connect",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "fopen",
        "fopen64",
        "fork",
        "fstat",
        "fstat64",
        "fstatat",
        "getdents",
        "getdents64",
        "getpwent",
        "getpwnam",
        "getpwuid",
        "kill",
        "link",
        "listxattr",
        "lstat",
        "lstat64",
        "open",
        "open64",
        "openat",
        "opendir",
        "pam_acct_mgmt",
        "pam_authenticate",
        "pam_open_session",
        "pcap_dispatch",
        "pcap_loop",
        "pcap_next",
        "pcap_next_ex",
        "pcap_stats",
        "popen",
        "ptrace",
        "read",
        "readdir",
        "readdir64",
        "readdir_r",
        "readlink",
        "rename",
        "socket",
        "stat",
        "stat64",
        "statvfs",
        "statx",
        "system",
        "unlink",
        "unlinkat",
        "write",
    }
)

# -- minimal ELF reader ----------------------------------------------------------
#
# The recovered buffer is a file image, not a loaded module, and it may be partially
# populated where the page cache had holes. A dedicated reader is therefore used
# rather than Volatility's in-memory ELF handling: it parses defensively and returns
# whatever it managed to decode instead of raising.

ELF_MAGIC = b"\x7fELF"

SHT_SYMTAB = 2
SHT_DYNSYM = 11

STT_FUNC = 2
STB_LOCAL = 0
SHN_UNDEF = 0


@dataclass
class ElfInfo:
    """What could be decoded from a recovered ELF image."""

    valid: bool = False
    bits: int = 0
    #: Global FUNC symbols the object *defines*: these override libc at load time.
    exported: List[str] = field(default_factory=list)

    def interposed(self) -> List[str]:
        """Exported functions that shadow a libc function of interest."""
        return [name for name in self.exported if name in INTERPOSED_LIBC_FUNCTIONS]


class ElfReader:
    """Parses just enough ELF to describe a shared object recovered from memory."""

    @classmethod
    def parse(cls, data: bytes) -> ElfInfo:
        info = ElfInfo()
        if len(data) < 64 or not data.startswith(ELF_MAGIC):
            return info

        elf_class = data[4]
        endian = "<" if data[5] == 1 else ">"
        if elf_class not in (1, 2):
            return info

        info.bits = 32 if elf_class == 1 else 64
        info.valid = True

        try:
            if info.bits == 64:
                e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
                e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 58)
            else:
                e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
                e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 46)
        except struct.error:
            return info

        if not e_shoff or not e_shnum:
            return info

        sections = cls._sections(data, endian, info.bits, e_shoff, e_shentsize, e_shnum)
        if not sections:
            return info

        cls._read_symbols(data, endian, info, sections)
        return info

    @staticmethod
    def _sections(
        data: bytes, endian: str, bits: int, shoff: int, shentsize: int, shnum: int
    ) -> List[Tuple[int, int, int, int, int]]:
        """Returns (sh_type, sh_offset, sh_size, sh_link, sh_entsize) per section."""
        sections = []
        # A corrupt shnum could ask for gigabytes of parsing; the real value is small.
        for index in range(min(shnum, 512)):
            base = shoff + index * shentsize
            if base + shentsize > len(data):
                break
            try:
                if bits == 64:
                    sh_type = struct.unpack_from(endian + "I", data, base + 4)[0]
                    sh_offset, sh_size = struct.unpack_from(
                        endian + "QQ", data, base + 24
                    )
                    sh_link = struct.unpack_from(endian + "I", data, base + 40)[0]
                    sh_entsize = struct.unpack_from(endian + "Q", data, base + 56)[0]
                else:
                    sh_type = struct.unpack_from(endian + "I", data, base + 4)[0]
                    sh_offset, sh_size = struct.unpack_from(
                        endian + "II", data, base + 16
                    )
                    sh_link = struct.unpack_from(endian + "I", data, base + 24)[0]
                    sh_entsize = struct.unpack_from(endian + "I", data, base + 36)[0]
            except struct.error:
                break
            sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
        return sections

    @classmethod
    def section_range(cls, data: bytes, name: str) -> Optional[Tuple[int, int]]:
        """``(file offset, size)`` of the named section, or ``None`` if the
        section table (at the end of the file) is not available."""
        if len(data) < 64 or not data.startswith(ELF_MAGIC) or data[4] not in (1, 2):
            return None
        bits = 64 if data[4] == 2 else 32
        endian = "<" if data[5] == 1 else ">"
        try:
            if bits == 64:
                e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
                e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    endian + "HHH", data, 58
                )
            else:
                e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
                e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    endian + "HHH", data, 46
                )
        except struct.error:
            return None
        if not e_shoff or e_shstrndx >= e_shnum:
            return None

        def header(index: int) -> Optional[Tuple[int, int, int]]:
            base = e_shoff + index * e_shentsize
            if base + e_shentsize > len(data):
                return None
            try:
                sh_name = struct.unpack_from(endian + "I", data, base)[0]
                if bits == 64:
                    sh_offset, sh_size = struct.unpack_from(
                        endian + "QQ", data, base + 24
                    )
                else:
                    sh_offset, sh_size = struct.unpack_from(
                        endian + "II", data, base + 16
                    )
            except struct.error:
                return None
            return sh_name, sh_offset, sh_size

        names = header(e_shstrndx)
        if names is None:
            return None
        _, names_offset, names_size = names
        for index in range(min(e_shnum, 512)):
            entry = header(index)
            if entry is None:
                break
            sh_name, sh_offset, sh_size = entry
            if cls._string_at(data, names_offset, names_size, sh_name) == name:
                return sh_offset, sh_size
        return None

    @staticmethod
    def _string_at(data: bytes, table_offset: int, table_size: int, index: int) -> str:
        start = table_offset + index
        if index >= table_size or start >= len(data):
            return ""
        end = data.find(b"\x00", start, min(len(data), table_offset + table_size))
        if end < 0:
            end = min(len(data), start + 256)
        return data[start:end].decode("utf-8", "replace")

    @classmethod
    def _read_symbols(cls, data: bytes, endian: str, info: ElfInfo, sections) -> None:
        """Collects the global FUNC symbols the object defines (exports).

        Only ``.dynsym`` governs symbol interposition -- ``.symtab`` (if present at
        all in a shipped ``.so``) lists build-time symbols the loader never consults --
        so the dynamic table is used when available and the static one is only a
        fallback for an object that has no ``.dynsym``.
        """
        dynsym = [s for s in sections if s[0] == SHT_DYNSYM]
        symtab = [s for s in sections if s[0] == SHT_SYMTAB]
        chosen = dynsym[0] if dynsym else (symtab[0] if symtab else None)
        if chosen is None:
            return

        _sh_type, sh_offset, sh_size, sh_link, sh_entsize = chosen
        if sh_link >= len(sections):
            return
        _, str_offset, str_size, _, _ = sections[sh_link]
        entry_size = sh_entsize or (24 if info.bits == 64 else 16)
        if entry_size <= 0:
            return

        exported: List[str] = []

        count = min(sh_size // entry_size, 65536)
        for index in range(count):
            base = sh_offset + index * entry_size
            if base + entry_size > len(data):
                break
            try:
                st_name = struct.unpack_from(endian + "I", data, base)[0]
                if info.bits == 64:
                    st_info = data[base + 4]
                    st_shndx = struct.unpack_from(endian + "H", data, base + 6)[0]
                else:
                    st_info = data[base + 12]
                    st_shndx = struct.unpack_from(endian + "H", data, base + 14)[0]
            except (struct.error, IndexError):
                break

            name = cls._string_at(data, str_offset, str_size, st_name)
            if not name:
                continue
            # Strip the GLIBC_2.x version suffix so names compare cleanly.
            name = name.split("@", 1)[0]

            if st_shndx == SHN_UNDEF:
                # An undefined entry is an import, not a definition.
                continue
            # Only global/weak FUNC definitions participate in symbol interposition;
            # local symbols never shadow libc.
            if (st_info & 0xF) == STT_FUNC and (st_info >> 4) != STB_LOCAL:
                exported.append(name)

        info.exported = sorted(set(exported))


# -- page cache access -----------------------------------------------------------


@dataclass
class RecoveredFile:
    """A file recovered from the page cache."""

    path: str
    inode_addr: int
    data: bytes
    modification_time: Optional[datetime.datetime] = None
    change_time: Optional[datetime.datetime] = None
    #: "standard" for /etc/ld.so.preload, "copy" for a renamed copy of it such as
    #: ld.so.preload.bak, "disguised" for a preload file found by content, and
    #: "linker-artifact" for a leftover patched-loader copy.
    kind: str = "standard"


def _nested_member_offset(
    symbol_space, template, name: str, _depth: int = 0
) -> Optional[Tuple[int, int]]:
    """``(offset, size)`` of member ``name`` in ``template``, looking through the
    anonymous structs and unions the object layer cannot address by name.

    The ISF names an anonymous member ``unnamed_field_N``; distribution kABI
    padding macros add ``rh_kabi_hidden_*``/``__UNIQUE_ID_*`` wrappers. Both are
    descended depth first; nested templates are references and are resolved
    through the symbol space.
    """
    try:
        members = template.vol.members
    except (AttributeError, exceptions.SymbolError):
        return None
    for member, (offset, sub) in members.items():
        if member == name:
            return offset, sub.size
        if _depth < 4 and member.startswith(
            ("unnamed_field", "__UNIQUE_ID", "rh_kabi")
        ):
            try:
                resolved = symbol_space.get_type(sub.vol.type_name)
            except exceptions.SymbolError:
                continue
            found = _nested_member_offset(symbol_space, resolved, name, _depth + 1)
            if found is not None:
                return offset + found[0], found[1]
    return None


class PageLayout:
    """Raw access to the ``struct page`` fields the page-cache readers need.

    ``mapping`` and ``index`` are resolved once, through anonymous members if the
    symbol table nests them there. Some distribution symbol tables (kABI-padded
    RHEL/CentOS kernels) lose the page-cache block of ``struct page`` entirely;
    then the offsets are derived from the layout the kernel has used since 4.18
    -- a five-word union after ``flags`` holding ``lru`` (two words), ``mapping``,
    ``index`` and ``private`` -- or, for a smaller union, the pre-4.18 layout with
    ``mapping`` and ``index`` directly after ``flags``. Every consumer checks a
    page's ``mapping`` against the inode's ``i_mapping`` before using it, so a
    wrong derivation yields no pages rather than wrong content.

    The physical address of a page is computed the way ``page.to_paddr()`` does,
    with the framework's own ``vmemmap`` start; that raises on architectures it
    does not cover, which the callers treat as "use the object layer".
    """

    def __init__(
        self, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> None:
        vmlinux = context.modules[vmlinux_module_name]
        layer = context.layers[vmlinux.layer_name]
        self._vmlinux = vmlinux
        self._layer = layer
        self._physical = context.layers[layer.config.get("memory_layer", layer.name)]
        self._canonicalize = getattr(layer, "canonicalize", None)
        ptr_template = vmlinux.get_type("pointer")
        self.ptr_size = ptr_template.size
        self.byteorder = ptr_template.vol.data_format.byteorder
        self.address_mask = layer.address_mask
        self.page_size = layer.page_size
        page_type = vmlinux.get_type("page")
        self.struct_size = page_type.size
        symbol_space = context.symbol_space
        mapping = _nested_member_offset(symbol_space, page_type, "mapping")
        index = _nested_member_offset(symbol_space, page_type, "index")
        #: Candidate ``(mapping offset, index offset)`` pairs still to be tried
        #: against a real page when the symbol table did not settle the layout.
        self._candidates: List[Tuple[int, int]] = []
        if mapping is None or index is None:
            word = self.ptr_size
            union_size = None
            for member, (offset, sub) in page_type.vol.members.items():
                if offset == word and member.startswith("unnamed_field"):
                    try:
                        union_size = symbol_space.get_type(sub.vol.type_name).size
                    except exceptions.SymbolError:
                        pass
            modern, legacy = (3 * word, 4 * word), (word, 2 * word)
            self._candidates = (
                [modern, legacy] if union_size == 5 * word else [legacy, modern]
            )
            mapping, index = (self._candidates[0][0], word), (
                self._candidates[0][1],
                word,
            )
            vollog.debug(
                "struct page has no mapping/index in the symbol table; trying "
                "mapping at +%#x / index at +%#x first, confirmed against a real page",
                mapping[0],
                index[0],
            )
        self.mapping_off = mapping[0]
        self.index_off, self.index_len = index
        self._vmemmap: Optional[int] = None

    def belongs_to(self, page_addr: int, mapping_addr: int) -> bool:
        """Whether the page's ``mapping`` is ``mapping_addr``.

        While the field offsets are still unconfirmed, each candidate layout is
        tried in turn and the first that makes this page point back at the
        expected address space is locked in for the rest of the run."""
        if self.mapping_of(page_addr) == mapping_addr:
            self._candidates = []
            return True
        for mapping_off, index_off in self._candidates[1:]:
            try:
                found = (
                    self._read_int(page_addr + mapping_off, self.ptr_size)
                    & self.address_mask
                ) == mapping_addr
            except exceptions.InvalidAddressException:
                continue
            if found:
                self.mapping_off, self.index_off = mapping_off, index_off
                self._candidates = []
                vollog.debug(
                    "struct page layout confirmed: mapping at +%#x, index at +%#x",
                    mapping_off,
                    index_off,
                )
                return True
        return False

    def _read_int(self, address: int, length: int) -> int:
        return int.from_bytes(self._layer.read(address, length), self.byteorder)

    def mapping_of(self, page_addr: int) -> int:
        """The ``address_space`` a cached page belongs to."""
        return (
            self._read_int(page_addr + self.mapping_off, self.ptr_size)
            & self.address_mask
        )

    def index_of(self, page_addr: int) -> int:
        """The page's index within its file."""
        return self._read_int(page_addr + self.index_off, self.index_len)

    def prepare(self, page_addr: int) -> None:
        """Resolves the ``vmemmap`` start once; raises if the architecture is
        not covered by the framework's page-to-physical arithmetic."""
        if self._vmemmap is None:
            page = self._vmlinux.object("page", offset=page_addr, absolute=True)
            self._vmemmap = page._intel_vmemmap_start

    def content(self, page_addr: int, length: Optional[int] = None) -> Optional[bytes]:
        """The page's bytes from the physical layer, or ``None`` if unavailable."""
        self.prepare(page_addr)
        addr = self._canonicalize(page_addr) if self._canonicalize else page_addr
        pfn = (addr - self._vmemmap) // self.struct_size
        length = length or self.page_size
        paddr = pfn * self.page_size
        if pfn < 0 or not self._physical.is_valid(paddr, length):
            return None
        return self._physical.read(paddr, length)


@functools.lru_cache(maxsize=4)
def _page_layout(
    context: interfaces.context.ContextInterface, vmlinux_module_name: str
) -> PageLayout:
    """One ``PageLayout`` per kernel module, so a derived layout is confirmed
    once and then shared by every reader."""
    return PageLayout(context, vmlinux_module_name)


class _RadixTreeCompat(linux_symbols.RadixTree):
    """A ``RadixTree`` whose node height survives a kABI-wrapped node layout.

    The framework reads a node's height from ``node.shift`` / ``node.path`` /
    ``node.height`` by member name. Kernels built with kABI padding (RHEL and
    CentOS 7, 3.10.0-*) wrap that word in anonymous unions the object layer
    cannot name, and the symbol table may retain only the deprecated member
    while the kernel uses the newer one, so every multi-page file fails with
    "Cannot find radix-tree node height".

    In every pre-4.20 layout that word is the first member of the node, so it
    is read raw and decoded according to ``layout``. Which layout is live cannot
    be told from the symbol table; the caller tries each and keeps the one whose
    leaf pages belong to the inode.
    """

    def __init__(self, *args, layout: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._layout = layout

    def get_node_height(self, nodep) -> int:
        try:
            return super().get_node_height(nodep)
        except exceptions.VolatilityException as excp:
            if "node height" not in str(excp):
                raise
        layer = self.vmlinux.context.layers[self.vmlinux.layer_name]
        byteorder = self.vmlinux.get_type("pointer").vol.data_format.byteorder
        if self._layout == "shift":
            # Kernels >= 4.7: an unsigned char shift, height = shift / chunk + 1.
            height = layer.read(nodep, 1)[0] // self.CHUNK_SHIFT + 1
        else:
            # 3.15 <= kernels < 4.7: path = offset << n | height; older kernels
            # store the plain height, which the mask leaves untouched.
            word = int.from_bytes(layer.read(nodep, 4), byteorder)
            height = word & self.RADIX_TREE_HEIGHT_MASK
        if self._max_height_array and not (0 <= height < self._max_height_array.count):
            raise exceptions.LinuxPageCacheException(
                f"Radix tree node {nodep:#x} height {height} out of range"
            )
        return height


def _read_pages_compat(
    context: interfaces.context.ContextInterface,
    module_name: str,
    inode: interfaces.objects.ObjectInterface,
    size: int,
) -> bytes:
    """Reads an inode's cached pages without ``page`` objects.

    The page tree is walked with the framework's XArray walker, or -- on a
    radix-tree kernel -- with the compatibility walker, trying every node
    layout in turn (newest first): the first one whose leaves are pages of this
    inode is the live one, since a wrong height makes the walk yield internal
    nodes whose ``mapping`` does not point back. Page fields and content are
    read through ``PageLayout``, so a symbol table without ``page.mapping`` is
    no obstacle. Returns the content (missing pages zero filled), or ``b""``.
    """
    pages = _page_layout(context, module_name)
    mapping_ptr = inode.i_mapping
    mapping_addr = int(mapping_ptr)
    root = mapping_ptr.dereference().i_pages
    storage = linux_symbols.IDStorage.choose_id_storage(context, module_name)
    if isinstance(storage, linux_symbols.RadixTree):
        trees = [
            _RadixTreeCompat(context, module_name, layout=layout)
            for layout in ("shift", "path")
        ]
    else:
        trees = [storage]
    for tree in trees:
        buffer = BytesIO()
        count = 0
        try:
            for page_addr in tree.get_entries(root):
                try:
                    if not pages.belongs_to(page_addr, mapping_addr):
                        continue
                    offset = pages.index_of(page_addr) * pages.page_size
                    if offset >= size:
                        continue
                    content = pages.content(page_addr)
                except exceptions.InvalidAddressException:
                    continue
                if content:
                    count += 1
                    buffer.seek(offset)
                    buffer.write(content[: size - offset])
        except (exceptions.VolatilityException, AttributeError) as excp:
            vollog.debug("Page walk with %s rejected: %s", type(tree).__name__, excp)
        if count:
            vollog.debug("Read %d page(s) with %s", count, type(tree).__name__)
            return buffer.getvalue()
    return b""


def read_inode(
    context: interfaces.context.ContextInterface,
    vmlinux_module_name: str,
    inode: interfaces.objects.ObjectInterface,
    path: str,
) -> RecoveredFile:
    """Reads an inode's cached content, zero filling any pages that are missing."""
    layer_name = context.modules[vmlinux_module_name].layer_name
    buffer = BytesIO()
    try:
        pagecache.InodePages.write_inode_content_to_stream(
            context, layer_name, inode, buffer
        )
    except (exceptions.VolatilityException, AttributeError) as excp:
        vollog.debug("Unable to read pages of %s: %s", path, excp)
        # On kABI-padded kernels (RHEL/CentOS) the framework cannot resolve the
        # radix-tree node height (3.10) or ``page.mapping`` (4.18); retry with
        # the compatibility reader, which resolves both raw. Only a better
        # result replaces what was read so far.
        try:
            data = _read_pages_compat(
                context, vmlinux_module_name, inode, int(inode.i_size)
            )
        except (exceptions.VolatilityException, AttributeError) as excp:
            vollog.debug("Compatibility page read of %s failed: %s", path, excp)
            data = b""
        if len(data) > len(buffer.getvalue()):
            vollog.debug(
                "Recovered %s (%d bytes) with the compatibility page-cache reader",
                path,
                len(data),
            )
            buffer = BytesIO(data)

    def safe(fn):
        try:
            return fn()
        except (
            AttributeError,
            exceptions.InvalidAddressException,
            ValueError,
            TypeError,
        ):
            return None

    return RecoveredFile(
        path=path,
        inode_addr=inode.vol.offset,
        data=buffer.getvalue(),
        modification_time=safe(inode.get_modification_time),
        change_time=safe(inode.get_change_time),
    )


@dataclass
class LoaderCheck:
    """The integrity verdict on one glibc dynamic linker found in the page cache."""

    recovered: RecoveredFile
    #: "intact", "patched", or "inconclusive" (the preload string is absent but so
    #: are pages of the loader's .rodata, so it may simply not be cached).
    state: str
    #: The path the patched loader reads instead of /etc/ld.so.preload, if recovered.
    reads: Optional[str] = None
    #: Whether ``reads`` is backed by evidence beyond the loader's own strings: a
    #: byte diff against a leftover copy, or a matching file in the page cache.
    verified: bool = False
    #: Unverified candidate strings when ``reads`` could not be settled.
    candidates: List[str] = field(default_factory=list)


# -- the plugin ------------------------------------------------------------------


@dataclass
class PreloadEntry:
    """One library named by an ld.so.preload file."""

    preload_path: str
    library: str
    preload_mtime: Optional[datetime.datetime] = None
    preload_ctime: Optional[datetime.datetime] = None
    recovered: Optional[RecoveredFile] = None
    elf: Optional[ElfInfo] = None
    mapped_pids: List[int] = field(default_factory=list)
    #: How this preload file was found / why it is noteworthy.
    detection: str = ""


class LdPreload(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers ld.so.preload from the page cache and reports the libc functions its libraries override."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 3, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="pagecache", component=pagecache.InodePages, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="path",
                description="Additional glob patterns to treat as preload files",
                element_type=str,
                optional=True,
            ),
            requirements.ListRequirement(
                name="scan-dir",
                description="Restrict the content scan for a disguised preload file "
                "to these directories (default: the whole page cache). The scan "
                "finds a small file that names only shared objects, defeating "
                "dynamic-linker patching that redirects the loader to it.",
                element_type=str,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="no-scan",
                description="Disable the content scan for disguised preload files, "
                "the dynamic-linker integrity check and the tamper-artifact check; "
                "only /etc/ld.so.preload is used",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="all-symbols",
                description="List every exported function, not just those that shadow "
                "a known libc function",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="skip-maps",
                description="Do not walk process mappings to find which processes have "
                "the library loaded (faster)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract the preload file and every resolved library",
                default=False,
                optional=True,
            ),
        ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._entries: Optional[List[PreloadEntry]] = None
        self._preload_files: List[RecoveredFile] = []
        self._linker_artifacts: List[RecoveredFile] = []
        self._loader_checks: List[LoaderCheck] = []
        #: disguised preload path -> path of the patched loader that names it
        self._confirmed_by: Dict[str, str] = {}
        self._dumped = False
        self._platform = "x86_64"
        self._libdir = "lib64"

    # -- collection ------------------------------------------------------------

    @staticmethod
    def _safe_iter(iterator) -> Iterator:
        """Drains an iterator, ending it quietly if the underlying walk dies."""
        while True:
            try:
                yield next(iterator)
            except StopIteration:
                return
            except (exceptions.InvalidAddressException, AttributeError):
                return

    @classmethod
    def get_superblocks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterator[Tuple[interfaces.objects.ObjectInterface, str]]:
        """Yields each mounted (superblock, mountpoint path) once.

        Replaces ``mountinfo.MountInfo.get_superblocks()``, which walks the mount
        list of every task -- rescanning the shared mount namespace once per
        process and reconstructing every mount's path -- before deduplicating by
        superblock. One task per mount *namespace* carries the same information,
        and the mountpoint path is only built for a superblock not seen before, so
        the expensive path reconstruction runs once per filesystem instead of once
        per mount per process.
        """
        seen_namespaces: Set[int] = set()
        seen_superblocks: Set[int] = set()
        for task in pslist.PsList.list_tasks(context, vmlinux_module_name):
            try:
                nsproxy = task.nsproxy
                if not (nsproxy and nsproxy.is_readable()):
                    continue
                mnt_ns = nsproxy.mnt_ns
                if not (mnt_ns and mnt_ns.is_readable()):
                    continue
                ns_addr = int(mnt_ns)
                if ns_addr in seen_namespaces:
                    continue
                seen_namespaces.add(ns_addr)
                if not (task.fs and task.fs.is_readable()):
                    # Path reconstruction below needs the task's fs_struct.
                    continue
                mounts = mnt_ns.get_mount_points()
            except (exceptions.InvalidAddressException, AttributeError):
                continue
            for mount in cls._safe_iter(iter(mounts)):
                try:
                    sb_ptr = mount.get_mnt_sb()
                    if not (sb_ptr and sb_ptr.is_readable()):
                        continue
                    sb_addr = int(sb_ptr)
                    if sb_addr in seen_superblocks:
                        continue
                    seen_superblocks.add(sb_addr)
                    mountpoint = linux_symbols.LinuxUtilities.get_path_mnt(task, mount)
                    if not mountpoint:
                        continue
                    yield sb_ptr.dereference(), mountpoint
                except (exceptions.InvalidAddressException, AttributeError):
                    continue

    @classmethod
    def get_cached_regular_files(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterator[Tuple[str, int]]:
        """Yields ``(path, inode address)`` for every regular file in the page cache.

        This replaces ``pagecache.Files.get_inodes()``, which spends most of the
        plugin's runtime validating inodes the caller then discards: per dentry it
        dereferences the inode and runs ``is_valid()`` once inside its dentry walk
        and then a second time (plus an ``i_mapping`` check and an ``InodeInternal``
        construction) before yielding -- roughly ten framework attribute reads per
        dentry, each of which is an image read through the object layer. Almost every
        yielded inode fails this plugin's path filter, so all of that work is wasted.

        The walk itself uses no framework objects either: each dentry is read once
        as raw bytes, and the sibling link, the inode pointer and the name are taken
        from that buffer at member offsets resolved once from the symbol table (the
        inode's ``i_mode`` is one further short read) -- the same technique as the
        VMA correlation below, and for the same reason. The object-based walk
        (``get_subdirs()``/``name_as_str()``) constructs hundreds of thousands of
        objects on a large dentry cache, which dominates the plugin's runtime.
        Consumers get an inode *address* and
        construct an object only for the handful of files they actually select;
        content-level validation (``is_valid()``) also happens only there.

        All sibling layouts are supported (see the child-list resolution below).
        The walk is iterative, every per-dentry read is guarded, the global seen
        set breaks cycles and a per-directory cap bounds a smeared sibling list, so
        one bad dentry costs at worst its subtree, never the whole walk.
        """
        vmlinux = context.modules[vmlinux_module_name]
        layer = context.layers[vmlinux.layer_name]

        ptr_template = vmlinux.get_type("pointer")
        ptr_size = ptr_template.size
        try:
            byteorder = ptr_template.vol.data_format.byteorder
        except AttributeError:
            byteorder = "little"

        # Raw pointer reads must be masked like the object layer masks them
        # (dropping the canonical sign-extension bits of a kernel address), or a
        # comparison against any object-derived address quietly never matches.
        address_mask = layer.address_mask

        def read_ptr(address: int) -> int:
            return (
                int.from_bytes(layer.read(address, ptr_size), byteorder) & address_mask
            )

        def member_offset(type_name: str, member: str) -> int:
            return vmlinux.get_type(type_name).relative_child_offset(member)

        missing_member = (
            AttributeError,
            KeyError,
            IndexError,
            ValueError,
            exceptions.SymbolError,
        )
        dentry_size = vmlinux.get_type("dentry").size
        d_inode_off = member_offset("dentry", "d_inode")
        d_parent_off = member_offset("dentry", "d_parent")
        d_name_off = member_offset("dentry", "d_name")
        d_name_name_off = d_name_off + member_offset("qstr", "name")
        i_mode_off = member_offset("inode", "i_mode")
        try:
            # Short names are stored inline in the dentry itself (d_iname), so
            # they come for free with the struct read below.
            d_iname_off = member_offset("dentry", "d_iname")
        except missing_member:
            d_iname_off = None
        # The child-list layout has three historical forms; the pair is resolved
        # atomically so a half-present layout never leaks offsets from two of them.
        #  * >= 6.8:  d_children (hlist_head) + d_sib (hlist_node), NULL-terminated.
        #  * mid:     d_subdirs (list_head) + d_child (list_head), a ring.
        #  * older:   d_subdirs (list_head) + d_u.d_child (list_head in a union).
        #             d_child is the first union member, so its offset is d_u's.
        children_off = sibling_off = None
        for child_member, sib_member in (
            ("d_children", "d_sib"),
            ("d_subdirs", "d_child"),
            ("d_subdirs", "d_u"),
        ):
            try:
                children_off = member_offset("dentry", child_member)
                sibling_off = member_offset("dentry", sib_member)
            except missing_member:
                children_off = sibling_off = None
                continue
            break
        if children_off is None or sibling_off is None:
            vollog.error(
                "dentry child-list layout not recognised (members: %s); "
                "cannot walk the page cache",
                ", ".join(sorted(vmlinux.get_type("dentry").vol.members)),
            )
            return
        # In qstr the name length shares a u64 with the hash (u32 hash, u32 len),
        # so on little endian the length is the upper half.
        d_name_len_off = d_name_off + (4 if byteorder == "little" else 0)

        def field_ptr(buf: bytes, offset: int) -> int:
            return (
                int.from_bytes(buf[offset : offset + ptr_size], byteorder)
                & address_mask
            )

        def read_name(dentry_addr: int, buf: bytes) -> Optional[str]:
            """The dentry's basename, sized by the qstr length field."""
            name_ptr = field_ptr(buf, d_name_name_off)
            if not name_ptr:
                return None
            length = int.from_bytes(buf[d_name_len_off : d_name_len_off + 4], byteorder)
            if 0 < length < 256:
                if (
                    d_iname_off is not None
                    and name_ptr == dentry_addr + d_iname_off
                    and d_iname_off + length <= dentry_size
                ):
                    return buf[d_iname_off : d_iname_off + length].decode(
                        "utf-8", "replace"
                    )
                return layer.read(name_ptr, length).decode("utf-8", "replace")
            # An implausible length means the union layout guess was wrong or the
            # dentry is smeared; fall back to a capped NUL-terminated read.
            data = layer.read(name_ptr, 64)
            end = data.find(b"\x00")
            if end == 0:
                return None
            return data[: end if end > 0 else 64].decode("utf-8", "replace")

        def iter_children(parent_addr: int) -> Iterator[Tuple[int, Optional[bytes]]]:
            """Yields ``(child dentry address, raw dentry bytes)`` per child.

            The whole struct is read once: the sibling link, the inode pointer
            and the name all come out of that one buffer, replacing four or
            five translated reads per dentry with one. The bytes are ``None``
            for a dentry that could not be read whole; the list still continues
            through its sibling link.
            """
            head = parent_addr + children_off
            try:
                node = read_ptr(head)
            except exceptions.InvalidAddressException:
                return
            count = 0
            # NULL ends an hlist, the head ends a list_head ring; the cap bounds
            # a smeared list that walks off into garbage (the global seen set
            # already breaks genuine cycles at the caller).
            while node and node != head and count < 262144:
                child = node - sibling_off
                count += 1
                try:
                    buf = layer.read(child, dentry_size)
                except exceptions.InvalidAddressException:
                    yield child, None
                    try:
                        node = read_ptr(node)
                    except exceptions.InvalidAddressException:
                        return
                    continue
                yield child, buf
                node = field_ptr(buf, sibling_off)

        seen_dentries: Set[int] = set()

        for superblock, mountpoint in cls.get_superblocks(context, vmlinux_module_name):
            parent_dir = "" if mountpoint == "/" else mountpoint
            try:
                fs_type = superblock.get_type()
                if fs_type and fs_type.split(".", 1)[0] in PSEUDO_FILESYSTEMS:
                    continue
                root_addr = int(superblock.s_root)
                if not root_addr:
                    continue
                # A filesystem root is its own parent; anything else is smear.
                if read_ptr(root_addr + d_parent_off) != root_addr:
                    continue
            except (exceptions.InvalidAddressException, AttributeError):
                continue

            if root_addr in seen_dentries:
                continue
            seen_dentries.add(root_addr)

            # Iterative DFS; (dentry address, path prefix) pairs to be expanded.
            stack = [(root_addr, parent_dir)]
            while stack:
                parent_addr, prefix = stack.pop()
                for child_addr, buf in iter_children(parent_addr):
                    if child_addr in seen_dentries or buf is None:
                        continue
                    seen_dentries.add(child_addr)
                    # The inode is routed on before the name is read: negative
                    # dentries (no inode) and non-dir/non-reg inodes are skipped
                    # without paying for their name.
                    inode_addr = field_ptr(buf, d_inode_off)
                    if not inode_addr:
                        continue
                    try:
                        mode = int.from_bytes(
                            layer.read(inode_addr + i_mode_off, 2), byteorder
                        )
                        is_dir = stat.S_ISDIR(mode)
                        if not (is_dir or stat.S_ISREG(mode)):
                            continue
                        basename = read_name(child_addr, buf)
                    except exceptions.InvalidAddressException:
                        continue
                    if not basename:
                        continue
                    path = prefix + "/" + basename
                    if is_dir:
                        stack.append((child_addr, path))
                    else:
                        yield path, inode_addr

    def _collect(self) -> List[PreloadEntry]:
        """Recovers preload files, resolves and analyses libraries. Runs once."""
        if self._entries is not None:
            return self._entries

        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        # ld.so dynamic-string tokens are expanded with the common per-architecture
        # values; the token-regex resolver below does not depend on getting the
        # exact value right, so an unusual $PLATFORM still resolves.
        try:
            if vmlinux.get_type("pointer").size == 4:
                self._platform, self._libdir = "i686", "lib"
        except (exceptions.SymbolError, AttributeError, IndexError):
            pass

        globs = (
            tuple(PRELOAD_GLOBS)
            + tuple(PRELOAD_COPY_GLOBS)
            + tuple(self.config.get("path") or [])
        )
        copy_match = re.compile(
            "|".join(fnmatch.translate(pattern) for pattern in PRELOAD_COPY_GLOBS)
        ).match
        # One regex instead of one fnmatch call per pattern per inode: this test runs
        # for every inode in the page cache, so its constant factor matters.
        glob_match = re.compile(
            "|".join(fnmatch.translate(pattern) for pattern in globs)
        ).match

        # The disguised preload file can be placed anywhere, so by default the whole
        # page cache is scanned by content; --scan-dir restricts that to given
        # directory prefixes (a bare "/" means everywhere, i.e. the default).
        scan = not self.config.get("no-scan", False)
        restrict_dirs = [
            "/" + d.strip("/") for d in (self.config.get("scan-dir") or ())
        ]
        scan_all = not restrict_dirs or any(d == "/" for d in restrict_dirs)

        def in_scan_scope(path: str) -> bool:
            return scan_all or any(path.startswith(d + "/") for d in restrict_dirs)

        # One page cache walk collects both the preload files and every candidate
        # library, so the (expensive) dentry traversal happens once. The path checks
        # come first: the path string already exists, while any inode field test costs
        # an image read, and almost every inode fails both checks. Content-level
        # validation (``is_valid()``) is deferred to the few files actually selected.
        preload_files: List[RecoveredFile] = []
        seen_preload_inodes: Set[int] = set()
        libraries: Dict[str, int] = {}
        scan_candidates: List[Tuple[str, int]] = []  # (path, inode) files to inspect
        linker_artifacts: List[Tuple[str, int]] = []
        loaders: Dict[str, int] = {}  # glibc dynamic linkers, path -> inode
        cached_paths: Set[str] = set()  # every regular file, for cross-checks

        for path, inode_addr in self.get_cached_regular_files(
            self.context, vmlinux_module_name
        ):
            if scan:
                cached_paths.add(path)
            if glob_match(path):
                if inode_addr in seen_preload_inodes:
                    continue
                seen_preload_inodes.add(inode_addr)
                inode = vmlinux.object("inode", offset=inode_addr, absolute=True)
                if self._inode_usable(inode):
                    recovered = read_inode(
                        self.context, vmlinux_module_name, inode, path
                    )
                    if copy_match(path):
                        recovered.kind = "copy"
                    preload_files.append(recovered)
            elif scan and LINKER_ARTIFACT_RE.match(path.rsplit("/", 1)[-1]):
                # Checked before the .so test: a linker artifact such as
                # ld-2.17.so.tmp contains ".so." and would otherwise be filed away
                # as an ordinary library and never flagged.
                linker_artifacts.append((path, inode_addr))
            elif path.endswith(".so") or ".so." in path:
                # Keep the first inode seen for a path; duplicates across mount
                # namespaces are resolved by exact path below. Whether it is intact
                # is checked only if a preload entry resolves to it.
                libraries.setdefault(path, inode_addr)
                if scan and GLIBC_LOADER_RE.match(path.rsplit("/", 1)[-1]):
                    loaders.setdefault(path, inode_addr)
            elif (
                scan
                and in_scan_scope(path)
                and (not path.rsplit("/", 1)[-1].startswith(SCAN_SKIP_PREFIXES))
            ):
                scan_candidates.append((path, inode_addr))

        if scan:
            self._scan_disguised_preloads(
                vmlinux_module_name,
                scan_candidates,
                preload_files,
                seen_preload_inodes,
            )
            self._collect_linker_artifacts(vmlinux_module_name, linker_artifacts)
            self._loader_checks = self._check_loaders(
                vmlinux_module_name, loaders, cached_paths
            )
            # A patched loader that names a content-scanned file confirms it.
            for check in self._loader_checks:
                if check.state != "patched" or not check.reads:
                    continue
                for preload in preload_files:
                    if preload.kind == "disguised" and self._same_file(
                        check.reads, preload.path
                    ):
                        self._confirmed_by[preload.path] = check.recovered.path
                        check.verified = True

        self._preload_files = preload_files
        if not preload_files:
            for check in self._loader_checks:
                if check.state == "patched":
                    vollog.warning(
                        "The dynamic linker %s is patched to read %s instead of "
                        "/etc/ld.so.preload; that file is not present in the page "
                        "cache",
                        check.recovered.path,
                        check.reads or "an unrecovered path",
                    )
            if self._linker_artifacts:
                vollog.warning(
                    "No preload file found, but a dynamic-linker tamper artifact is "
                    "present (%s) -- the loader may have been patched to read a "
                    "preload file whose pages are not cached.",
                    ", ".join(a.path for a in self._linker_artifacts),
                )
            else:
                vollog.info(
                    "No ld.so.preload file present in the page cache. This is the "
                    "expected state for a clean system."
                )
            self._entries = []
            return self._entries

        entries: List[PreloadEntry] = []
        # Several preload files (or duplicate lines) can name the same library; the
        # inode is read and parsed once and the result shared. None marks an inode
        # that failed the smear check, so it is not re-checked per entry.
        analysed: Dict[int, Optional[Tuple[RecoveredFile, ElfInfo]]] = {}
        for preload in preload_files:
            names = self._parse_preload(preload.data)
            if not names:
                vollog.warning(
                    "%s is present but lists no library (%d byte(s) recovered)",
                    preload.path,
                    len(preload.data),
                )
            # Standard /etc/ld.so.preload needs no note; a file found by content
            # under another name is flagged.
            if preload.path in self._confirmed_by:
                detection = (
                    "disguised preload file: the dynamic linker "
                    f"{self._confirmed_by[preload.path]} is patched to read it "
                    "instead of /etc/ld.so.preload"
                )
            elif preload.kind == "disguised":
                detection = (
                    "disguised preload file (dynamic linker patched to read this "
                    "name instead of /etc/ld.so.preload)"
                )
            elif preload.kind == "copy":
                detection = (
                    "renamed copy of /etc/ld.so.preload; not read by the loader, "
                    "but records an earlier state"
                )
            else:
                detection = ""
            for name in names:
                entry = PreloadEntry(
                    preload_path=preload.path,
                    library=name,
                    preload_mtime=preload.modification_time,
                    preload_ctime=preload.change_time,
                    detection=detection,
                )
                resolved = self._lookup(name, libraries)
                if resolved is not None:
                    lib_path, inode_addr = resolved
                    if inode_addr not in analysed:
                        inode = vmlinux.object(
                            "inode", offset=inode_addr, absolute=True
                        )
                        if self._inode_usable(inode):
                            recovered = read_inode(
                                self.context, vmlinux_module_name, inode, lib_path
                            )
                            analysed[inode_addr] = (
                                recovered,
                                ElfReader.parse(recovered.data),
                            )
                        else:
                            analysed[inode_addr] = None
                    if analysed[inode_addr] is not None:
                        entry.recovered, entry.elf = analysed[inode_addr]
                entries.append(entry)

        if entries and not self.config.get("skip-maps", False):
            discovered_inodes = self._correlate_processes(entries)
            # Recovery fallback: a preloaded library that no cached dentry path
            # leads to anymore (parent dentries evicted, or the file unlinked
            # after loading) is still reachable through the inode a mapping
            # process's ``vm_file`` points at -- and its pages are usually
            # resident, since the loader read them.
            for entry in entries:
                if entry.recovered is not None:
                    continue
                inode_addr = discovered_inodes.get(entry.library)
                if not inode_addr or inode_addr in analysed:
                    continue
                inode = vmlinux.object("inode", offset=inode_addr, absolute=True)
                if not self._inode_usable(inode):
                    analysed[inode_addr] = None
                    continue
                recovered = read_inode(
                    self.context, vmlinux_module_name, inode, entry.library
                )
                analysed[inode_addr] = (recovered, ElfReader.parse(recovered.data))
                vollog.info(
                    "%s is mapped by running processes but was not reachable "
                    "through any cached dentry path; recovered it via the "
                    "vm_file inode at %#x instead",
                    entry.library,
                    inode_addr,
                )
                for candidate in entries:
                    if (
                        candidate.library == entry.library
                        and candidate.recovered is None
                    ):
                        candidate.recovered, candidate.elf = analysed[inode_addr]

        # Confirmation gate for content-scanned (disguised) files. A real preload
        # file names a shared object that the loader has actually loaded, so at
        # least one of its libraries resolves to a cached object or is mapped by a
        # process. An unrelated file that merely happens to consist of ``.so`` paths
        # (a .gitignore listing a build artifact, say) names nothing real, and is
        # dropped -- this is what lets the scan cover the whole page cache safely.
        disguised = {p.path for p in preload_files if p.kind == "disguised"}
        if disguised:
            confirmed = {
                entry.preload_path
                for entry in entries
                if entry.preload_path in disguised
                and (
                    entry.recovered is not None
                    or entry.mapped_pids
                    or entry.preload_path in self._confirmed_by
                )
            }
            unconfirmed = disguised - confirmed
            if unconfirmed:
                entries = [e for e in entries if e.preload_path not in unconfirmed]
                preload_files = [p for p in preload_files if p.path not in unconfirmed]
                self._preload_files = preload_files
            for path in confirmed:
                vollog.warning(
                    "%s names only shared objects that are present on the system: a "
                    "preload file under a non-standard name (the dynamic linker was "
                    "patched to read it)",
                    path,
                )

        self._entries = entries
        return entries

    @staticmethod
    def _parse_preload(data: bytes) -> List[str]:
        """Splits an ld.so.preload file into library paths.

        The loader treats the file as a whitespace separated list, so newlines and
        spaces are equivalent. Comments are not part of the format, but a '#' line is
        skipped anyway because administrators write them and the loader would only
        fail to find the resulting path. NUL bytes are treated as separators too: a
        page cache hole is recovered as zeros, and gluing the text on either side of
        it into one token would lose both paths.
        """
        names: List[str] = []
        text = data.decode("utf-8", "replace").replace("\x00", " ")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.extend(token for token in line.split() if token)
        return names

    @staticmethod
    def _inode_usable(inode: interfaces.objects.ObjectInterface) -> bool:
        """Smear check for an inode about to be read, guarded against bad reads."""
        try:
            return bool(inode.is_valid())
        except (exceptions.InvalidAddressException, AttributeError):
            return False

    @staticmethod
    def _looks_like_preload(data: bytes) -> bool:
        """Whether the file content is an ld.so.preload list and nothing else.

        A preload file is exclusively a whitespace/newline separated list of
        absolute paths to shared objects. Requiring *every* non-comment token to
        be an absolute ``.so`` path is what separates a disguised preload file
        from ordinary /etc config that merely mentions a library: prelink,
        sestatus, GSS-mech and the like always carry non-path tokens (section
        headers, flags, OIDs) and so are rejected, while bdvl's single-line
        ``/path/lib.so.$PLATFORM`` passes.
        """
        tokens = LdPreload._parse_preload(data)
        if not tokens:
            return False
        return all(
            token.startswith("/") and SO_TOKEN_RE.search(token) for token in tokens
        )

    def _scan_disguised_preloads(
        self,
        vmlinux_module_name: str,
        candidates: List[Tuple[str, int]],
        preload_files: List[RecoveredFile],
        seen_inodes: Set[int],
    ) -> None:
        """Promotes any scanned file that names only shared objects to a preload
        file. A patched linker can point at a file of any name in any directory,
        so the file has no telltale name -- only telltale content."""
        vmlinux = self.context.modules[vmlinux_module_name]
        layer = self.context.layers[vmlinux.layer_name]
        peek = self._first_page_peeker(vmlinux, layer)
        try:
            i_size_off = vmlinux.get_type("inode").relative_child_offset("i_size")
            byteorder = vmlinux.get_type("pointer").vol.data_format.byteorder
        except (exceptions.SymbolError, AttributeError, IndexError):
            i_size_off, byteorder = None, "little"
        peeked = hits = 0
        for path, inode_addr in candidates:
            if inode_addr in seen_inodes:
                continue
            if peek is not None:
                # The candidate's size and first cached page are read with raw
                # layer reads and tested for preload content before any object
                # is constructed; only a hit pays for the validated read below.
                try:
                    data = peek(inode_addr)
                except exceptions.InvalidAddressException:
                    continue
                if data is None:
                    continue
                if data is not UNDECIDED:
                    peeked += 1
                    if not self._looks_like_preload(data):
                        continue
                    hits += 1
            elif i_size_off is not None:
                # Cheap size gate by a raw i_size read, so oversized files are
                # dropped without constructing an inode object.
                try:
                    size = int.from_bytes(
                        layer.read(inode_addr + i_size_off, 8), byteorder
                    )
                except exceptions.InvalidAddressException:
                    continue
                if not 0 < size <= PRELOAD_SCAN_MAX_SIZE:
                    continue
            inode = vmlinux.object("inode", offset=inode_addr, absolute=True)
            if not self._inode_usable(inode):
                continue
            recovered = read_inode(self.context, vmlinux_module_name, inode, path)
            if not self._looks_like_preload(recovered.data):
                continue
            seen_inodes.add(inode_addr)
            recovered.kind = "disguised"
            preload_files.append(recovered)
        vollog.debug(
            "Content scan: %d candidate(s), %d small cached file(s) inspected, "
            "%d with preload content",
            len(candidates),
            peeked,
            hits,
        )

    def _first_page_peeker(
        self, vmlinux, layer
    ) -> Optional[Callable[[int], Union[bytes, object, None]]]:
        """Builds ``peek(inode address)`` returning a small file's first cached page.

        The content scan has to look at every small regular file in the page
        cache, so it must not construct an inode, address_space, tree and page
        object per candidate. The returned function follows
        ``inode.i_mapping -> address_space.{nrpages, page_tree/i_pages} -> page``
        with raw reads and reads the first page from the physical layer through
        ``PageLayout``. ``peek`` returns the bytes, ``None`` for a file that is
        empty, larger than a preload file can be or not cached, and ``UNDECIDED``
        for one it cannot settle (a tree head that is not a direct page pointer,
        or an architecture without the ``vmemmap`` arithmetic). This method
        returns ``None`` itself when the kernel's layout cannot be resolved; in
        both cases the caller takes the object-based path.
        """
        try:
            pages = _page_layout(self.context, self.config["kernel"])
            ptr_size, byteorder, address_mask = (
                pages.ptr_size,
                pages.byteorder,
                pages.address_mask,
            )
            inode_type = vmlinux.get_type("inode")
            i_size_off = inode_type.relative_child_offset("i_size")
            i_size_len = inode_type.vol.members["i_size"][1].size
            i_mapping_off = inode_type.relative_child_offset("i_mapping")
            mapping_type = vmlinux.get_type("address_space")
            nrpages_off = mapping_type.relative_child_offset("nrpages")
            nrpages_len = mapping_type.vol.members["nrpages"][1].size
            tree_member = (
                "i_pages" if mapping_type.has_member("i_pages") else "page_tree"
            )
            tree_off = mapping_type.relative_child_offset(tree_member)
            tree_type_name = mapping_type.vol.members[tree_member][1].vol.type_name
            tree_type = vmlinux.context.symbol_space.get_type(tree_type_name)
            head_member = "xa_head" if tree_type.has_member("xa_head") else "rnode"
            head_off = tree_off + tree_type.relative_child_offset(head_member)
        except (
            exceptions.SymbolError,
            AttributeError,
            KeyError,
            IndexError,
            TypeError,
        ):
            return None
        page_size = pages.page_size
        state = {"broken": False}

        def read_int(address: int, length: int) -> int:
            return int.from_bytes(layer.read(address, length), byteorder)

        def peek(inode_addr: int) -> Union[bytes, object, None]:
            size = read_int(inode_addr + i_size_off, i_size_len)
            if not 0 < size <= PRELOAD_SCAN_MAX_SIZE:
                return None
            if state["broken"]:
                return UNDECIDED
            mapping = read_int(inode_addr + i_mapping_off, ptr_size) & address_mask
            if not mapping or read_int(mapping + nrpages_off, nrpages_len) == 0:
                return None
            head = read_int(mapping + head_off, ptr_size) & address_mask
            if not head:
                return None
            # A tagged head is an internal node (or an XArray value entry), not
            # a page. A file this small normally has its single page right here;
            # anything else is left to the object layer rather than guessed at.
            if head & 3:
                return UNDECIDED
            # The framework skips a cached page whose address space is not the
            # inode's (a stale or reused page); so does this.
            if not pages.belongs_to(head, mapping):
                return None
            try:
                pages.prepare(head)
            except (exceptions.VolatilityException, AttributeError):
                # Not an architecture this arithmetic covers; from here on
                # every sized candidate goes to the object layer.
                state["broken"] = True
                return UNDECIDED
            return pages.content(head, min(size, page_size))

        return peek

    @staticmethod
    def _same_file(wanted: str, cached: str) -> bool:
        """Whether ``cached`` is ``wanted`` allowing for usr-merge and container
        mount prefixes (``/lib/x`` matches ``/usr/lib/x`` and ``/mnt/root/lib/x``)."""
        return cached == wanted or (wanted.startswith("/") and cached.endswith(wanted))

    def _check_loaders(
        self,
        vmlinux_module_name: str,
        loaders: Dict[str, int],
        cached_paths: Set[str],
    ) -> List[LoaderCheck]:
        """Reads every glibc dynamic linker in the page cache and checks that it
        still carries the ``/etc/ld.so.preload`` string.

        A loader without it has been patched to read a different preload file.
        The replacement is recovered exactly when a leftover copy of the original
        (``ld-*.so.tmp`` and the like) is cached: the two differ only in that
        string. Otherwise the loader's other absolute-path strings are narrowed
        down by elimination and cross-checked against the page cache. A loader
        whose ``.rodata`` is not fully cached cannot be judged and is reported as
        inconclusive rather than patched.
        """
        vmlinux = self.context.modules[vmlinux_module_name]
        checks: List[LoaderCheck] = []
        seen: Set[int] = set()
        for path, inode_addr in loaders.items():
            if inode_addr in seen:
                continue
            seen.add(inode_addr)
            inode = vmlinux.object("inode", offset=inode_addr, absolute=True)
            if not self._inode_usable(inode):
                continue
            recovered = read_inode(self.context, vmlinux_module_name, inode, path)
            data = recovered.data
            if not data.startswith(ELF_MAGIC):
                vollog.debug("Dynamic linker %s: content not recoverable", path)
                continue
            if LOADER_PRELOAD_STRING + b"\x00" in data:
                vollog.debug("Dynamic linker %s: preload path intact", path)
                checks.append(LoaderCheck(recovered, "intact"))
                continue
            # Absent. Decide whether the string's home, .rodata, was actually read
            # before calling the loader patched; a missing page reads as zeros.
            rodata = ElfReader.section_range(data, ".rodata")
            region = data[rodata[0] : rodata[0] + rodata[1]] if rodata else data
            if self._has_zero_page(region):
                vollog.warning(
                    "Dynamic linker %s does not contain the /etc/ld.so.preload "
                    "string, but part of its read-only data is not cached; "
                    "inconclusive",
                    path,
                )
                checks.append(LoaderCheck(recovered, "inconclusive"))
                continue
            check = LoaderCheck(recovered, "patched")
            self._recover_replacement(check, cached_paths)
            vollog.warning(
                "The dynamic linker %s is patched: it reads %s instead of "
                "/etc/ld.so.preload",
                path,
                check.reads or "a path that could not be recovered",
            )
            checks.append(check)
        return checks

    @staticmethod
    def _has_zero_page(region: bytes, page_size: int = 4096) -> bool:
        """Whether ``region`` contains a whole page of zeros -- the signature of
        a page that was not in the cache and was zero filled on recovery."""
        for offset in range(0, len(region), page_size):
            chunk = region[offset : offset + page_size]
            if len(chunk) == page_size and not chunk.strip(b"\x00"):
                return True
        return False

    def _recover_replacement(self, check: LoaderCheck, cached_paths: Set[str]) -> None:
        """Fills ``check.reads`` / ``candidates`` for a patched loader."""
        live = check.recovered.data
        directory = check.recovered.path.rsplit("/", 1)[0]
        # Exact route: a leftover copy of the original loader in the same directory
        # and of the same size differs from the live one only in the patched string.
        for artifact in self._linker_artifacts:
            if artifact.path.rsplit("/", 1)[0] != directory:
                continue
            if len(artifact.data) != len(live) or not artifact.data:
                continue
            replaced = self._string_at_difference(live, artifact.data)
            if replaced:
                check.reads, check.verified = replaced, True
                return
        # Heuristic route: the loader's absolute-path strings minus the known ones.
        candidates = []
        for match in LOADER_STRING_RE.finditer(live):
            text = match.group(1).decode("ascii")
            if (
                text.endswith("/")
                or text in LOADER_KNOWN_PATHS
                or text.startswith(LOADER_IGNORED_PREFIXES)
                or "%" in text
                or text == LOADER_PRELOAD_STRING.decode()
            ):
                continue
            if text not in candidates:
                candidates.append(text)
        # A candidate that names a cached file is the answer; a preload file is
        # read at every process start, so it is essentially always cached.
        for text in candidates:
            if any(self._same_file(text, cached) for cached in cached_paths):
                check.reads, check.verified = text, True
                return
        if len(candidates) == 1:
            check.reads = candidates[0]
        else:
            check.candidates = candidates

    @staticmethod
    def _string_at_difference(live: bytes, original: bytes) -> Optional[str]:
        """The NUL-terminated string in ``live`` covering the first byte that
        differs from ``original`` -- the patched-in path."""
        for offset, (a, b) in enumerate(zip(live, original)):
            if a != b:
                break
        else:
            return None
        start = live.rfind(b"\x00", max(0, offset - 256), offset) + 1
        end = live.find(b"\x00", offset, offset + 256)
        if end < 0 or start == 0:
            return None
        try:
            text = live[start:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        return text if text.startswith("/") else None

    def _collect_linker_artifacts(
        self, vmlinux_module_name: str, artifacts: List[Tuple[str, int]]
    ) -> None:
        """Records leftover patched-loader copies (ld-*.so.tmp and the like)."""
        vmlinux = self.context.modules[vmlinux_module_name]
        seen: Set[int] = set()
        for path, inode_addr in artifacts:
            if inode_addr in seen:
                continue
            seen.add(inode_addr)
            inode = vmlinux.object("inode", offset=inode_addr, absolute=True)
            if not self._inode_usable(inode):
                continue
            recovered = read_inode(self.context, vmlinux_module_name, inode, path)
            # The name says loader copy; the content has to agree when it is
            # available, or a stray text file under such a name would be reported.
            if recovered.data and not recovered.data.startswith(ELF_MAGIC):
                vollog.debug("%s is named like a loader copy but is not an ELF", path)
                continue
            recovered.kind = "linker-artifact"
            self._linker_artifacts.append(recovered)
            vollog.warning(
                "%s is a leftover copy of the dynamic linker, consistent with an "
                "in-place patch of ld.so",
                path,
            )

    def _expand_tokens(self, name: str) -> str:
        """Expands the ld.so dynamic-string tokens a preload path may contain."""
        for token, value in (
            ("$PLATFORM", self._platform),
            ("${PLATFORM}", self._platform),
            ("$LIB", self._libdir),
            ("${LIB}", self._libdir),
        ):
            name = name.replace(token, value)
        return name

    def _lookup(
        self, name: str, libraries: Dict[str, int]
    ) -> Optional[Tuple[str, int]]:
        """Resolves a preload entry to a cached (path, inode address).

        Handles the ``/bin`` -> ``/usr/bin`` usr-merge (suffix match) and the ld.so
        dynamic-string tokens ($PLATFORM/$LIB): the concrete value is tried first,
        and a token that cannot be pinned down is matched as ``[^/]+`` so the entry
        still resolves to the real cached object regardless of the expanded value.
        """
        candidates = [name]
        expanded = self._expand_tokens(name)
        if expanded != name:
            candidates.append(expanded)
        for candidate in candidates:
            if candidate in libraries:
                return candidate, libraries[candidate]
            # A container's file appears under its mountpoint, and /bin is a symlink
            # to /usr/bin; a leading-'/' suffix match accepts both while '/lib/foo.so'
            # still cannot match '/evillib/foo.so'.
            for path, inode_addr in libraries.items():
                if path.endswith(candidate) and candidate.startswith("/"):
                    return path, inode_addr
        if DYNAMIC_TOKEN_RE.search(name):
            regex = self._token_suffix_regex(name)
            for path, inode_addr in libraries.items():
                if regex.search(path):
                    return path, inode_addr
        return None

    @staticmethod
    def _token_suffix_regex(name: str) -> "re.Pattern":
        """A suffix regex for a path with dynamic tokens, each token -> one path
        component fragment ([^/]+)."""
        parts, last = [], 0
        for match in DYNAMIC_TOKEN_RE.finditer(name):
            parts.append(re.escape(name[last : match.start()]))
            parts.append(r"[^/]+")
            last = match.end()
        parts.append(re.escape(name[last:]))
        return re.compile("".join(parts) + r"$")

    # -- process correlation -----------------------------------------------------
    #
    # The correlation answers one question per VMA: is its backing file one of the
    # wanted libraries? Framework objects answer it at the cost of constructing a
    # vm_area_struct (and often a file) object per VMA, each attribute access going
    # through the object layer. Instead, the few member offsets involved are
    # resolved from the symbol table once and the pointer chain
    # vma->vm_file->f_path.dentry->d_name.name is followed with raw layer reads.
    # Full objects are only constructed for the rare file whose dentry basename
    # matches a wanted library and needs its complete path rebuilt.
    #
    # This also sidesteps ``vm_area_struct.is_valid()`` dereferencing
    # ``file.get_inode()`` without a ``None`` check, where one file-backed VMA with a
    # non-resident inode can abort the rest of a task's walk inside
    # ``get_vma_iter()``. Here every per-VMA read is guarded individually: one bad
    # VMA costs one VMA, not the task.

    def _iter_vma_files(
        self, mm, layer, byteorder: str, ptr_size: int, vm_file_off: int, vm_next_off
    ) -> Iterator[int]:
        """Yields the ``vm_file`` pointer of each VMA of a task (zero for an
        anonymous mapping) without constructing a ``vm_area_struct``.

        Kernels >= 6.1 store VMAs in a maple tree; the framework's slot iterator
        yields the stored pointers, used here as plain addresses. Older kernels
        thread a singly linked list through ``vm_next``; there the span covering
        ``vm_next`` and ``vm_file`` is read once per VMA, so following the list
        and fetching the file cost a single translated read.
        """
        address_mask = layer.address_mask

        def ptr_at(buf: bytes, offset: int) -> int:
            return (
                int.from_bytes(buf[offset : offset + ptr_size], byteorder)
                & address_mask
            )

        try:
            has_maple = mm.has_member("mm_mt")
        except (exceptions.InvalidAddressException, AttributeError):
            return

        if has_maple:
            for slot in self._safe_iter(iter(mm.mm_mt.get_slot_iter())):
                try:
                    addr = int(slot)
                except (TypeError, ValueError):
                    continue
                # Values below the first page are maple-tree metadata, not VMAs.
                if addr < 0x1000:
                    continue
                try:
                    yield ptr_at(layer.read(addr + vm_file_off, ptr_size), 0)
                except exceptions.InvalidAddressException:
                    continue
            return

        if vm_next_off is None:
            return
        try:
            addr = int(mm.mmap)
        except (exceptions.InvalidAddressException, AttributeError):
            return
        span_start = min(vm_next_off, vm_file_off)
        span_len = max(vm_next_off, vm_file_off) - span_start + ptr_size
        seen: Set[int] = set()
        # The seen set breaks cycles; the count cap bounds a smeared list that
        # walks off into garbage without ever repeating an address.
        while addr and addr >= 0x1000 and addr not in seen and len(seen) < 262144:
            seen.add(addr)
            try:
                buf = layer.read(addr + span_start, span_len)
            except exceptions.InvalidAddressException:
                return
            yield ptr_at(buf, vm_file_off - span_start)
            addr = ptr_at(buf, vm_next_off - span_start)

    def _correlate_processes(self, entries: List[PreloadEntry]) -> Dict[str, int]:
        """Finds which running processes currently map each library.

        Returns ``{library name: inode address}`` for libraries whose inode was
        discovered through a process's ``vm_file`` -- the recovery fallback for
        a library no cached dentry path leads to anymore.
        """
        wanted_names = {entry.library for entry in entries}
        # A preload path may carry $PLATFORM/$LIB tokens or /bin (usr-merge); the
        # mapped file's basename is the expanded, real one. Both the raw and the
        # expanded basename are accepted at the cheap gate, and a token'd name is
        # matched as a suffix regex when the full path is reconstructed.
        wanted_basenames: Set[bytes] = set()
        path_matchers: List[Tuple[str, "re.Pattern"]] = []
        for name in wanted_names:
            expanded = self._expand_tokens(name)
            for variant in {name, expanded}:
                wanted_basenames.add(
                    variant.rsplit("/", 1)[-1].encode("utf-8", "replace")
                )
            if DYNAMIC_TOKEN_RE.search(name):
                path_matchers.append((name, self._token_suffix_regex(name)))
        # A dentry name longer than every wanted basename can only be a mismatch,
        # so name reads are capped just past the longest wanted one: a longer name
        # comes back without a NUL terminator and compares unequal.
        name_read_len = max(len(name) for name in wanted_basenames) + 1
        wanted_inodes = {
            entry.recovered.inode_addr: entry.library
            for entry in entries
            if entry.recovered is not None
        }
        by_library: Dict[str, Set[int]] = {name: set() for name in wanted_names}
        discovered_inodes: Dict[str, int] = {}
        file_cache: Dict[int, Optional[str]] = {}

        vmlinux = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[vmlinux.layer_name]

        ptr_template = vmlinux.get_type("pointer")
        ptr_size = ptr_template.size
        try:
            byteorder = ptr_template.vol.data_format.byteorder
        except AttributeError:
            byteorder = "little"

        # Masked like the object layer masks pointers, so a raw-read inode
        # address actually equals the object-derived one in ``wanted_inodes``.
        address_mask = layer.address_mask

        def read_ptr(address: int) -> int:
            return (
                int.from_bytes(layer.read(address, ptr_size), byteorder) & address_mask
            )

        def member_offset(type_name: str, member: str) -> int:
            return vmlinux.get_type(type_name).relative_child_offset(member)

        missing_member = (
            AttributeError,
            KeyError,
            IndexError,
            ValueError,
            exceptions.SymbolError,
        )
        vm_file_off = member_offset("vm_area_struct", "vm_file")
        f_path_dentry_off = member_offset("file", "f_path") + member_offset(
            "path", "dentry"
        )
        try:
            f_inode_off = member_offset("file", "f_inode")
        except missing_member:
            f_inode_off = None  # kernels < 3.9: reach the inode via the dentry
        d_inode_off = member_offset("dentry", "d_inode")
        d_name_name_off = member_offset("dentry", "d_name") + member_offset(
            "qstr", "name"
        )
        try:
            vm_next_off = member_offset("vm_area_struct", "vm_next")
        except missing_member:
            vm_next_off = None  # maple-tree kernel; the list walk is never taken

        def classify_file(file_addr: int, task) -> Optional[str]:
            """Which wanted library (if any) this file struct is.

            Inode address first -- the library's inode is known from the page cache
            walk, so a hit is an integer comparison. Only a matching dentry
            basename pays for full path reconstruction (which still catches a
            bind-mounted or otherwise aliased copy).
            """
            try:
                dentry_addr = 0
                if f_inode_off is not None:
                    inode_addr = read_ptr(file_addr + f_inode_off)
                else:
                    dentry_addr = read_ptr(file_addr + f_path_dentry_off)
                    if not dentry_addr:
                        return None
                    inode_addr = read_ptr(dentry_addr + d_inode_off)
                if inode_addr and inode_addr in wanted_inodes:
                    return wanted_inodes[inode_addr]

                if not dentry_addr:
                    dentry_addr = read_ptr(file_addr + f_path_dentry_off)
                    if not dentry_addr:
                        return None
                name_ptr = read_ptr(dentry_addr + d_name_name_off)
                if not name_ptr:
                    return None
                try:
                    basename = layer.read(name_ptr, name_read_len).split(b"\x00", 1)[0]
                except exceptions.InvalidAddressException:
                    # A short name right before an unmapped page fails the fixed
                    # size read; let the object layer read it exactly.
                    filp = vmlinux.object("file", offset=file_addr, absolute=True)
                    basename = (
                        filp.get_dentry()
                        .d_name.name_as_str()
                        .encode("utf-8", "replace")
                    )
                if basename not in wanted_basenames:
                    return None

                filp = vmlinux.object("file", offset=file_addr, absolute=True)
                path = linux_symbols.LinuxUtilities.path_for_file(
                    self.context, task, filp
                )
                for name in wanted_names:
                    expanded = self._expand_tokens(name)
                    hit = (
                        path == name
                        or path == expanded
                        or (
                            name.startswith("/")
                            and (path.endswith(name) or path.endswith(expanded))
                        )
                    )
                    if hit:
                        # Matched by name, so the page cache walk did not have
                        # this inode; remember it as the recovery fallback.
                        if inode_addr:
                            discovered_inodes.setdefault(name, inode_addr)
                        return name
                for name, regex in path_matchers:
                    if regex.search(path):
                        if inode_addr:
                            discovered_inodes.setdefault(name, inode_addr)
                        return name
            except (exceptions.InvalidAddressException, AttributeError, ValueError):
                return None
            return None

        for task in pslist.PsList.list_tasks(self.context, self.config["kernel"]):
            try:
                pid = int(task.pid)
                mm = task.mm
                if not (mm and mm.is_readable()):
                    continue
            except (exceptions.InvalidAddressException, AttributeError, ValueError):
                continue

            for file_addr in self._iter_vma_files(
                mm, layer, byteorder, ptr_size, vm_file_off, vm_next_off
            ):
                if not file_addr:
                    continue
                if file_addr in file_cache:
                    library = file_cache[file_addr]
                else:
                    library = classify_file(file_addr, task)
                    file_cache[file_addr] = library
                if library is not None:
                    by_library[library].add(pid)

        for entry in entries:
            entry.mapped_pids = sorted(by_library.get(entry.library, ()))
        return discovered_inodes

    # -- output ----------------------------------------------------------------

    @staticmethod
    def _format_pids(pids: List[int]) -> str:
        """Renders a sorted PID list with inclusive ``first-last`` ranges.

        A preload library is mapped into essentially every dynamically linked
        process, so the raw list runs to dozens of PIDs; collapsing consecutive
        PIDs keeps it scannable. No information is lost: expanding the ranges
        reproduces the exact list.
        """
        parts: List[str] = []
        start = prev = pids[0]
        for pid in pids[1:]:
            if pid == prev + 1:
                prev = pid
                continue
            parts.append(str(start) if start == prev else f"{start}-{prev}")
            start = prev = pid
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        return ", ".join(parts)

    @staticmethod
    def _timestamp_note(
        label: str,
        mtime: Optional[datetime.datetime],
        ctime: Optional[datetime.datetime],
    ) -> str:
        """Flags a modification time that cannot be taken at face value.

        A write sets both ``mtime`` and the inode's status-change time; only the
        former can be set from userland (``cp -p``, ``touch -r``). A ``ctime``
        well after the ``mtime`` therefore means the shown modification time was
        carried over from an original or set deliberately, and the change time
        is when the file really got its current content or metadata."""
        if not mtime or not ctime or (ctime - mtime).total_seconds() <= 60:
            return ""
        return (
            f"{label} changed at {ctime:%Y-%m-%d %H:%M:%S} UTC, after its "
            "modification time (mtime preserved from an original or set deliberately)"
        )

    def _generator(self):
        entries = self._collect()

        if self.config.get("dump") and not self._dumped:
            self._dump(entries)
            self._dumped = True

        show_all = self.config.get("all-symbols", False)

        na = renderers.NotAvailableValue
        nap = renderers.NotApplicableValue

        for entry in entries:
            elf = entry.elf
            recovered = entry.recovered

            notes = [entry.detection]
            if elf is not None and elf.valid:
                functions = elf.exported if show_all else elf.interposed()
                hooks = ", ".join(functions) if functions else nap()
            else:
                hooks = na()
                if recovered is not None and not recovered.data:
                    # The library was located but its content was not recoverable
                    # from the page cache, so its exports cannot be read. Say so
                    # rather than leaving a bare "-".
                    notes.append("library content not recoverable from the page cache")
            notes.append(
                self._timestamp_note(
                    "preload file", entry.preload_mtime, entry.preload_ctime
                )
            )
            if recovered is not None:
                notes.append(
                    self._timestamp_note(
                        "library", recovered.modification_time, recovered.change_time
                    )
                )
            note = "; ".join(part for part in notes if part)

            yield (
                0,
                (
                    entry.preload_path,
                    entry.preload_mtime or na(),
                    entry.library,
                    (recovered.modification_time if recovered else None) or na(),
                    hooks,
                    (
                        self._format_pids(entry.mapped_pids)
                        if entry.mapped_pids
                        else nap()
                    ),
                    note or nap(),
                ),
            )

        # A patched dynamic linker gets its own row: it is the root of the
        # persistence, and the file it points at may not even be cached.
        reported = {entry.preload_path for entry in entries}
        for check in self._loader_checks:
            if check.state != "patched":
                continue
            if check.reads and any(
                self._same_file(check.reads, path) for path in reported
            ):
                target = f"reads {check.reads} (analysed above)"
            elif check.reads and check.verified:
                target = (
                    f"reads {check.reads}, which is cached but could not be "
                    "analysed as a preload file"
                )
            elif check.reads:
                target = f"reads {check.reads}, which is not present in the page cache"
            elif check.candidates:
                target = (
                    "the replacement path could not be verified; candidate "
                    "string(s): " + ", ".join(check.candidates)
                )
            else:
                target = "the replacement path could not be recovered"
            note = f"patched dynamic linker: {target} instead of /etc/ld.so.preload"
            stamp = self._timestamp_note(
                "loader",
                check.recovered.modification_time,
                check.recovered.change_time,
            )
            yield (
                0,
                (
                    check.recovered.path,
                    check.recovered.modification_time or na(),
                    "(dynamic linker)",
                    na(),
                    na(),
                    nap(),
                    f"{note}; {stamp}" if stamp else note,
                ),
            )

        # Leftover patched-loader copies are reported even when their pages (and so
        # the preload path they were patched with) could not be recovered.
        for artifact in self._linker_artifacts:
            note = (
                "leftover copy of the dynamic linker, consistent with an in-place "
                "patch of ld.so"
            )
            stamp = self._timestamp_note(
                "copy", artifact.modification_time, artifact.change_time
            )
            yield (
                0,
                (
                    artifact.path,
                    artifact.modification_time or na(),
                    "(dynamic linker copy)",
                    na(),
                    na(),
                    nap(),
                    f"{note}; {stamp}" if stamp else note,
                ),
            )

    def _dump(self, entries: List[PreloadEntry]) -> None:
        """Extracts the preload file and every library it names."""
        written: Set[str] = set()
        for preload in self._preload_files:
            self._write(preload, "ldsopreload", written)
        for entry in entries:
            if entry.recovered is not None:
                self._write(entry.recovered, "preloadlib", written)
        for artifact in self._linker_artifacts:
            self._write(artifact, "linkerartifact", written)
        for check in self._loader_checks:
            if check.state == "patched":
                self._write(check.recovered, "patchedlinker", written)

    def _write(self, recovered: RecoveredFile, prefix: str, written: Set[str]) -> None:
        if recovered.path in written:
            return
        written.add(recovered.path)
        filename = self.open.sanitize_filename(
            f"{prefix}.{recovered.path.strip('/').replace('/', '_')}"
            f".0x{recovered.inode_addr:x}"
        )
        try:
            with self.open(filename) as handle:
                handle.write(recovered.data)
            vollog.info("Wrote %s to %s", recovered.path, filename)
        except OSError as excp:
            vollog.error("Unable to write %s: %s", filename, excp)

    def generate_timeline(self):
        self._collect()
        modified = timeliner.TimeLinerType.MODIFIED
        changed = timeliner.TimeLinerType.CHANGED
        for preload in self._preload_files:
            description = f"ld.so.preload file {preload.path}"[:400]
            if preload.modification_time:
                yield description, modified, preload.modification_time
            if preload.change_time:
                yield description, changed, preload.change_time
        for entry in self._entries or ():
            recovered = entry.recovered
            if recovered is None:
                continue
            description = f"ld.so.preload library {entry.library}"[:400]
            if recovered.modification_time:
                yield description, modified, recovered.modification_time
            if recovered.change_time:
                yield description, changed, recovered.change_time
        for check in self._loader_checks:
            if check.state != "patched":
                continue
            description = f"patched dynamic linker {check.recovered.path}"[:400]
            if check.recovered.modification_time:
                yield description, modified, check.recovered.modification_time
            if check.recovered.change_time:
                yield description, changed, check.recovered.change_time

    def run(self):
        return renderers.TreeGrid(
            [
                ("File", str),
                ("File Modification Time", datetime.datetime),
                ("Library", str),
                ("Library Modification Time", datetime.datetime),
                ("Overridden Functions", str),
                ("Mapped PIDs", str),
                ("Notes", str),
            ],
            self._generator(),
        )
