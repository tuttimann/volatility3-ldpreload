# This file is Copyright 2026 tuttimann and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the image-independent parts of ``linux.ldpreload``.

Everything here runs without a memory image: the ELF reader, the preload-file
parser and content test, path resolution, the environment assessment, the
patched-loader string recovery and the name regexes. Run with::

    python -m unittest discover -s tests -v

``volatility3`` must be importable (the plugin imports the framework at module
level); the tests are skipped with a message otherwise.
"""

import contextlib
import datetime
import importlib.util
import pathlib
import random
import re
import signal
import struct
import time
import unittest
from types import SimpleNamespace
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = REPO / "linux" / "ldpreload.py"

try:
    import volatility3  # noqa: F401

    HAVE_FRAMEWORK = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_FRAMEWORK = False


def load_plugin():
    spec = importlib.util.spec_from_file_location("ldpreload_under_test", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if HAVE_FRAMEWORK:
    ldpreload = load_plugin()


def make_plugin(config=None, **attrs):
    """An ``LdPreload`` instance without a context, for its pure helpers."""
    plugin = ldpreload.LdPreload.__new__(ldpreload.LdPreload)
    plugin._config_cache = dict(config or {})
    plugin._entries = None
    plugin._preload_files = []
    plugin._linker_artifacts = []
    plugin._loader_checks = []
    plugin._confirmed_by = {}
    plugin._dumped = False
    plugin._limit = 0
    plugin._platform = "x86_64"
    plugin._libdir = "lib64"
    plugin._read_total = 0
    plugin._read_total_warned = False
    for name, value in attrs.items():
        setattr(plugin, name, value)
    return plugin


# -- a minimal ELF builder -----------------------------------------------------

STT_FUNC, STT_OBJECT = 2, 1
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
SHT_PROGBITS, SHT_STRTAB, SHT_DYNSYM = 1, 3, 11


PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 4, 5, 6, 10, 11
DT_GNU_HASH = 0x6FFFFEF5


def build_elf(*args, **kwargs):
    """The image of ``build_elf_layout``."""
    return build_elf_layout(*args, **kwargs)[0]


def build_elf_layout(
    symbols,
    bits=64,
    rodata=b"",
    shentsize=None,
    truncate_at=None,
    strip_sections=False,
    dynamic=True,
    hash_style="sysv",
    endian="<",
    vaddr_base=0,
    machine=None,
    hash_word=4,
):
    """A shared-object image with .dynstr, .dynsym, .rodata and .shstrtab and,
    with ``dynamic``, the hash table(s) of ``hash_style`` ("sysv", "gnu" or
    "both"), a dynamic segment and the program headers (one PT_LOAD of the
    whole file at ``vaddr_base``, one PT_DYNAMIC) the loader goes by. The new
    parts follow the old ones, so the offsets of .dynstr and .dynsym do not
    depend on them.

    ``symbols`` is a list of ``(name, type, binding, defined)``. Returns the
    image and a dict of the file offsets of its parts.
    """
    sym_size = 24 if bits == 64 else 16
    shdr_size = 64 if bits == 64 else 40
    ehdr_size = 64 if bits == 64 else 52
    phdr_size = 56 if bits == 64 else 32
    dyn_size = 16 if bits == 64 else 8

    dynstr = bytearray(b"\x00")  # bytearrays: one test builds 65537 symbols
    name_offsets = []
    for name, *_ in symbols:
        name_offsets.append(len(dynstr))
        dynstr += name.encode() + b"\x00"

    dynsym = bytearray(sym_size)  # the mandatory null symbol
    for (name, sym_type, binding, defined), name_off in zip(symbols, name_offsets):
        info = (binding << 4) | sym_type
        shndx = 3 if defined else 0  # .rodata or SHN_UNDEF
        if bits == 64:
            dynsym += struct.pack(endian + "IBBHQQ", name_off, info, 0, shndx, 0x1000, 16)
        else:
            dynsym += struct.pack(endian + "IIIBBH", name_off, 0x1000, 16, info, 0, shndx)

    shstrtab = b"\x00.dynstr\x00.dynsym\x00.rodata\x00.shstrtab\x00"
    shname = {
        ".dynstr": 1,
        ".dynsym": 9,
        ".rodata": 17,
        ".shstrtab": 25,
    }

    nsyms = len(symbols) + 1
    # Hash tables with real, non-zero chains: a run of zero words would read
    # as an uncached page.
    word = "Q" if hash_word == 8 else "I"
    sysv_hash = struct.pack(endian + word * 3, 1, nsyms, nsyms - 1) + struct.pack(
        f"{endian}{nsyms}{word}", 0, *range(nsyms - 1)
    )
    hashed = nsyms - 1  # every symbol but the null one, from symoffset 1
    chain = [(2 * index + 2) & ~1 for index in range(hashed)]
    if chain:
        chain[-1] |= 1
    gnu_hash = (
        struct.pack(endian + "IIII", 1, 1, 1, 6)
        + struct.pack(endian + ("Q" if bits == 64 else "I"), (1 << bits) - 1)
        + struct.pack(endian + "I", 1 if hashed else 0)
        + struct.pack(f"{endian}{hashed}I", *chain)
    )

    body = bytearray()
    offsets = {}
    parts = [
        ("dynstr", dynstr),
        ("dynsym", dynsym),
        ("rodata", rodata),
        ("shstrtab", shstrtab),
    ]
    if dynamic and hash_style in ("sysv", "both"):
        parts.append(("hash", sysv_hash))
    if dynamic and hash_style in ("gnu", "both"):
        parts.append(("gnu_hash", gnu_hash))
    for label, blob in parts:
        offsets[label] = ehdr_size + len(body)
        body += blob
        body += b"\x00" * (-len(body) % 8)

    phoff = phnum = 0
    if dynamic:
        # d_ptr entries are addresses, d_val entries are not.
        tags = []
        if "hash" in offsets:
            tags.append((DT_HASH, vaddr_base + offsets["hash"]))
        if "gnu_hash" in offsets:
            tags.append((DT_GNU_HASH, vaddr_base + offsets["gnu_hash"]))
        tags += [
            (DT_STRTAB, vaddr_base + offsets["dynstr"]),
            (DT_SYMTAB, vaddr_base + offsets["dynsym"]),
            (DT_STRSZ, len(dynstr)),
            (DT_SYMENT, sym_size),
            (DT_NULL, 0),
        ]
        dyn_format = endian + ("qQ" if bits == 64 else "iI")
        blob = b"".join(struct.pack(dyn_format, tag, value) for tag, value in tags)
        offsets["dynamic"] = ehdr_size + len(body)
        body += blob
        phoff = offsets["phdr"] = ehdr_size + len(body)
        phnum = 2
        body += b"\x00" * (phnum * phdr_size)
    shoff = ehdr_size + len(body)

    def shdr(name, sh_type, offset, size, link=0, entsize=0):
        if bits == 64:
            return struct.pack(
                endian + "IIQQQQIIQQ", name, sh_type, 0, 0, offset, size, link, 0, 1, entsize
            )
        return struct.pack(
            endian + "IIIIIIIIII", name, sh_type, 0, 0, offset, size, link, 0, 1, entsize
        )

    headers = (
        shdr(0, 0, 0, 0)
        + shdr(shname[".dynstr"], SHT_STRTAB, offsets["dynstr"], len(dynstr))
        + shdr(shname[".dynsym"], SHT_DYNSYM, offsets["dynsym"], len(dynsym), 1, sym_size)
        + shdr(shname[".rodata"], SHT_PROGBITS, offsets["rodata"], len(rodata))
        + shdr(shname[".shstrtab"], SHT_STRTAB, offsets["shstrtab"], len(shstrtab))
    )
    shnum = 5
    shentsize = shdr_size if shentsize is None else shentsize
    if strip_sections:
        # What sstrip leaves: no section header table at all. The loader does
        # not need one (it works from PT_DYNAMIC), so the object still loads.
        headers, shoff, shnum = b"", 0, 0
    offsets["shoff"] = shoff

    if dynamic:
        size = ehdr_size + len(body) + len(headers)
        if bits == 64:
            phdr_format = endian + "IIQQQQQQ"
            load = (PT_LOAD, 5, 0, vaddr_base, vaddr_base, size, size, 0x1000)
            dyn = (PT_DYNAMIC, 6, offsets["dynamic"], vaddr_base + offsets["dynamic"],
                   vaddr_base + offsets["dynamic"], len(blob), len(blob), 8)
        else:
            phdr_format = endian + "IIIIIIII"
            load = (PT_LOAD, 0, vaddr_base, vaddr_base, size, size, 5, 0x1000)
            dyn = (PT_DYNAMIC, offsets["dynamic"], vaddr_base + offsets["dynamic"],
                   vaddr_base + offsets["dynamic"], len(blob), len(blob), 6, 4)
        start = phoff - ehdr_size
        body[start : start + 2 * phdr_size] = struct.pack(
            phdr_format, *load
        ) + struct.pack(phdr_format, *dyn)

    big = endian == ">"
    if machine is None:
        machine = (43 if bits == 64 else 2) if big else (62 if bits == 64 else 3)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 2 if big else 1, 1, 0]) + b"\x00" * 8
    phentsize = phdr_size if dynamic else 0
    if bits == 64:
        ehdr = ident + struct.pack(
            endian + "HHIQQQIHHHHHH",
            3, machine, 1, 0, phoff, shoff, 0, 64, phentsize, phnum, shentsize, shnum, 4,
        )
    else:
        ehdr = ident + struct.pack(
            endian + "HHIIIIIHHHHHH",
            3, machine, 1, 0, phoff, shoff, 0, 52, phentsize, phnum, shentsize, shnum, 4,
        )
    data = ehdr + bytes(body) + headers
    if truncate_at is not None:
        data = data[:truncate_at]
    return data, offsets


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ElfReaderTests(unittest.TestCase):
    SYMBOLS = [
        ("readdir", STT_FUNC, STB_GLOBAL, True),
        ("open", STT_FUNC, STB_WEAK, True),
        ("helper", STT_FUNC, STB_LOCAL, True),  # local: never interposes
        ("write", STT_FUNC, STB_GLOBAL, False),  # import, not a definition
        ("secret_table", STT_OBJECT, STB_GLOBAL, True),  # data, not a function
        ("hide_me", STT_FUNC, STB_GLOBAL, True),
        ("fopen@@GLIBC_2.2.5", STT_FUNC, STB_GLOBAL, True),
    ]

    def test_exports_and_interposed_64(self):
        info = ldpreload.ElfReader.parse(build_elf(self.SYMBOLS))
        self.assertTrue(info.valid)
        self.assertEqual(info.bits, 64)
        self.assertEqual(info.exported, ["fopen", "hide_me", "open", "readdir"])
        self.assertEqual(info.interposed(), ["fopen", "open", "readdir"])

    def test_exports_32(self):
        info = ldpreload.ElfReader.parse(build_elf(self.SYMBOLS, bits=32))
        self.assertTrue(info.valid)
        self.assertEqual(info.bits, 32)
        self.assertEqual(info.exported, ["fopen", "hide_me", "open", "readdir"])

    def test_section_range(self):
        data = build_elf(self.SYMBOLS, rodata=b"/etc/ld.so.preload\x00/etc/ld.so.cache\x00")
        rng = ldpreload.ElfReader.section_range(data, ".rodata")
        self.assertIsNotNone(rng)
        offset, size = rng
        self.assertEqual(data[offset : offset + size], b"/etc/ld.so.preload\x00/etc/ld.so.cache\x00")
        self.assertIsNone(ldpreload.ElfReader.section_range(data, ".nosuch"))

    def test_truncated_image_is_valid_but_empty(self):
        data = build_elf(self.SYMBOLS, truncate_at=200)
        info = ldpreload.ElfReader.parse(data)
        self.assertTrue(info.valid)
        self.assertEqual(info.exported, [])

    def test_garbage_and_short_input(self):
        self.assertFalse(ldpreload.ElfReader.parse(b"").valid)
        self.assertFalse(ldpreload.ElfReader.parse(b"\x7fELF" + b"\x00" * 10).valid)
        self.assertFalse(ldpreload.ElfReader.parse(b"not an elf" * 20).valid)
        self.assertIsNone(ldpreload.ElfReader.section_range(b"x" * 100, ".rodata"))

    def test_zero_shentsize_does_not_alias_headers(self):
        # Without a dynamic segment the section headers are all there is.
        data = build_elf(self.SYMBOLS, shentsize=0, dynamic=False)
        info = ldpreload.ElfReader.parse(data)
        self.assertTrue(info.valid)
        self.assertEqual(info.exported, [])
        self.assertIsNone(ldpreload.ElfReader.section_range(data, ".rodata"))

    def test_zero_shentsize_direct_probe(self):
        # parse() alone cannot tell: its first header is the null one, which
        # yields nothing however often it is re-read. Aimed at the .dynstr
        # header, an entry size of 0 would return that header once per shnum.
        sections = ldpreload.ElfReader._sections
        data = build_elf(self.SYMBOLS)
        shoff = struct.unpack_from("<Q", data, 0x28)[0] + 64  # header 1: .dynstr
        self.assertEqual(sections(data, "<", 64, shoff, 0, 2), [])
        self.assertEqual(sections(data, "<", 64, shoff, 63, 2), [])
        self.assertEqual(sections(data, "<", 32, shoff, 39, 2), [])
        # The real entry size reads two distinct headers (.dynstr, .dynsym).
        real = sections(data, "<", 64, shoff, 64, 2)
        self.assertEqual([entry[0] for entry in real], [SHT_STRTAB, SHT_DYNSYM])

    def test_zero_filled_hole_is_tolerated(self):
        data = bytearray(build_elf(self.SYMBOLS))
        # Wipe the string table page: names become empty and are skipped.
        rng = ldpreload.ElfReader.section_range(bytes(data), ".rodata")
        self.assertIsNotNone(rng)
        data[64:100] = b"\x00" * 36  # part of .dynstr
        info = ldpreload.ElfReader.parse(bytes(data))
        self.assertTrue(info.valid)
        self.assertTrue(set(info.exported) <= {"fopen", "hide_me", "open", "readdir"})


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class PreloadFileTests(unittest.TestCase):
    def test_parse_whitespace_comments_and_holes(self):
        data = b"/lib64/a.so\n# comment\n  /lib/b.so /opt/c.so.1 \n\x00\x00/usr/lib/d.so\n"
        self.assertEqual(
            ldpreload.LdPreload._parse_preload(data),
            ["/lib64/a.so", "/lib/b.so", "/opt/c.so.1", "/usr/lib/d.so"],
        )
        self.assertEqual(ldpreload.LdPreload._parse_preload(b""), [])
        self.assertEqual(ldpreload.LdPreload._parse_preload(b"\x00" * 4096), [])

    def test_looks_like_preload(self):
        looks = ldpreload.LdPreload._looks_like_preload
        self.assertTrue(looks(b"/lib64/selinux.so.3\n"))
        self.assertTrue(looks(b"/bin/llvm-sizh/libllvm-sizh.so.$PLATFORM\n"))
        self.assertTrue(looks(b"/lib/a.so /lib/b.so.1.2\n\x00\x00\x00"))
        self.assertFalse(looks(b""))
        self.assertFalse(looks(b"libfoo.so\n"))  # bare name: not accepted by the scan
        self.assertFalse(looks(b"/lib/a.so\nsome text\n"))
        self.assertFalse(looks(b"[section]\nlib=/lib/a.so\n"))
        self.assertFalse(looks(b"/usr/lib64/libc.so.6 2\n"))  # trailing flag
        self.assertFalse(looks(b"/etc/ld.so.conf.d\n"))  # a loader-owned name, never preloaded
        self.assertFalse(looks(b"/lib64/a.so\n/etc/ld.so.cache\n"))
        self.assertFalse(looks(b"/etc/ld.so.conf\n"))
        self.assertFalse(looks(b"/etc/ld.so.cache~\n"))
        self.assertFalse(looks(b"\x7fELF" + b"\x00" * 60))

    def test_ld_so_named_library_is_preload_content(self):
        # Only the loader's own config/cache names are excluded, not every ld.so.*.
        looks = ldpreload.LdPreload._looks_like_preload
        self.assertTrue(looks(b"/usr/lib/ld.so.evil.so\n"))
        self.assertTrue(looks(b"/lib64/a.so\n/usr/lib/ld.so.x.so.1\n"))

    def test_split_preload_value(self):
        split = ldpreload.LdPreload._split_preload_value
        self.assertEqual(split("/a.so:/b.so"), ["/a.so", "/b.so"])
        self.assertEqual(split(" /a.so  /b.so "), ["/a.so", "/b.so"])
        self.assertEqual(split("/a.so: /b.so"), ["/a.so", "/b.so"])
        self.assertEqual(split(""), [])
        self.assertEqual(split(":"), [])

    def test_split_preload_value_like_the_loader(self):
        # glibc splits LD_PRELOAD at " :" and LD_AUDIT at ":" only; a tab or a
        # newline (or, for LD_AUDIT, a space) is part of the object's name.
        split = ldpreload.LdPreload._split_preload_value
        self.assertEqual(split("/tmp/a\tb.so:/c.so", "LD_PRELOAD"), ["/tmp/a\tb.so", "/c.so"])
        self.assertEqual(split("/tmp/a\nb.so /c.so", "LD_PRELOAD"), ["/tmp/a\nb.so", "/c.so"])
        self.assertEqual(split("/tmp/my lib.so:/c.so", "LD_AUDIT"), ["/tmp/my lib.so", "/c.so"])

    def test_parse_separators_and_comments_like_the_loader(self):
        parse = ldpreload.LdPreload._parse_preload
        looks = ldpreload.LdPreload._looks_like_preload
        # A colon separates entries, as it does for the loader.
        self.assertEqual(parse(b"/lib/a.so:/lib/b.so\n"), ["/lib/a.so", "/lib/b.so"])
        self.assertTrue(looks(b"/lib/a.so:/lib/b.so\n"))
        # A comment starts at any '#', not only at the start of a line.
        self.assertEqual(
            parse(b"/lib/c.so#x\n/lib/d.so # note here\n  # whole line\n/lib/e.so"),
            ["/lib/c.so", "/lib/d.so", "/lib/e.so"],
        )
        self.assertTrue(looks(b"/lib/c.so#/etc/passwd\n"))
        self.assertTrue(looks(b"/lib/d.so # loaded by the vendor agent\n"))
        self.assertFalse(looks(b"# /lib/only-a-comment.so\n"))
        # Only " \t\n:" separate: other whitespace belongs to the name.
        self.assertEqual(
            parse("/lib/evil x.so\n/lib/a\x0bb.so\r\n".encode()),
            ["/lib/evil x.so", "/lib/a\x0bb.so\r"],
        )
        self.assertTrue(looks("/lib/evil x.so\n".encode()))

    def test_preload_vars_from_environment_block(self):
        block = (
            b"PATH=/usr/bin\x00LD_PRELOAD=/tmp/x.so:/tmp/y.so\x00XLD_PRELOAD=/no\x00"
            b"LD_AUDIT=/opt/a.so\x00LD_PRELOAD\x00\x00HOME=/root\x00"
        )
        self.assertEqual(
            list(ldpreload.LdPreload._preload_vars(block)),
            [("LD_PRELOAD", "/tmp/x.so:/tmp/y.so"), ("LD_AUDIT", "/opt/a.so")],
        )
        self.assertEqual(list(ldpreload.LdPreload._preload_vars(b"\x00" * 100)), [])


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ResolutionTests(unittest.TestCase):
    LIBRARIES = {
        "/usr/lib64/libc.so.6": 1,
        "/usr/lib64/selinux.so.3": 2,
        "/usr/bin/opensslbn/libopensslbn.so.x86_64": 3,
        "/var/lib/docker/overlay2/abc/merged/lib/evil.so": 4,
        "/home/user/build/libfoo.so": 5,
        "/usr/lib64/libfoo.so": 6,
        "/var/tmp/evil.so": 7,
    }

    def setUp(self):
        self.plugin = make_plugin()

    def test_exact_and_usr_merge(self):
        lookup = self.plugin._lookup
        self.assertEqual(lookup("/usr/lib64/libc.so.6", self.LIBRARIES), ("/usr/lib64/libc.so.6", 1))
        self.assertEqual(lookup("/lib64/selinux.so.3", self.LIBRARIES), ("/usr/lib64/selinux.so.3", 2))

    def test_container_prefix(self):
        self.assertEqual(
            self.plugin._lookup("/lib/evil.so", self.LIBRARIES),
            ("/var/lib/docker/overlay2/abc/merged/lib/evil.so", 4),
        )

    def test_dynamic_tokens(self):
        lookup = self.plugin._lookup
        self.assertEqual(
            lookup("/bin/opensslbn/libopensslbn.so.$PLATFORM", self.LIBRARIES),
            ("/usr/bin/opensslbn/libopensslbn.so.x86_64", 3),
        )
        # An unexpected platform value still resolves through the token regex.
        plugin = make_plugin(_platform="haswell")
        self.assertEqual(
            plugin._lookup("/bin/opensslbn/libopensslbn.so.${PLATFORM}", self.LIBRARIES),
            ("/usr/bin/opensslbn/libopensslbn.so.x86_64", 3),
        )

    def test_bare_and_relative_names_prefer_system_dirs(self):
        lookup = self.plugin._lookup
        self.assertEqual(lookup("libfoo.so", self.LIBRARIES), ("/usr/lib64/libfoo.so", 6))
        self.assertEqual(lookup("./build/libfoo.so", self.LIBRARIES), ("/usr/lib64/libfoo.so", 6))
        self.assertIsNone(lookup("libmissing.so", self.LIBRARIES))
        self.assertIsNone(lookup("/nonexistent/lib.so", self.LIBRARIES))

    def linear_lookup(self, name, libraries):
        """The 1.7.0 lookup: every name against every cached path."""
        plugin = self.plugin
        candidates = [name]
        expanded = plugin._expand_tokens(name)
        if expanded != name:
            candidates.append(expanded)
        for candidate in candidates:
            if candidate in libraries:
                return candidate, libraries[candidate]
            for path, inode_addr in libraries.items():
                if path.endswith(candidate) and candidate.startswith("/"):
                    return path, inode_addr
        if ldpreload.DYNAMIC_TOKEN_RE.search(name):
            regex = plugin._token_suffix_regex(name)
            for path, inode_addr in libraries.items():
                if regex.search(path):
                    return path, inode_addr
        if not name.startswith("/"):
            basename = name.rsplit("/", 1)[-1]
            matches = [
                (path, inode_addr)
                for path, inode_addr in libraries.items()
                if path.rsplit("/", 1)[-1] == basename
            ]
            if matches:
                matches.sort(key=lambda m: (not m[0].startswith(ldpreload.SYSTEM_LIB_DIRS), m[0]))
                return matches[0]
        return None

    def test_indexed_lookup_matches_the_linear_one(self):
        rng = random.Random(1800)
        parts = ["usr", "lib", "lib64", "tmp", "x", "mnt", "root", "", "bin", "a.so", "b.so"]
        names = ["libc.so.6", "evil.so", "a.so", "b.so", "x86_64", "lib64", ""]

        def path():
            return "/" + "/".join(rng.choice(parts) for _ in range(rng.randint(0, 4))) + (
                "/" + rng.choice(names) if rng.random() < 0.9 else "/"
            )

        for _ in range(300):
            libraries = {}
            for _ in range(rng.randint(0, 30)):
                libraries.setdefault(path(), rng.randint(1, 1000))
            index = self.plugin._basename_index(libraries)
            queries = list(libraries)[:5] + [path() for _ in range(10)] + [
                rng.choice(names),
                "./build/" + rng.choice(names),
                "/usr/$LIB/" + rng.choice(names),
                "/" + rng.choice(names),
                "lib/" + rng.choice(names),
            ]
            for name in queries:
                expected = self.linear_lookup(name, libraries)
                self.assertEqual(self.plugin._lookup(name, libraries, index), expected, name)
                self.assertEqual(self.plugin._lookup(name, libraries), expected, name)

    def test_suffix_match_needs_a_component_boundary(self):
        # "/lib/evil.so" must not resolve to "/evillib/evil.so"-like paths.
        self.assertIsNone(self.plugin._lookup("/mp/evil.so", {"/var/tmp/evil.so": 7}))

    def test_token_suffix_regex(self):
        regex = ldpreload.LdPreload._token_suffix_regex("/bin/x/lib.so.$PLATFORM")
        self.assertTrue(regex.search("/usr/bin/x/lib.so.x86_64"))
        self.assertFalse(regex.search("/usr/bin/x/lib.so.x86_64/extra"))
        self.assertFalse(regex.search("/usr/bin/x/lib.so"))
        regex = ldpreload.LdPreload._token_suffix_regex("/usr/$LIB/libx.so")
        self.assertTrue(regex.search("/usr/lib64/libx.so"))
        self.assertTrue(regex.search("/usr/lib/libx.so"))

    def test_same_file(self):
        same = ldpreload.LdPreload._same_file
        self.assertTrue(same("/etc/x", "/etc/x"))
        self.assertTrue(same("/etc/x", "/mnt/root/etc/x"))
        self.assertTrue(same("/lib/x.so", "/usr/lib/x.so"))
        self.assertFalse(same("/etc/x", "/etc/xy"))
        self.assertFalse(same("etc/x", "/etc/x"))

    def test_expand_tokens(self):
        expand = self.plugin._expand_tokens
        self.assertEqual(expand("/usr/$LIB/a.so.$PLATFORM"), "/usr/lib64/a.so.x86_64")
        self.assertEqual(expand("/usr/${LIB}/a.so.${PLATFORM}"), "/usr/lib64/a.so.x86_64")
        self.assertEqual(expand("/plain.so"), "/plain.so")


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class EnvironmentAssessmentTests(unittest.TestCase):
    def entry(self, library, recovered_path=None, exported=(), var="LD_PRELOAD"):
        entry = ldpreload.PreloadEntry(
            preload_path=var, library=library, env_var=var, env_pids={100: "bash"}
        )
        if recovered_path is not None:
            entry.recovered = ldpreload.RecoveredFile(
                path=recovered_path, inode_addr=0x1000, data=b"\x7fELF"
            )
            entry.elf = ldpreload.ElfInfo(valid=True, bits=64, exported=sorted(exported))
        return entry

    def assess(self, entry, **config):
        plugin = make_plugin(config)
        return plugin._assess_env_entries([entry])

    def test_tmp_library_overriding_readdir_is_suspicious(self):
        entry = self.entry("/tmp/.x/evil.so", "/tmp/.x/evil.so", ["readdir", "open"])
        (kept,) = self.assess(entry)
        self.assertFalse(kept.benign)
        self.assertEqual(
            kept.reasons,
            ["outside the system library directories", "hidden file", "overrides libc functions"],
        )

    def test_relative_path(self):
        entry = self.entry("./build/evil.so", "/home/u/build/evil.so", ["accept"])
        (kept,) = self.assess(entry)
        self.assertIn("relative path", kept.reasons)
        self.assertIn("overrides libc functions", kept.reasons)

    def test_bare_name_not_found(self):
        (kept,) = self.assess(self.entry("libx.so"))
        self.assertEqual(kept.reasons, ["bare name, not found in the page cache"])
        self.assertFalse(kept.benign)

    def test_not_named_like_shared_object(self):
        (kept,) = self.assess(self.entry("/usr/lib64/data.bin", "/usr/lib64/data.bin"))
        self.assertEqual(kept.reasons, ["not named like a shared object"])

    def test_vendor_wrapper_in_system_dir_is_assumed_safe(self):
        path = "/opt/splunkforwarder/lib/libdlwrapper.so"
        entry = self.entry(path, path, ["dlopen_wrapper"])
        (kept,) = self.assess(entry)
        self.assertTrue(kept.benign)
        self.assertEqual(kept.reasons, [])
        self.assertEqual(self.assess(entry, **{"filter-safe-env": True}), [])

    def test_unanalysed_system_library_is_not_assumed_safe(self):
        # Nothing of the library was seen: not cached at all ...
        path = "/usr/lib64/libquiet.so"
        entry = self.entry(path)
        (kept,) = self.assess(entry, **{"filter-safe-env": True})
        self.assertFalse(kept.benign)
        # ... or recovered without a readable symbol table (no dynamic segment
        # and no section headers, or their pages not cached). Neither is
        # hidden as safe.
        entry = self.entry(path, path)
        entry.elf = ldpreload.ElfReader.parse(
            build_elf([], strip_sections=True, dynamic=False)
        )
        self.assertTrue(entry.elf.valid and entry.elf.incomplete)
        (kept,) = self.assess(entry, **{"filter-safe-env": True})
        self.assertFalse(kept.benign)
        self.assertEqual(kept.reasons, [])

    def test_known_preload_overriding_libc_is_assumed_safe_only_in_system_dir(self):
        entry = self.entry("/usr/lib64/libjemalloc.so.2", "/usr/lib64/libjemalloc.so.2", ["open", "read"])
        (kept,) = self.assess(entry)
        self.assertTrue(kept.benign)
        self.assertEqual(kept.reasons, ["overrides libc functions"])
        entry = self.entry("/tmp/libjemalloc.so.2", "/tmp/libjemalloc.so.2", ["open"])
        (kept,) = self.assess(entry)
        self.assertFalse(kept.benign)

    def test_unknown_system_library_overriding_libc_is_not_safe(self):
        entry = self.entry("/usr/lib64/libselinux.so.3", "/usr/lib64/libselinux.so.3", ["readdir"])
        (kept,) = self.assess(entry)
        self.assertFalse(kept.benign)
        self.assertEqual(kept.reasons, ["overrides libc functions"])

    def test_env_note(self):
        plugin = make_plugin()
        entry = self.entry("libx.so", "/usr/lib64/libx.so", ["readdir"])
        entry.env_pids = {100: "bash", 101: "sshd"}
        entry.mapped_pids = [100, 101, 200]
        entry.reasons = ["overrides libc functions"]
        note = plugin._env_note(entry)
        self.assertIn("PID(s) 100 (bash), 101 (sshd)", note)
        self.assertIn("resolved to /usr/lib64/libx.so", note)
        self.assertIn("mapped by all of them", note)
        self.assertIn("suspicious: overrides libc functions", note)
        entry.mapped_pids = [100]
        self.assertIn("mapped by 100 of them", plugin._env_note(entry))
        entry.mapped_pids = [300]
        self.assertIn("mapped by other processes only", plugin._env_note(entry))
        entry.mapped_pids = []
        self.assertIn("not mapped by any process", plugin._env_note(entry))


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class LoaderTests(unittest.TestCase):
    STOCK = (
        b"\x00/etc/ld.so.cache\x00/etc/ld.so.preload\x00/proc/self/exe\x00"
        b"/lib64/\x00/usr/lib64/\x00/dev/null\x00/etc/suid-debug\x00%s/%s\x00"
    )

    def check(self, data, path="/usr/lib64/ld-2.17.so"):
        return ldpreload.LoaderCheck(
            ldpreload.RecoveredFile(path=path, inode_addr=1, data=data), "patched"
        )

    def test_string_at_difference(self):
        live = self.STOCK.replace(b"/etc/ld.so.preload", b"/etc/shadowrddoqnf")
        self.assertEqual(
            ldpreload.LdPreload._string_at_difference(live, self.STOCK), "/etc/shadowrddoqnf"
        )
        self.assertIsNone(ldpreload.LdPreload._string_at_difference(self.STOCK, self.STOCK))
        # A difference outside a string (binary code) is not a path.
        self.assertIsNone(
            ldpreload.LdPreload._string_at_difference(b"\x00\x01\x02\x03", b"\x00\x01\x02\x04")
        )

    def test_replacement_by_elimination_verified_against_cache(self):
        plugin = make_plugin()
        live = self.STOCK.replace(b"/etc/ld.so.preload", b"/etc/shadowrddoqnf")
        check = self.check(live)
        plugin._recover_replacement(check, {"/etc/shadowrddoqnf": 5, "/etc/passwd": 6})
        self.assertEqual(check.reads, "/etc/shadowrddoqnf")
        self.assertTrue(check.verified)

    def test_replacement_single_candidate_unverified(self):
        plugin = make_plugin()
        live = self.STOCK.replace(b"/etc/ld.so.preload", b"/etc/shadowrddoqnf")
        check = self.check(live)
        plugin._recover_replacement(check, {"/etc/passwd": 6})
        self.assertEqual(check.reads, "/etc/shadowrddoqnf")
        self.assertFalse(check.verified)

    def test_replacement_from_leftover_copy(self):
        live = self.STOCK.replace(b"/etc/ld.so.preload", b"/etc/shadowrddoqnf")
        artifact = ldpreload.RecoveredFile(
            path="/usr/lib64/ld-2.17.so.tmp", inode_addr=2, data=self.STOCK, kind="linker-artifact"
        )
        plugin = make_plugin(_linker_artifacts=[artifact])
        check = self.check(live)
        plugin._recover_replacement(check, {})
        self.assertEqual(check.reads, "/etc/shadowrddoqnf")
        self.assertTrue(check.verified)

    def test_ambiguous_candidates(self):
        plugin = make_plugin()
        live = self.STOCK.replace(b"/etc/ld.so.preload", b"/etc/shadowrddoqnf") + b"/opt/other\x00"
        check = self.check(live)
        plugin._recover_replacement(check, {})
        self.assertIsNone(check.reads)
        self.assertEqual(check.candidates, ["/etc/shadowrddoqnf", "/opt/other"])

    def test_adjacent_strings_are_all_seen(self):
        strings = [m.group(1) for m in ldpreload.LOADER_STRING_RE.finditer(self.STOCK)]
        self.assertEqual(
            strings,
            [b"/etc/ld.so.cache", b"/etc/ld.so.preload", b"/proc/self/exe", b"/lib64/",
             b"/usr/lib64/", b"/dev/null", b"/etc/suid-debug"],
        )

    def test_has_zero_page(self):
        zero = ldpreload.LdPreload._has_zero_page
        self.assertFalse(zero(b"x" * 8192))
        self.assertTrue(zero(b"x" * 4096 + b"\x00" * 4096))
        self.assertFalse(zero(b"x" * 4096 + b"\x00" * 4095))
        self.assertFalse(zero(b""))

    def test_zero_page_is_found_in_an_unaligned_section(self):
        # .rodata from 0x240 to 0x2800; the file page 0x1000-0x2000 inside it is
        # a hole. Chunks counted from 0x240 would each be part data, part hole.
        zero = ldpreload.LdPreload._has_zero_page
        data = b"x" * 0x1000 + b"\x00" * 0x1000 + b"z" * 0x1000
        self.assertTrue(zero(data, 0x240, 0x2800))
        # A hole outside the section does not count, a partly zero page neither.
        self.assertFalse(zero(data, 0x2000, 0x3000))
        self.assertFalse(zero(b"x" * 0x1000 + b"\x00" * 0xFFF + b"z" * 0x1001, 0x240, 0x2800))
        # Out-of-range bounds from a hostile section header are clamped.
        self.assertFalse(zero(data, 1 << 60, 1 << 61))
        self.assertTrue(zero(data, 0, 1 << 62))

    def test_truncated_or_holed_loader_is_inconclusive_not_patched(self):
        rodata = (b"\x00/etc/ld.so.cache\x00" + b"r" * 0x2000).ljust(0x3000, b"r")
        elf = build_elf([], rodata=rodata)
        # Without section headers .rodata cannot be located: a cut is undecided.
        bare = build_elf([], rodata=rodata, strip_sections=True)
        kernel = FakeKernel({7: elf})
        for label, content, truncated, expected in (
            ("whole", elf, False, "patched"),
            ("cut after a complete .rodata", elf, True, "patched"),
            ("cut, .rodata not locatable", bare, True, "inconclusive"),
        ):
            with self.subTest(label):
                plugin = kernel.plugin()

                def read(context, module, inode, path, max_size=None, limit=None):
                    self.assertEqual(limit, ldpreload.LOADER_MAX_SIZE)
                    return ldpreload.RecoveredFile(
                        path=path, inode_addr=7, data=content, truncated=truncated
                    )

                with mock.patch.object(ldpreload, "read_inode", side_effect=read), \
                        mock.patch.object(ldpreload, "vollog"):
                    (check,) = plugin._check_loaders(
                        "kernel", {"/usr/lib64/ld-2.17.so": 7}, {}
                    )
                self.assertEqual(check.state, expected)


class FakeKernel:
    """A stand-in for the kernel module: ``files`` maps inode address to content.

    ``object("inode", offset=...)`` hands out an inode that passes the smear
    check and reports the content's length as ``i_size`` unless ``sizes``
    overrides it; ``read`` replaces ``read_inode``.
    """

    layer_name = "layer"

    def __init__(self, files, sizes=None):
        self.files = files
        self.sizes = sizes or {}
        self.reads = []
        self.bounds = []

    def get_type(self, name):
        return SimpleNamespace(size=8)

    def object(self, type_name, offset, absolute=False):
        size = self.sizes.get(offset, len(self.files.get(offset, b"")))
        return SimpleNamespace(
            vol=SimpleNamespace(offset=offset), is_valid=lambda: True, i_size=size
        )

    def read(self, context, module_name, inode, path, max_size=None, limit=None):
        self.reads.append(path)
        self.bounds.append(max_size)
        return ldpreload.RecoveredFile(
            path=path, inode_addr=inode.vol.offset, data=self.files[inode.vol.offset]
        )

    def plugin(self, config=None):
        config = {"kernel": "kernel", **(config or {})}
        context = SimpleNamespace(modules={"kernel": self}, layers={"layer": SimpleNamespace()})
        return make_plugin(config, _context=context)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class CollectionTests(unittest.TestCase):
    EVIL = build_elf([("readdir", STT_FUNC, STB_GLOBAL, True)])

    def collect(self, kernel, cached, loader_checks=()):
        plugin = kernel.plugin({"no-env": True, "skip-maps": True})
        plugin.get_cached_regular_files = lambda *args: iter(cached)
        plugin._first_page_peeker = lambda *args: None
        plugin._collect_linker_artifacts = lambda *args: None
        plugin._check_loaders = lambda *args: list(loader_checks)
        with mock.patch.object(ldpreload, "read_inode", side_effect=kernel.read), \
                mock.patch.object(ldpreload, "vollog"):
            return plugin, plugin._collect()

    def test_ld_so_named_library_is_indexed_and_analysed(self):
        # A real shared object whose name starts with "ld.so." is a library: a
        # disguised preload file naming it is found and the hook is read.
        kernel = FakeKernel({1: b"/usr/lib/ld.so.evil.so\n", 2: self.EVIL, 3: b"/usr/lib\n"})
        cached = [
            ("/opt/.cfg/settings", 1),
            ("/usr/lib/ld.so.evil.so", 2),
            ("/etc/ld.so.conf", 3),
        ]
        _, entries = self.collect(kernel, cached)
        self.assertEqual(
            [(e.preload_path, e.library) for e in entries],
            [("/opt/.cfg/settings", "/usr/lib/ld.so.evil.so")],
        )
        self.assertEqual(entries[0].recovered.path, "/usr/lib/ld.so.evil.so")
        self.assertEqual(entries[0].elf.interposed(), ["readdir"])
        # The loader's own config file is neither scanned nor indexed.
        self.assertNotIn("/etc/ld.so.conf", kernel.reads)

    def test_standard_preload_resolves_ld_so_named_library(self):
        kernel = FakeKernel({1: b"/usr/lib/ld.so.evil.so\n", 2: self.EVIL})
        cached = [("/etc/ld.so.preload", 1), ("/usr/lib/ld.so.evil.so", 2)]
        _, entries = self.collect(kernel, cached)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].elf.interposed(), ["readdir"])

    def patched_loader(self):
        loader = ldpreload.RecoveredFile(path="/usr/lib64/ld-2.17.so", inode_addr=9, data=b"")
        return ldpreload.LoaderCheck(loader, "patched", reads="/etc/custom.so.1", verified=True)

    def scanned_targets(self, paths):
        """Each of ``paths`` is a cached, content-scanned preload file naming
        /lib/evil.so; returns the plugin and the loader check after _collect."""
        files = {2: self.EVIL, 9: b"\x00"}
        cached = [("/lib/evil.so", 2), ("/usr/lib64/ld-2.17.so", 9)]
        for number, path in enumerate(paths, start=10):
            files[number] = b"/lib/evil.so\n"
            cached.append((path, number))
        check = self.patched_loader()
        plugin, _ = self.collect(FakeKernel(files), cached, [check])
        return plugin, check

    def test_scanned_exact_target_is_confirmed_in_either_order(self):
        for paths in (
            ["/container/etc/custom.so.1", "/etc/custom.so.1"],
            ["/etc/custom.so.1", "/container/etc/custom.so.1"],
        ):
            with self.subTest(order=paths):
                plugin, check = self.scanned_targets(paths)
                self.assertEqual(plugin._confirmed_by, {"/etc/custom.so.1": "/usr/lib64/ld-2.17.so"})
                self.assertEqual(check.targets, ["/etc/custom.so.1"])
                self.assertFalse(check.ambiguous)

    def test_scanned_suffix_targets_are_ambiguous_not_confirmed(self):
        plugin, check = self.scanned_targets(["/a/etc/custom.so.1", "/b/etc/custom.so.1"])
        self.assertEqual(plugin._confirmed_by, {})
        self.assertTrue(check.ambiguous)
        self.assertEqual(check.targets, ["/a/etc/custom.so.1", "/b/etc/custom.so.1"])
        with mock.patch.object(ldpreload, "vollog"):
            rows = [row for _, row in plugin._generator() if row[2] == "(dynamic linker)"]
        (row,) = rows
        self.assertIn("ambiguous: matches the cached files /a/etc/custom.so.1, /b/etc/custom.so.1", row[6])
        self.assertIn("none attributed to this loader", row[6])
        self.assertNotIn("analysed above", row[6])

    def test_single_suffix_target_is_still_confirmed(self):
        # A lone container match is still the loader's target, as before.
        plugin, _ = self.scanned_targets(["/container/etc/custom.so.1"])
        self.assertEqual(plugin._confirmed_by, {"/container/etc/custom.so.1": "/usr/lib64/ld-2.17.so"})

    def content_scanned_targets(self, paths):
        """As ``scanned_targets``, but the loader reads /etc/target.conf, a name
        the content scan inspects: every one of ``paths`` is found by the scan
        itself, and the loader-target read must not be needed."""
        files = {2: self.EVIL, 9: b"\x00"}
        cached = [("/lib/evil.so", 2), ("/usr/lib64/ld-2.17.so", 9)]
        for number, path in enumerate(paths, start=10):
            files[number] = b"/lib/evil.so\n"
            cached.append((path, number))
        loader = ldpreload.RecoveredFile(path="/usr/lib64/ld-2.17.so", inode_addr=9, data=b"")
        check = ldpreload.LoaderCheck(loader, "patched", reads="/etc/target.conf", verified=False)
        kernel = FakeKernel(files)
        with mock.patch.object(
            ldpreload.LdPreload, "_read_loader_target", return_value=None
        ) as read_target:
            plugin, _ = self.collect(kernel, cached, [check])
        read_target.assert_not_called()
        self.assertEqual(
            sorted(p.path for p in plugin._preload_files if p.kind == "disguised"), sorted(paths)
        )
        return plugin, check

    def test_content_scanned_exact_target_is_confirmed_in_either_order(self):
        for paths in (
            ["/container/etc/target.conf", "/etc/target.conf"],
            ["/etc/target.conf", "/container/etc/target.conf"],
        ):
            with self.subTest(order=paths):
                plugin, check = self.content_scanned_targets(paths)
                self.assertEqual(plugin._confirmed_by, {"/etc/target.conf": "/usr/lib64/ld-2.17.so"})
                self.assertEqual(check.targets, ["/etc/target.conf"])
                self.assertFalse(check.ambiguous)
                self.assertTrue(check.verified)

    def test_content_scanned_suffix_targets_are_ambiguous_not_confirmed(self):
        for paths in (
            ["/a/etc/target.conf", "/b/etc/target.conf"],
            ["/b/etc/target.conf", "/a/etc/target.conf"],
        ):
            with self.subTest(order=paths):
                plugin, check = self.content_scanned_targets(paths)
                self.assertEqual(plugin._confirmed_by, {})
                self.assertTrue(check.ambiguous)
                self.assertFalse(check.verified)
                self.assertEqual(check.targets, paths)

    def test_content_scanned_single_suffix_target_is_confirmed(self):
        plugin, check = self.content_scanned_targets(["/container/etc/target.conf"])
        self.assertEqual(plugin._confirmed_by, {"/container/etc/target.conf": "/usr/lib64/ld-2.17.so"})
        self.assertTrue(check.verified)

    def test_loader_config_files_are_not_libraries(self):
        kernel = FakeKernel({1: b"/etc/ld.so.cache\n", 2: b"\x00" * 64})
        cached = [("/etc/ld.so.preload", 1), ("/etc/ld.so.cache", 2)]
        _, entries = self.collect(kernel, cached)
        self.assertEqual([e.library for e in entries], ["/etc/ld.so.cache"])
        self.assertIsNone(entries[0].recovered)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class LoaderTargetTests(unittest.TestCase):
    def read_target(self, kernel, wanted, cached, notes=None, read=None):
        plugin = kernel.plugin()
        # Without notes the call is the one the plugin made before the budget.
        extra = () if notes is None else (notes,)
        with mock.patch.object(ldpreload, "read_inode", side_effect=read or kernel.read), \
                mock.patch.object(ldpreload, "vollog"):
            return plugin._read_loader_target("kernel", wanted, cached, set(), *extra)

    def test_target_naming_ld_so_library_is_accepted(self):
        kernel = FakeKernel({5: b"/usr/lib/ld.so.evil.so\n"})
        target = self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5})
        self.assertIsNotNone(target)
        self.assertEqual((target.path, target.kind), ("/etc/custom.so.1", "disguised"))

    def test_exact_path_wins_in_either_enumeration_order(self):
        kernel = FakeKernel({5: b"/lib/exact.so\n", 6: b"/lib/container.so\n"})
        for cached in (
            {"/container/etc/custom.so.1": 6, "/etc/custom.so.1": 5},
            {"/etc/custom.so.1": 5, "/container/etc/custom.so.1": 6},
        ):
            with self.subTest(order=list(cached)):
                target = self.read_target(kernel, "/etc/custom.so.1", cached)
                self.assertEqual((target.path, target.data), ("/etc/custom.so.1", b"/lib/exact.so\n"))

    def test_target_paths_prefer_exact(self):
        paths = ldpreload.LdPreload._loader_target_paths
        both = {"/container/etc/x": 6, "/etc/x": 5}
        self.assertEqual(paths("/etc/x", both), ["/etc/x"])
        self.assertEqual(paths("/etc/x", dict(reversed(list(both.items())))), ["/etc/x"])
        self.assertEqual(paths("/etc/x", {"/b/etc/x": 2, "/a/etc/x": 1}), ["/b/etc/x", "/a/etc/x"])
        self.assertEqual(paths("/etc/x", {"/etc/xy": 1}), [])

    def test_several_suffix_targets_are_not_picked(self):
        kernel = FakeKernel({5: b"/lib/a.so\n", 6: b"/lib/b.so\n"})
        cached = {"/a/etc/custom.so.1": 5, "/b/etc/custom.so.1": 6}
        self.assertIsNone(self.read_target(kernel, "/etc/custom.so.1", cached))
        self.assertEqual(kernel.reads, [])

    def test_ambiguity_note(self):
        kernel = FakeKernel({5: b"/lib/a.so\n", 6: b"/lib/b.so\n"})
        notes = []
        cached = {"/a/etc/custom.so.1": 5, "/b/etc/custom.so.1": 6}
        self.read_target(kernel, "/etc/custom.so.1", cached, notes)
        self.assertEqual(len(notes), 1)
        self.assertIn("loader target /etc/custom.so.1 is ambiguous", notes[0])
        self.assertIn("/a/etc/custom.so.1, /b/etc/custom.so.1", notes[0])

    def test_aliases_of_one_inode_are_not_ambiguous(self):
        kernel = FakeKernel({5: b"/lib/a.so\n"})
        cached = {"/a/etc/custom.so.1": 5, "/b/etc/custom.so.1": 5}
        target = self.read_target(kernel, "/etc/custom.so.1", cached)
        self.assertEqual(target.path, "/a/etc/custom.so.1")

    def test_name_only_target_is_not_analysed(self):
        # Known limitation (review F4, unchanged): a loader target still has to
        # pass the content scan's test, which wants absolute .so paths, so a
        # bare library name -- valid preload syntax -- is not analysed. This
        # pins the current behaviour; changing it is a separate decision.
        kernel = FakeKernel({5: b"libevil.so\n"})
        self.assertIsNone(self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5}))
        self.assertEqual(kernel.reads, ["/etc/custom.so.1"])

    def test_target_above_scan_limit_within_budget_is_read(self):
        data = b"/lib/evil.so\n" + b"#" * (2 * ldpreload.PRELOAD_SCAN_MAX_SIZE) + b"\n"
        kernel = FakeKernel({5: data})
        target = self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5})
        self.assertIsNotNone(target)
        # The read is held to the size checked against the budget.
        self.assertEqual(kernel.bounds, [len(data)])

    def test_oversized_sparse_target_is_not_read(self):
        # A 1 TiB inode: refused on its size, before any page is read.
        kernel = FakeKernel({5: b"/lib/evil.so\n"}, sizes={5: 1 << 40})
        target = self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5})
        self.assertIsNone(target)
        self.assertEqual(kernel.reads, [])

    def test_negative_size_target_is_not_read(self):
        kernel = FakeKernel({5: b"/lib/evil.so\n"}, sizes={5: -1})
        self.assertIsNone(self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5}))
        self.assertEqual(kernel.reads, [])

    def test_memory_error_while_reading_is_caught(self):
        kernel = FakeKernel({5: b"/lib/evil.so\n"})
        read = mock.Mock(side_effect=MemoryError)
        target = self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5}, read=read)
        self.assertIsNone(target)
        read.assert_called_once()

    def test_budget_and_memory_notes(self):
        # The budget is the loader target's own, above the content scan's gate.
        self.assertGreater(ldpreload.LOADER_TARGET_MAX_SIZE, ldpreload.PRELOAD_SCAN_MAX_SIZE)
        cached = {"/etc/custom.so.1": 5}
        notes = []
        kernel = FakeKernel({5: b"/lib/evil.so\n"}, sizes={5: 1 << 40})
        self.read_target(kernel, "/etc/custom.so.1", cached, notes)
        self.assertEqual(len(notes), 1)
        self.assertIn("loader target /etc/custom.so.1 not analysed (incomplete)", notes[0])
        self.assertIn(str(1 << 40), notes[0])
        self.assertIn(str(ldpreload.LOADER_TARGET_MAX_SIZE), notes[0])
        notes = []
        kernel = FakeKernel({5: b"/lib/evil.so\n"})
        self.read_target(kernel, "/etc/custom.so.1", cached, notes, read=mock.Mock(side_effect=MemoryError))
        self.assertEqual(len(notes), 1)
        self.assertIn("not analysed (incomplete): out of memory", notes[0])

    def test_budget_note_reaches_the_loader_row(self):
        loader = ldpreload.RecoveredFile(path="/usr/lib64/ld-2.17.so", inode_addr=1, data=b"")
        check = ldpreload.LoaderCheck(loader, "patched", reads="/etc/custom.so.1", verified=True)
        kernel = FakeKernel({5: b"/lib/evil.so\n", 6: b"\x00"}, sizes={5: 1 << 40})
        plugin = kernel.plugin({"no-env": True, "skip-maps": True})
        plugin.get_cached_regular_files = lambda *args: iter(
            [("/etc/custom.so.1", 5), ("/usr/lib64/ld-2.17.so", 6)]
        )
        plugin._first_page_peeker = lambda *args: None
        plugin._collect_linker_artifacts = lambda *args: None
        plugin._check_loaders = lambda *args: [check]
        with mock.patch.object(ldpreload, "read_inode", side_effect=kernel.read), \
                mock.patch.object(ldpreload, "vollog"):
            rows = list(plugin._generator())
        self.assertEqual(kernel.reads, [])
        (row,) = rows
        self.assertEqual(len(row[1]), 7)
        self.assertIn("cached but could not be analysed", row[1][6])
        self.assertIn("loader target /etc/custom.so.1 not analysed (incomplete)", row[1][6])


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class BoundedReadTests(unittest.TestCase):
    def test_bounded_buffer_refuses_to_grow(self):
        buffer = ldpreload._BoundedBuffer(8192)
        buffer.truncate(8192)
        buffer.seek(4096)
        buffer.write(b"x" * 4096)
        self.assertEqual(len(buffer.getvalue()), 8192)
        with self.assertRaises(ldpreload.ReadBudgetExceeded):
            buffer.seek(1 << 40)
        with self.assertRaises(ldpreload.ReadBudgetExceeded):
            buffer.write(b"y")  # at 8192: one byte past the bound
        with self.assertRaises(ldpreload.ReadBudgetExceeded):
            buffer.truncate(1 << 40)
        self.assertEqual(len(buffer.getvalue()), 8192)

    def test_read_inode_places_nothing_beyond_i_size(self):
        # A sparse page far past i_size is dropped without allocating up to it,
        # whichever reader (framework or its own bound) rejects it.
        pages = [(0, b"/lib/evil.so\n".ljust(4096, b"\x00")), (1 << 28, b"x" * 4096)]
        inode = SimpleNamespace(
            is_reg=True,
            i_size=8192,
            get_contents=lambda: iter(pages),
            vol=SimpleNamespace(offset=0x1000),
            get_modification_time=lambda: None,
            get_change_time=lambda: None,
        )
        context = SimpleNamespace(
            modules={"kernel": SimpleNamespace(layer_name="layer")},
            layers={"layer": SimpleNamespace(page_size=4096)},
        )
        with mock.patch.object(ldpreload.pagecache, "vollog"):
            recovered = ldpreload.read_inode(context, "kernel", inode, "/etc/x")
        self.assertLessEqual(len(recovered.data), 8192)
        self.assertTrue(recovered.data.startswith(b"/lib/evil.so\n"))

    def test_compat_reader_places_nothing_beyond_size(self):
        offsets = {1: 0, 2: 4096 - 100, 3: 1 << 40}
        pages = SimpleNamespace(
            page_size=1,  # index_of() already yields byte offsets here
            belongs_to=lambda page, mapping: True,
            index_of=lambda page: offsets[page],
            content=lambda page: bytes([0x40 + page]) * 4096,
        )
        storage = SimpleNamespace(get_entries=lambda root: iter([1, 2, 3]))
        inode = SimpleNamespace(i_mapping=mock.MagicMock())
        inode.i_mapping.__int__.return_value = 0x2000
        inode.i_mapping.dereference.return_value = SimpleNamespace(i_pages="root")
        with mock.patch.object(ldpreload, "_page_layout", return_value=pages), \
                mock.patch.object(
                    ldpreload.linux_symbols.IDStorage,
                    "choose_id_storage",
                    return_value=storage,
                ):
            data = ldpreload._read_pages_compat(None, "kernel", inode, 4096)
        # Page 2 is cut at the size, page 3 (at 1 TiB) is skipped.
        self.assertEqual(len(data), 4096)
        self.assertEqual(data[-100:], b"B" * 100)

    def test_bounded_buffer_refuses_negative_and_end_relative_positions(self):
        buffer = ldpreload._BoundedBuffer(8)
        buffer.write(b"abcd")
        for offset, whence in ((-1, 0), (-5, 1), (-5, 2), (5, 2), (1 << 40, 1), (1 << 40, 2)):
            with self.subTest(offset=offset, whence=whence):
                with self.assertRaises(ldpreload.ReadBudgetExceeded):
                    buffer.seek(offset, whence)
                self.assertEqual(buffer.tell(), 4)
        with self.assertRaises(ldpreload.ReadBudgetExceeded):
            buffer.truncate(-1)
        self.assertEqual(buffer.seek(4, 2), 8)
        self.assertEqual(buffer.seek(-8, 1), 0)
        self.assertEqual(buffer.getvalue(), b"abcd")


def fake_inode(i_size=32):
    return SimpleNamespace(
        i_size=i_size,
        is_valid=lambda: True,
        vol=SimpleNamespace(offset=5),
        get_modification_time=lambda: None,
        get_change_time=lambda: None,
    )


def compat_pages(offsets):
    """Patches for ``_read_pages_compat``: page ``n`` of the inode's tree sits at
    byte offset ``offsets[n]`` and holds 4096 bytes."""
    pages = SimpleNamespace(
        page_size=1,
        belongs_to=lambda page, mapping: True,
        index_of=lambda page: offsets[page],
        content=lambda page: b"/lib/evil.so\n".ljust(4096, b"\x00"),
    )
    storage = SimpleNamespace(get_entries=lambda root: iter(offsets))
    return (
        mock.patch.object(ldpreload, "_page_layout", return_value=pages),
        mock.patch.object(
            ldpreload.linux_symbols.IDStorage, "choose_id_storage", return_value=storage
        ),
    )


def compat_inode(i_size=32):
    inode = fake_inode(i_size)
    inode.i_mapping = mock.MagicMock()
    inode.i_mapping.__int__.return_value = 0x2000
    inode.i_mapping.dereference.return_value = SimpleNamespace(i_pages="root")
    return inode


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class LoaderTargetBoundTests(unittest.TestCase):
    """The loader-target budget held through the real ``read_inode``, with the
    framework's page writer and the compatibility reader mocked."""

    WANTED = "/etc/target.conf"

    def read_target(self, inode, write, compat=None):
        context = SimpleNamespace(
            modules={"kernel": SimpleNamespace(layer_name="layer", object=lambda *a, **k: inode)}
        )
        plugin = make_plugin(_context=context)
        notes = []
        patches = [
            mock.patch.object(
                ldpreload.pagecache.InodePages, "write_inode_content_to_stream", side_effect=write
            ),
            mock.patch.object(ldpreload, "vollog"),
        ]
        if compat is not None:
            patches.append(mock.patch.object(ldpreload, "_read_pages_compat", compat))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            target = plugin._read_loader_target(
                "kernel", self.WANTED, {self.WANTED: 5}, set(), notes
            )
        return target, notes

    def assertIncomplete(self, target, notes, reason):
        self.assertIsNone(target)
        self.assertEqual(len(notes), 1)
        self.assertIn(f"loader target {self.WANTED} not analysed (incomplete)", notes[0])
        self.assertIn(reason, notes[0])

    def test_sparse_page_after_valid_content_is_incomplete(self):
        # Valid preload bytes first, then a page at 1 TiB: the bytes read so far
        # are not taken as the target, and nothing falls back to an unbounded read.
        def write(context, layer, inode, stream):
            stream.write(b"/lib/evil.so\n")
            stream.seek(1 << 40)

        compat = mock.Mock(return_value=b"/lib/evil.so\n")
        target, notes = self.read_target(fake_inode(), write, compat)
        self.assertIncomplete(target, notes, f"offset {1 << 40} is outside the 32-byte read bound")
        compat.assert_not_called()

    def test_negative_offset_is_incomplete(self):
        def write(context, layer, inode, stream):
            stream.write(b"/lib/evil.so\n")
            stream.seek(-4096, 1)

        target, notes = self.read_target(fake_inode(), write, mock.Mock())
        self.assertIncomplete(target, notes, "offset -4083 is outside")

    def test_i_size_grown_after_the_check_is_incomplete(self):
        # The bound is the size checked against the budget, not a later i_size.
        def write(context, layer, inode, stream):
            inode.i_size = 1 << 40
            stream.truncate(inode.i_size)

        target, notes = self.read_target(fake_inode(), write, mock.Mock())
        self.assertIncomplete(target, notes, "outside the 32-byte read bound")

    def test_compat_reader_gets_the_checked_bound(self):
        # An i_size unreadable by the time of the retry neither fails nor
        # unbounds the compatibility read: it gets the checked size, strictly.
        def write(context, layer, inode, stream):
            del inode.i_size
            raise AttributeError("page.mapping")

        inode = fake_inode()
        compat = mock.Mock(return_value=b"/lib/evil.so\n")
        target, notes = self.read_target(inode, write, compat)
        compat.assert_called_once_with(mock.ANY, "kernel", inode, 32, strict=True)
        self.assertEqual((target.data, notes), (b"/lib/evil.so\n", []))

    def test_compat_page_outside_bound_is_incomplete(self):
        layout, storage = compat_pages({1: 0, 2: 1 << 40})
        with layout, storage:
            target, notes = self.read_target(
                compat_inode(), mock.Mock(side_effect=AttributeError("page.mapping"))
            )
        self.assertIncomplete(target, notes, f"page at offset {1 << 40} is outside the 32-byte")

    def test_memory_error_in_compat_reader_is_incomplete(self):
        target, notes = self.read_target(
            fake_inode(),
            mock.Mock(side_effect=AttributeError("page.mapping")),
            mock.Mock(side_effect=MemoryError),
        )
        self.assertIncomplete(target, notes, "out of memory")

    def test_unbounded_read_keeps_its_fallback(self):
        # Without max_size, read_inode behaves as before: a rejected framework
        # read is retried by the compatibility reader with i_size, leniently.
        def write(context, layer, inode, stream):
            stream.write(b"/lib")
            stream.seek(1 << 40)

        inode = fake_inode()
        context = SimpleNamespace(modules={"kernel": SimpleNamespace(layer_name="layer")})
        compat = mock.Mock(return_value=b"/lib/evil.so\n")
        with mock.patch.object(
            ldpreload.pagecache.InodePages, "write_inode_content_to_stream", side_effect=write
        ), mock.patch.object(ldpreload, "_read_pages_compat", compat), \
                mock.patch.object(ldpreload, "vollog"):
            recovered = ldpreload.read_inode(context, "kernel", inode, "/etc/x")
        compat.assert_called_once_with(context, "kernel", inode, 32, strict=False)
        self.assertEqual(recovered.data, b"/lib/evil.so\n")

    def test_strict_compat_reader_raises_lenient_one_skips(self):
        layout, storage = compat_pages({1: 0, 2: 1 << 40})
        with layout, storage:
            data = ldpreload._read_pages_compat(None, "kernel", compat_inode(), 32)
            with self.assertRaises(ldpreload.ReadBudgetExceeded):
                ldpreload._read_pages_compat(None, "kernel", compat_inode(), 32, strict=True)
        self.assertEqual(data, b"/lib/evil.so\n".ljust(32, b"\x00"))


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class NamePatternTests(unittest.TestCase):
    def test_glibc_loader_names(self):
        match = ldpreload.GLIBC_LOADER_RE.match
        for name in (
            "ld-linux-x86-64.so.2",
            "ld-linux.so.2",
            "ld-linux-aarch64.so.1",
            "ld-linux-armhf.so.3",
            "ld-2.17.so",
            "ld-2.28.so",
            "ld64.so.1",
            "ld.so.1",
        ):
            self.assertTrue(match(name), name)
        for name in ("ld-musl-x86_64.so.1", "ld.so.cache", "ld.so.conf", "libc.so.6", "ld-2.17.so.tmp"):
            self.assertFalse(match(name), name)

    def test_linker_artifact_names(self):
        match = ldpreload.LINKER_ARTIFACT_RE.match
        for name in (
            "ld-2.17.so.tmp",
            "ld-linux-x86-64.so.2.bak",
            "ld-linux-x86-64.so.2.orig",
            "ld-2.28.so~",
            "ld.so.1.old",
            "ld-linux-x86-64.so.2.12345",
        ):
            self.assertTrue(match(name), name)
        for name in ("ld.so.conf.bak", "ld.so.cache~", "ld-2.17.so", "ld-linux-x86-64.so.2", "ld.so.conf.d"):
            self.assertFalse(match(name), name)

    def test_benign_preload_names(self):
        match = ldpreload.BENIGN_PRELOAD_RE.match
        for name in ("libasan.so.8", "libjemalloc.so.2", "libfakeroot-sysv.so", "libeatmydata.so", "libtcmalloc_minimal.so.4", "libclang_rt.asan-x86_64.so"):
            self.assertTrue(match(name), name)
        for name in ("libselinux.so.3", "evil.so", "libdlwrapper.so", "libasan.so.8.txt", "libjemalloc.so.evil"):
            self.assertFalse(match(name), name)

    def test_so_token(self):
        search = ldpreload.SO_TOKEN_RE.search
        for name in ("a.so", "a.so.1", "a.so.1.2.3", "a.so.$PLATFORM", "libc.so.6"):
            self.assertTrue(search(name), name)
        for name in ("a.so.d/x", "a.sock", "a.so/", "readme"):
            self.assertFalse(search(name), name)

    def test_interposed_set_covers_the_classic_hooks(self):
        for name in ("readdir", "readdir64", "__xstat", "getdents64", "pam_authenticate", "accept", "pcap_loop", "dlsym"):
            self.assertIn(name, ldpreload.INTERPOSED_LIBC_FUNCTIONS)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class RenderingTests(unittest.TestCase):
    def test_format_pids(self):
        fmt = ldpreload.LdPreload._format_pids
        self.assertEqual(fmt([1]), "1")
        self.assertEqual(fmt([1, 2, 3]), "1-3")
        self.assertEqual(fmt([1, 549, 571, 685, 686, 687, 688, 700]), "1, 549, 571, 685-688, 700")
        self.assertEqual(fmt([5, 7]), "5, 7")

    def test_timestamp_note(self):
        note = ldpreload.LdPreload._timestamp_note
        base = datetime.datetime(2026, 7, 10, 6, 26, 1, tzinfo=datetime.timezone.utc)
        self.assertEqual(note("x", base, base + datetime.timedelta(seconds=30)), "")
        self.assertEqual(note("x", None, base), "")
        self.assertEqual(note("x", base, None), "")
        text = note("library", base, base + datetime.timedelta(minutes=14))
        self.assertTrue(text.startswith("library changed at 2026-07-10 06:40:01 UTC"))

    def test_wrap_only_when_a_limit_is_set(self):
        plugin = make_plugin()
        plugin._limit = 0
        self.assertEqual(plugin._wrap("a, " * 40, 48), "a, " * 40)
        plugin._limit = 20
        folded = plugin._wrap("alpha beta gamma delta epsilon zeta eta theta", 48)
        self.assertTrue(folded.startswith("\n"))
        for line in folded.split("\n")[1:]:
            self.assertEqual(len(line), 20)
            self.assertLessEqual(len(line.rstrip()), 20)
        self.assertEqual(plugin._wrap("short", 48), "short")


@contextlib.contextmanager
def deadline(seconds):
    """Fails the enclosed block instead of letting it run on: a regex that
    backtracks catastrophically would otherwise hang the suite, not fail it."""
    if not hasattr(signal, "SIGALRM"):  # pragma: no cover - not on Windows
        yield
        return

    def expired(signum, frame):
        raise AssertionError(f"still running after {seconds} s")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class HostileInputTests(unittest.TestCase):
    """Patterns and parsers fed with what a user of the imaged system controls:
    file content, file names and environment values."""

    def test_so_token_does_not_backtrack_exponentially(self):
        # One line of a 4 KiB file anywhere in the page cache.
        content = b"/x.so" + b".a" * 1000 + b"/z\n"
        with deadline(10):
            self.assertFalse(ldpreload.LdPreload._looks_like_preload(content))
            self.assertFalse(ldpreload.SO_TOKEN_RE.search(".so" * 1300 + "/"))

    def test_token_matcher_agrees_with_the_regex_it_replaces(self):
        def reference(name):
            parts, last = [], 0
            for match in ldpreload.DYNAMIC_TOKEN_RE.finditer(name):
                parts.append(re.escape(name[last : match.start()]))
                parts.append(r"[^/]+")
                last = match.end()
            parts.append(re.escape(name[last:]))
            return re.compile("".join(parts) + r"\Z")

        rng = random.Random(1707)
        pieces = ["$LIB", "${PLATFORM}", "$ORIGIN", "/", "a", "b", ".", "ab", "/a"]
        checked = matched = 0
        for _ in range(4000):
            name = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 6)))
            if name.count("$") > ldpreload._TokenSuffixMatcher.MAX_TOKENS:
                continue
            path = "".join(rng.choice("ab./") for _ in range(rng.randint(0, 9)))
            expected = bool(reference(name).search(path))
            got = ldpreload.LdPreload._token_suffix_regex(name).search(path)
            self.assertEqual(got, expected, (name, path))
            checked += 1
            matched += expected
        self.assertGreater(matched, 100)
        self.assertGreater(checked - matched, 100)

    def test_many_tokens_do_not_backtrack(self):
        plugin = make_plugin()
        long_name = "/usr/lib64/" + "a" * 60 + ".so"
        dotted = "/usr/lib64/" + "a." * 40 + "so"
        libraries = {long_name: 1, dotted: 2}
        with deadline(10):
            # Adjacent tokens, as LD_PRELOAD='/lib64/$LIB$LIB...X.so' sets them.
            for count in (8, 14, 40):
                name = "/lib64/" + "$LIB" * count + "X.so"
                self.assertIsNone(plugin._lookup(name, libraries), count)
            # Tokens between literals that also occur inside what a token spans.
            name = "/lib64/" + ".".join(["$LIB"] * 8) + ".X"
            self.assertIsNone(plugin._lookup(name, libraries))
            self.assertEqual(
                plugin._lookup("/lib64/" + "$LIB." * 7 + "$LIB.so", {dotted: 2}), (dotted, 2)
            )
        # More tokens than any real path has are not matched at all.
        matcher = ldpreload.LdPreload._token_suffix_regex("/" + "$LIB" * 9)
        self.assertFalse(matcher.search("/aaaaaaaaaaaa"))

    def test_symbol_name_search_is_bounded(self):
        # A string table without terminators is not searched to its end for
        # every one of up to 65536 symbols.
        data = b"\x7fELF" + b"A" * 20000 + b"\x00"
        name = ldpreload.ElfReader._string_at(data, 4, len(data) - 4, 1)
        self.assertLessEqual(len(name), ldpreload.ELF_NAME_MAX)

    def test_name_read_length_is_capped_at_a_file_name(self):
        length = ldpreload.LdPreload._name_read_len
        self.assertEqual(length({b"evil.so", b"libfoo.so.1"}), 12)
        # A 100 KiB "basename" from an environment value.
        self.assertEqual(length({b"x" * 100000, b"evil.so"}), 256)

    def test_task_list_failing_midway_ends_the_walk_with_a_warning(self):
        def tasks(*args, **kwargs):
            raise ldpreload.exceptions.InvalidAddressException("layer", 0xDEAD, "smeared")
            yield  # pragma: no cover - makes this a generator

        with mock.patch.object(ldpreload.pslist.PsList, "list_tasks", tasks), \
                self.assertLogs(ldpreload.vollog, "WARNING") as logs:
            self.assertEqual(list(ldpreload.LdPreload.get_superblocks(None, "kernel")), [])
        # Said once, with what was being walked and the error that ended it.
        (message,) = logs.output
        self.assertIn("task list was aborted", message)
        self.assertIn("smeared", message)
        self.assertIn("incomplete", message)

    def test_aborted_iteration_keeps_what_came_before_and_warns_once(self):
        def items():
            yield 1
            yield 2
            raise AttributeError("no such member")

        with self.assertLogs(ldpreload.vollog, "WARNING") as logs:
            self.assertEqual(list(ldpreload.LdPreload._safe_iter(items(), "mount list")), [1, 2])
        self.assertEqual(len(logs.output), 1)
        self.assertIn("mount list", logs.output[0])
        self.assertIn("no such member", logs.output[0])
        # A walk that simply ends says nothing.
        with mock.patch.object(ldpreload, "vollog") as log:
            self.assertEqual(list(ldpreload.LdPreload._safe_iter(iter([1]))), [1])
        log.warning.assert_not_called()


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ElfCompletenessTests(unittest.TestCase):
    HOOK = [("readdir", STT_FUNC, STB_GLOBAL, True)]

    def test_complete_symbol_table(self):
        info = ldpreload.ElfReader.parse(build_elf(self.HOOK))
        self.assertFalse(info.incomplete)
        self.assertFalse(ldpreload.ElfReader.parse(build_elf([])).incomplete)

    def test_stripped_or_missing_section_table_is_incomplete(self):
        # Without a dynamic segment (or with its headers past the recovered
        # content) the section headers are all there is.
        for label, data in (
            ("no section headers", build_elf(self.HOOK, strip_sections=True, dynamic=False)),
            ("headers not cached", build_elf(self.HOOK, truncate_at=200)),
            ("bad entry size", build_elf(self.HOOK, shentsize=0, dynamic=False)),
        ):
            with self.subTest(label):
                info = ldpreload.ElfReader.parse(data)
                self.assertTrue(info.valid)
                self.assertEqual(info.exported, [])
                self.assertTrue(info.incomplete)

    def test_symbols_beyond_the_parse_cap_are_incomplete(self):
        # 65536 fillers first, the hook after them.
        symbols = [("f", STT_FUNC, STB_LOCAL, True)] * 65536 + self.HOOK
        info = ldpreload.ElfReader.parse(build_elf(symbols))
        self.assertEqual(info.interposed(), [])
        self.assertTrue(info.incomplete)

    def test_uncached_symbol_or_string_page_is_incomplete(self):
        # 400 fillers push the hook's symbol and name past the first file page;
        # .dynstr starts at 64, .dynsym right after it.
        symbols = [(f"filler{n:04}", STT_FUNC, STB_LOCAL, True) for n in range(400)]
        data = build_elf(symbols + self.HOOK)
        self.assertEqual(ldpreload.ElfReader.parse(data).interposed(), ["readdir"])
        for label, page in (("string table", 0x1000), ("symbol table", 0x2000)):
            with self.subTest(label):
                holed = data[:page] + b"\x00" * 0x1000 + data[page + 0x1000 :]
                self.assertTrue(ldpreload.ElfReader.parse(holed).incomplete)

    def rows(self, elf, env_var=""):
        path = "/usr/lib64/libquiet.so"
        entry = ldpreload.PreloadEntry(
            preload_path=env_var or "/etc/ld.so.preload",
            library=path,
            env_var=env_var,
            env_pids={100: "bash"} if env_var else {},
            recovered=ldpreload.RecoveredFile(path=path, inode_addr=1, data=b"\x7fELF"),
            elf=elf,
        )
        plugin = make_plugin({"skip-maps": True}, _entries=[entry])
        return [row for _, row in plugin._generator()]

    def test_unknown_overrides_are_not_rendered_as_none(self):
        na = ldpreload.renderers.NotAvailableValue
        nap = ldpreload.renderers.NotApplicableValue
        (row,) = self.rows(
            ldpreload.ElfReader.parse(build_elf(self.HOOK, strip_sections=True, dynamic=False))
        )
        self.assertIsInstance(row[4], na)
        self.assertIn("symbol table not fully readable", row[6])
        self.assertIn("unknown", row[6])
        # A fully read table without a known hook still says "none".
        helper = [("helper", STT_FUNC, STB_GLOBAL, True)]
        (row,) = self.rows(ldpreload.ElfReader.parse(build_elf(helper)))
        self.assertIsInstance(row[4], nap)
        self.assertIsInstance(row[6], nap)

    def test_read_note_reaches_the_library_row(self):
        path = "/usr/lib64/libquiet.so"
        entry = ldpreload.PreloadEntry(
            preload_path="/etc/ld.so.preload",
            library=path,
            recovered=ldpreload.RecoveredFile(
                path=path, inode_addr=1, data=b"", note=f"{path} not read: out of memory"
            ),
        )
        plugin = make_plugin({"skip-maps": True}, _entries=[entry])
        ((_, row),) = plugin._generator()
        self.assertIn("not read: out of memory", row[6])


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ReadBudgetTests(unittest.TestCase):
    """The lenient budget of an ordinary ``read_inode`` (no ``max_size``)."""

    CONTEXT = SimpleNamespace(modules={"kernel": SimpleNamespace(layer_name="layer")})

    def read(self, inode, write, compat=None, **kwargs):
        compat = compat or mock.Mock(return_value=b"")
        with mock.patch.object(
            ldpreload.pagecache.InodePages, "write_inode_content_to_stream", side_effect=write
        ), mock.patch.object(ldpreload, "_read_pages_compat", compat), \
                mock.patch.object(ldpreload, "vollog"):
            return ldpreload.read_inode(self.CONTEXT, "kernel", inode, "/tmp/x.so", **kwargs), compat

    @staticmethod
    def framework_write(context, layer, inode, stream):
        # What the framework's writer does with a page at the end of the file.
        stream.truncate(inode.i_size)
        stream.seek(inode.i_size - 4096)
        stream.write(b"x" * 4096)

    def test_sparse_file_above_the_budget_is_read_up_to_it(self):
        # 1 TiB declared, one cached page at its very end: without a budget the
        # buffer would be zero filled up to that page.
        inode = fake_inode(i_size=1 << 40)
        compat = mock.Mock(return_value=b"\x7fELF")
        recovered, compat = self.read(inode, self.framework_write, compat, limit=1 << 16)
        compat.assert_called_once_with(self.CONTEXT, "kernel", inode, 1 << 16, strict=False)
        self.assertEqual(recovered.data, b"\x7fELF")
        self.assertTrue(recovered.truncated)
        self.assertIn(f"only the first {1 << 16} of {1 << 40} bytes", recovered.note)

    def test_default_budget_applies_without_an_explicit_limit(self):
        inode = fake_inode(i_size=ldpreload.FILE_READ_MAX_SIZE + 1)
        recovered, compat = self.read(inode, self.framework_write)
        self.assertEqual(compat.call_args[0][3], ldpreload.FILE_READ_MAX_SIZE)
        self.assertTrue(recovered.truncated)

    def test_file_within_the_budget_is_not_truncated(self):
        inode = fake_inode(i_size=8192)
        recovered, compat = self.read(inode, self.framework_write, limit=1 << 16)
        compat.assert_not_called()
        self.assertEqual(len(recovered.data), 8192)
        self.assertFalse(recovered.truncated)
        self.assertEqual(recovered.note, "")

    def test_unreadable_size_is_still_bounded(self):
        inode = fake_inode()
        del inode.i_size

        def write(context, layer, inode, stream):
            stream.seek(1 << 40)

        recovered, compat = self.read(inode, write, limit=1 << 16)
        compat.assert_called_once_with(self.CONTEXT, "kernel", inode, 1 << 16, strict=False)
        self.assertEqual(recovered.data, b"")

    def test_out_of_memory_is_reported_not_raised(self):
        for label, write, compat in (
            ("framework reader", mock.Mock(side_effect=MemoryError), None),
            (
                "compatibility reader",
                mock.Mock(side_effect=AttributeError("page.mapping")),
                mock.Mock(side_effect=MemoryError),
            ),
        ):
            with self.subTest(label):
                recovered, _ = self.read(fake_inode(), write, compat)
                self.assertEqual(recovered.data, b"")
                self.assertIn("out of memory", recovered.note)

    def test_unusable_timestamps_become_none(self):
        # The framework hands back an absent-value object for a time it cannot
        # convert -- the epoch itself, as `touch -d @0` sets it, included -- and
        # raises on an inode layout it does not know. Either used to reach
        # `ctime - mtime` and the timeliner as if it were a datetime.
        stamp = datetime.datetime(2026, 7, 10, tzinfo=datetime.timezone.utc)

        def unsupported():
            raise ldpreload.exceptions.VolatilityException("Unsupported kernel inode type")

        inode = fake_inode()
        inode.get_modification_time = ldpreload.renderers.UnparsableValue
        inode.get_change_time = lambda: stamp
        recovered, _ = self.read(inode, lambda *args: None)
        self.assertIsNone(recovered.modification_time)
        self.assertEqual(recovered.change_time, stamp)
        self.assertEqual(
            ldpreload.LdPreload._timestamp_note(
                "library", recovered.modification_time, recovered.change_time
            ),
            "",
        )
        inode.get_change_time = unsupported
        recovered, _ = self.read(inode, lambda *args: None)
        self.assertIsNone(recovered.change_time)

    def test_callers_pass_their_budgets(self):
        kernel = FakeKernel({1: b"/lib/evil.so\n", 2: b"\x7fELF"})
        limits = {}

        def read(context, module, inode, path, max_size=None, limit=None):
            limits[path] = limit
            return kernel.read(context, module, inode, path)

        plugin = kernel.plugin({"no-env": True, "skip-maps": True, "no-scan": True})
        plugin.get_cached_regular_files = lambda *args: iter(
            [("/etc/ld.so.preload", 1), ("/lib/evil.so", 2)]
        )
        with mock.patch.object(ldpreload, "read_inode", side_effect=read), \
                mock.patch.object(ldpreload, "vollog"):
            plugin._collect()
            plugin._collect_linker_artifacts("kernel", [("/lib/ld-2.17.so.tmp", 2)])
        self.assertEqual(limits["/etc/ld.so.preload"], ldpreload.PRELOAD_FILE_MAX_SIZE)
        self.assertEqual(limits["/lib/ld-2.17.so.tmp"], ldpreload.LOADER_MAX_SIZE)
        self.assertEqual(limits["/lib/evil.so"], ldpreload.FILE_READ_MAX_SIZE)

    def test_truncated_scan_candidate_is_not_a_preload_file(self):
        kernel = FakeKernel({1: b"/lib/evil.so\n"})
        plugin = kernel.plugin()
        plugin._first_page_peeker = lambda *args: None

        def read(context, module, inode, path, max_size=None, limit=None):
            self.assertEqual(limit, ldpreload.PRELOAD_SCAN_MAX_SIZE)
            return ldpreload.RecoveredFile(
                path=path, inode_addr=1, data=b"/lib/evil.so\n", truncated=True
            )

        found = []
        with mock.patch.object(ldpreload, "read_inode", side_effect=read), \
                mock.patch.object(ldpreload, "vollog"):
            plugin._scan_disguised_preloads("kernel", [("/var/big.log", 1)], found, set())
        self.assertEqual(found, [])

    def test_unreadable_size_is_noted_and_truncated_when_the_budget_is_filled(self):
        limit = 1 << 16
        for label, written, truncated in (
            ("fills the budget", limit, True),
            ("ends within the budget", 4096, False),
        ):
            with self.subTest(label):
                inode = fake_inode()
                del inode.i_size
                recovered, _ = self.read(
                    inode, lambda c, l, i, stream: stream.write(b"x" * written), limit=limit
                )
                self.assertEqual(len(recovered.data), written)
                self.assertEqual(recovered.truncated, truncated)
                self.assertIn("size of /tmp/x.so unreadable", recovered.note)
        # A readable size leaves the note empty, as before.
        recovered, _ = self.read(fake_inode(8192), self.framework_write, limit=limit)
        self.assertEqual((recovered.truncated, recovered.note), (False, ""))

    def test_scan_candidate_of_unreadable_size_is_not_a_preload_file(self):
        # Through the real read_inode: preload content filling the scan budget
        # of a file whose size is unknown is cut off, not complete.
        content = b"/lib/evil.so\n".ljust(ldpreload.PRELOAD_SCAN_MAX_SIZE, b"\n")
        self.assertTrue(ldpreload.LdPreload._looks_like_preload(content))
        kernel = FakeKernel({1: content}, sizes={1: None})
        plugin = kernel.plugin()
        plugin._first_page_peeker = lambda *args: None
        found = []
        with mock.patch.object(
            ldpreload.pagecache.InodePages,
            "write_inode_content_to_stream",
            side_effect=lambda c, l, i, stream: stream.write(content),
        ), mock.patch.object(ldpreload, "vollog"):
            plugin._scan_disguised_preloads("kernel", [("/var/x.log", 1)], found, set())
        self.assertEqual(found, [])
        self.assertEqual(plugin._read_total, 0)


def budget_read(kernel):
    """A ``read_inode`` stand-in that honours ``limit`` the way the real one
    does: the content up to it, ``truncated`` and a note if the file is longer."""

    def read(context, module_name, inode, path, max_size=None, limit=None):
        kernel.reads.append(path)
        kernel.bounds.append(limit)
        data = kernel.files[inode.vol.offset]
        cut = len(data) > limit
        return ldpreload.RecoveredFile(
            path=path,
            inode_addr=inode.vol.offset,
            data=data[:limit],
            truncated=cut,
            note=f"only the first {limit} of {len(data)} bytes of {path} were read "
            "(read budget)" if cut else "",
        )

    return read


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class TotalReadBudgetTests(unittest.TestCase):
    """All budgeted reads of one plugin run share ``TOTAL_READ_MAX_SIZE``."""

    def setUp(self):
        patch = mock.patch.object(ldpreload, "TOTAL_READ_MAX_SIZE", 10000)
        patch.start()
        self.addCleanup(patch.stop)

    def test_reads_stop_when_the_total_is_used_up(self):
        kernel = FakeKernel({n: b"x" * 6000 for n in (1, 2, 3, 4)})
        plugin = kernel.plugin()
        inode = lambda n: kernel.object("inode", offset=n)  # noqa: E731
        with mock.patch.object(ldpreload, "read_inode", side_effect=budget_read(kernel)), \
                self.assertLogs(ldpreload.vollog, "WARNING") as logs:
            first = plugin._read_file("kernel", inode(1), "/lib/a.so", limit=8192)
            second = plugin._read_file("kernel", inode(2), "/lib/b.so", limit=8192)
            third = plugin._read_file("kernel", inode(3), "/lib/c.so", limit=8192)
            fourth = plugin._read_file("kernel", inode(4), "/lib/d.so")
        # Within the total: untouched, with the caller's own limit.
        self.assertEqual((len(first.data), first.truncated, first.note), (6000, False, ""))
        # Only the rest of the total is read, and the note says why.
        self.assertEqual((len(second.data), second.truncated), (4000, True))
        self.assertIn("total read budget of 10000 bytes", second.note)
        # Nothing left: not read at all.
        for recovered in (third, fourth):
            self.assertEqual((recovered.data, recovered.truncated), (b"", True))
            self.assertIn("not read: the total read budget", recovered.note)
        self.assertEqual(kernel.reads, ["/lib/a.so", "/lib/b.so"])
        self.assertEqual(kernel.bounds, [8192, 4000])
        self.assertEqual(plugin._read_total, 10000)
        # One warning for the run, not one per file.
        self.assertEqual(len(logs.output), 1)
        self.assertIn("/lib/b.so", logs.output[0])

    def test_the_count_belongs_to_the_plugin_instance(self):
        kernel = FakeKernel({1: b"x" * 9000})
        with mock.patch.object(ldpreload, "read_inode", side_effect=budget_read(kernel)), \
                mock.patch.object(ldpreload, "vollog"):
            for _ in range(2):
                plugin = kernel.plugin()
                recovered = plugin._read_file(
                    "kernel", kernel.object("inode", offset=1), "/lib/a.so"
                )
                self.assertFalse(recovered.truncated)
        self.assertFalse(hasattr(ldpreload, "_read_total"))
        fresh = ldpreload.LdPreload.__new__(ldpreload.LdPreload)
        with mock.patch.object(ldpreload.plugins.PluginInterface, "__init__", lambda *a, **k: None):
            fresh.__init__()
        self.assertEqual((fresh._read_total, fresh._read_total_warned), (0, False))

    def test_discarded_scan_candidates_do_not_use_up_the_total(self):
        files = {n: b"not a preload file\n" * 100 for n in range(1, 40)}
        kernel = FakeKernel(files)
        plugin = kernel.plugin()
        plugin._first_page_peeker = lambda *args: None
        found = []
        with mock.patch.object(ldpreload, "read_inode", side_effect=budget_read(kernel)), \
                mock.patch.object(ldpreload, "vollog") as log:
            plugin._scan_disguised_preloads(
                "kernel", [(f"/var/log/{n}", n) for n in files], found, set()
            )
        self.assertEqual(len(kernel.reads), len(files))
        self.assertEqual(plugin._read_total, 0)
        log.warning.assert_not_called()

    def test_row_of_a_library_beyond_the_total_says_so(self):
        evil = build_elf([("readdir", STT_FUNC, STB_GLOBAL, True)])
        preload = b"/lib/a.so\n/lib/b.so\n/lib/c.so\n"
        kernel = FakeKernel({1: preload, 2: evil, 3: evil, 4: evil})
        plugin = kernel.plugin({"no-env": True, "skip-maps": True, "no-scan": True})
        plugin.get_cached_regular_files = lambda *args: iter(
            [("/etc/ld.so.preload", 1), ("/lib/a.so", 2), ("/lib/b.so", 3), ("/lib/c.so", 4)]
        )
        total = len(preload) + len(evil) + 100
        with mock.patch.object(ldpreload, "TOTAL_READ_MAX_SIZE", total), \
                mock.patch.object(ldpreload, "read_inode", side_effect=budget_read(kernel)), \
                self.assertLogs(ldpreload.vollog, "WARNING") as logs:
            rows = [row for _, row in plugin._generator()]
        self.assertEqual([row[2] for row in rows], ["/lib/a.so", "/lib/b.so", "/lib/c.so"])
        self.assertEqual(rows[0][4], "readdir")
        self.assertNotIn("total read budget", str(rows[0][6]))
        # Cut short: the hook is not claimed absent, and the note says why.
        self.assertIsInstance(rows[1][4], ldpreload.renderers.NotAvailableValue)
        self.assertIn(f"total read budget of {total} bytes", rows[1][6])
        self.assertIn("/lib/c.so not read: the total read budget", rows[2][6])
        self.assertEqual(len([line for line in logs.output if "total read budget" in line]), 1)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class LinearSoTokenTests(unittest.TestCase):
    """``SO_TOKEN_RE`` without the regex: same answers, linear time."""

    #: The pattern the matcher replaces; quadratic when searched unanchored.
    REFERENCE = re.compile(r"\.so(?:\.[^/\s]+)?$")

    def test_matcher_agrees_with_the_regex_it_replaces(self):
        search = ldpreload.SO_TOKEN_RE.search
        rng = random.Random(170)
        alphabet = (".so", ".so.", ".", "s", "o", "/", "\n", "\t", " ", "\r", "a", "1", "\x85", "\x1c")
        texts = [
            "", "\n", ".so", ".so\n", ".so\n\n", "a.so.", "a.so.\n", "a.so.1\n", "a.so.1 ",
            "a.so.\t", ".so.so", "a.so.b/c.so.d", "a.so.d/x", "a.so.1\tb", "a.so\t.so.1",
            "/" + ".so" * 1364 + "\t", "/" + ".so" * 1364 + "\r", ".so." * 1024,
            ".so" * 1300 + "/", "x" * 4093 + ".so", "x" * 4090 + ".so.12",
        ]
        texts += [
            "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 9)))
            for _ in range(30000)
        ]
        for text in texts:
            self.assertLessEqual(len(text), 4096)
            self.assertIs(search(text), bool(self.REFERENCE.search(text)), repr(text))

    def timed(self, call):
        with deadline(20):
            start = time.perf_counter()
            result = call()
            elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0)
        return result

    def test_megabyte_environment_name_is_assessed_in_linear_time(self):
        # LD_PRELOAD is not split at a tab, so the whole megabyte is one name.
        name = ".so" * ((1 << 20) // 3) + "\t"
        self.assertEqual(ldpreload.LdPreload._split_preload_value(name), [name])
        entry = ldpreload.PreloadEntry(
            preload_path="LD_PRELOAD", library=name, env_var="LD_PRELOAD", env_pids={1: "sh"}
        )
        (kept,) = self.timed(lambda: make_plugin()._assess_env_entries([entry]))
        self.assertIn("not named like a shared object", kept.reasons)

    def test_megabyte_token_is_tested_for_preload_content_in_linear_time(self):
        looks = ldpreload.LdPreload._looks_like_preload
        body = b"/" + b".so" * ((1 << 20) // 3)
        # A carriage return is part of the token, and not of a shared-object name.
        self.assertFalse(self.timed(lambda: looks(body + b"\r")))
        self.assertTrue(self.timed(lambda: looks(body + b".1\n")))
        self.assertFalse(self.timed(lambda: looks(body + b".1/x\n")))


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class UnreadLoaderTailTests(unittest.TestCase):
    """A loader whose end is not cached is not called patched."""

    PATH = "/usr/lib64/ld-2.17.so"

    def check(self, data, size):
        kernel = FakeKernel({7: data}, sizes={7: size})
        with mock.patch.object(ldpreload, "read_inode", side_effect=kernel.read), \
                mock.patch.object(ldpreload, "vollog"):
            (check,) = kernel.plugin()._check_loaders("kernel", {self.PATH: 7}, {})
        return check.state

    def test_loader_shorter_than_its_size_is_inconclusive(self):
        rodata = (b"\x00/etc/ld.so.cache\x00" + b"r" * 0x2000).ljust(0x3000, b"r")
        elf = build_elf([], rodata=rodata)
        self.assertEqual(self.check(elf, len(elf)), "patched")
        # The recovered content ends with the last cached page: the section
        # headers and whatever else follows were never seen.
        cut = elf[:0x2000]
        self.assertIsNone(ldpreload.ElfReader.section_range(cut, ".rodata"))
        self.assertFalse(ldpreload._has_zero_page(cut))
        self.assertEqual(self.check(cut, len(elf)), "inconclusive")

    def test_patched_loader_with_complete_rodata_and_uncached_tail_is_patched(self):
        # The in-place patch: .rodata is located by the section headers and
        # lies wholly in the recovered content. A tail that is not cached
        # (debug sections, say) cannot hold the string.
        rodata = (b"\x00/etc/ld.so.cache\x00" + b"r" * 0x2000).ljust(0x3000, b"r")
        elf = build_elf([], rodata=rodata)
        start, size = ldpreload.ElfReader.section_range(elf, ".rodata")
        self.assertLessEqual(start + size, len(elf))
        self.assertEqual(self.check(elf, len(elf) + 1), "patched")
        self.assertEqual(self.check(elf, len(elf) + (1 << 20)), "patched")
        # A hole inside .rodata still leaves it open.
        holed = bytearray(elf)
        holed[0x1000:0x2000] = bytes(0x1000)
        self.assertEqual(self.check(bytes(holed), len(elf) + 1), "inconclusive")

    def test_rodata_reaching_past_the_recovered_content_is_inconclusive(self):
        rodata = (b"\x00/etc/ld.so.cache\x00" + b"r" * 0x2000).ljust(0x3000, b"r")
        elf = bytearray(build_elf([], rodata=rodata))
        # Grow .rodata's sh_size (fourth section header) past the end of what
        # was read: the string may sit in the part that is not cached.
        shoff = struct.unpack_from("<Q", elf, 40)[0]
        struct.pack_into("<Q", elf, shoff + 3 * 64 + 32, len(elf))
        elf = bytes(elf)
        start, size = ldpreload.ElfReader.section_range(elf, ".rodata")
        self.assertGreater(start + size, len(elf))
        self.assertFalse(ldpreload._has_zero_page(elf))
        self.assertEqual(self.check(elf, start + size), "inconclusive")
        self.assertEqual(self.check(elf, None), "inconclusive")

    def test_loader_of_unreadable_size_is_inconclusive(self):
        rodata = b"\x00/etc/ld.so.cache\x00".ljust(0x100, b"r")
        bare = build_elf([], rodata=rodata, strip_sections=True)
        self.assertEqual(self.check(bare, len(bare)), "patched")
        self.assertEqual(self.check(bare, None), "inconclusive")
        # With .rodata located and complete, the size does not matter.
        self.assertEqual(self.check(build_elf([], rodata=rodata), None), "patched")

    def test_intact_loader_stays_intact_whatever_was_read(self):
        elf = build_elf([], rodata=b"\x00/etc/ld.so.preload\x00")
        self.assertEqual(self.check(elf, len(elf) + 4096), "intact")


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ForgedSymbolTableTests(unittest.TestCase):
    """Section headers are the file author's word; no or an empty ``.dynsym``
    is not evidence that a library exports nothing. These images have no
    dynamic segment, so the section headers are all the reader has (the
    section-header fallback); see ``DynamicSegmentTests`` for the same forgeries
    next to a dynamic segment."""

    HOOK = [("readdir", STT_FUNC, STB_GLOBAL, True)]
    SHT_SYMTAB = 2

    @staticmethod
    def patched_dynsym(data, sh_type=None, sh_size=None, sh_offset=None):
        """``data`` with the type, size or offset of its .dynsym header (index 2)
        changed (64-bit little-endian images)."""
        image = bytearray(data)
        header = struct.unpack_from("<Q", image, 40)[0] + 2 * 64
        if sh_type is not None:
            struct.pack_into("<I", image, header + 4, sh_type)
        if sh_offset is not None:
            struct.pack_into("<Q", image, header + 24, sh_offset)
        if sh_size is not None:
            struct.pack_into("<Q", image, header + 32, sh_size)
        return bytes(image)

    def test_empty_dynsym_is_incomplete(self):
        info = ldpreload.ElfReader.parse(
            self.patched_dynsym(build_elf(self.HOOK, dynamic=False), sh_size=0)
        )
        self.assertTrue(info.valid)
        self.assertEqual(info.exported, [])
        self.assertTrue(info.incomplete)

    def test_missing_dynsym_is_incomplete(self):
        info = ldpreload.ElfReader.parse(
            self.patched_dynsym(build_elf(self.HOOK, dynamic=False), sh_type=SHT_PROGBITS)
        )
        self.assertEqual(info.exported, [])
        self.assertTrue(info.incomplete)

    def test_symtab_fallback_is_read_but_incomplete(self):
        info = ldpreload.ElfReader.parse(
            self.patched_dynsym(build_elf(self.HOOK, dynamic=False), sh_type=self.SHT_SYMTAB)
        )
        self.assertEqual(info.interposed(), ["readdir"])
        self.assertEqual(info.source, "sections")
        self.assertTrue(info.incomplete)

    def test_section_headers_alone_are_never_complete(self):
        info = ldpreload.ElfReader.parse(build_elf(self.HOOK, dynamic=False))
        self.assertEqual(info.interposed(), ["readdir"])
        self.assertEqual(info.source, "sections")
        self.assertTrue(info.incomplete)

    def test_library_with_empty_dynsym_is_not_assumed_safe(self):
        path = "/usr/lib64/libquiet.so"
        for label, data, benign in (
            ("real table", build_elf([("helper", STT_FUNC, STB_GLOBAL, True)]), True),
            (
                "empty table",
                self.patched_dynsym(build_elf(self.HOOK, dynamic=False), sh_size=0),
                False,
            ),
        ):
            with self.subTest(label):
                entry = ldpreload.PreloadEntry(
                    preload_path="LD_PRELOAD",
                    library=path,
                    env_var="LD_PRELOAD",
                    env_pids={100: "bash"},
                    recovered=ldpreload.RecoveredFile(path=path, inode_addr=1, data=data),
                    elf=ldpreload.ElfReader.parse(data),
                )
                plugin = make_plugin({"filter-safe-env": True, "skip-maps": True})
                kept = plugin._assess_env_entries([entry])
                self.assertEqual(entry.benign, benign)
                self.assertEqual(kept, [] if benign else [entry])
                if not benign:
                    plugin._entries = kept
                    ((_, row),) = plugin._generator()
                    self.assertIsInstance(row[4], ldpreload.renderers.NotAvailableValue)
                    self.assertIn("symbol table not fully readable", row[6])


def patch_dynamic(data, offsets, tag, value=None, new_tag=None, bits=64, endian="<"):
    """``data`` with the value (and/or tag) of its dynamic entry ``tag`` changed."""
    image = bytearray(data)
    size = 16 if bits == 64 else 8
    fmt = endian + ("qQ" if bits == 64 else "iI")
    base = offsets["dynamic"]
    while True:
        entry_tag, entry_value = struct.unpack_from(fmt, image, base)
        if entry_tag == tag:
            struct.pack_into(
                fmt,
                image,
                base,
                entry_tag if new_tag is None else new_tag,
                entry_value if value is None else value,
            )
            return bytes(image)
        if entry_tag == DT_NULL:
            raise KeyError(tag)
        base += size


def patch_phdr(data, offsets, index, field, value):
    """``data`` with one field of program header ``index`` changed (64-bit LE)."""
    image = bytearray(data)
    position = {"type": 0, "offset": 8, "vaddr": 16, "filesz": 32, "memsz": 40}[field]
    fmt = "<I" if field == "type" else "<Q"
    struct.pack_into(fmt, image, offsets["phdr"] + index * 56 + position, value)
    return bytes(image)


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class DynamicSegmentTests(unittest.TestCase):
    """The symbol table is read through PT_DYNAMIC, as the loader reads it;
    section headers are a fallback and a cross-check."""

    SYMBOLS = ElfReaderTests.SYMBOLS
    EXPORTS = ["fopen", "hide_me", "open", "readdir"]
    HOOK = [("readdir", STT_FUNC, STB_GLOBAL, True)]
    DISAGREE = "section headers disagree with the dynamic segment"

    def assert_dynamic_complete(self, info, exported=None):
        self.assertTrue(info.valid)
        self.assertEqual(info.source, "dynamic")
        self.assertEqual(info.exported, self.EXPORTS if exported is None else exported)
        self.assertEqual(info.notes, [])
        self.assertFalse(info.incomplete)

    def assert_fallback(self, info):
        """No usable dynamic table: the section headers' word, incomplete."""
        self.assertTrue(info.valid)
        self.assertEqual(info.source, "sections")
        self.assertTrue(info.incomplete)

    def test_each_hash_style_class_and_byte_order(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                for style in ("sysv", "gnu", "both"):
                    with self.subTest(bits=bits, endian=endian, style=style):
                        data = build_elf(
                            self.SYMBOLS, bits=bits, endian=endian, hash_style=style
                        )
                        info = ldpreload.ElfReader.parse(data)
                        self.assertEqual(info.bits, bits)
                        self.assert_dynamic_complete(info)

    def test_eight_byte_hash_words_of_s390_and_alpha(self):
        for machine in (22, 0x9026):
            with self.subTest(machine=machine):
                data = build_elf(
                    self.SYMBOLS, endian=">", machine=machine, hash_word=8
                )
                self.assert_dynamic_complete(ldpreload.ElfReader.parse(data))
        # The same table on another machine is read as 4-byte words: nbucket
        # 0 and nchain 1, which the section headers contradict.
        data = build_elf(self.SYMBOLS, endian=">", hash_word=8)
        self.assertTrue(ldpreload.ElfReader.parse(data).incomplete)

    def test_mutated_images_never_raise(self):
        # Random byte changes to every kind of image the builder makes; the
        # parser returns what it read, whatever the bytes.
        rng = random.Random(18)
        images = [
            build_elf(self.SYMBOLS, bits=bits, endian=endian, hash_style=style)
            for bits in (32, 64)
            for endian in ("<", ">")
            for style in ("sysv", "gnu", "both")
        ]
        started = time.monotonic()
        for _ in range(600):
            image = bytearray(rng.choice(images))
            for _ in range(rng.randint(1, 8)):
                position = rng.randrange(len(image))
                image[position] = rng.choice((0, 0xFF, rng.randrange(256)))
            self.assertIsInstance(ldpreload.ElfReader.parse(bytes(image)), ldpreload.ElfInfo)
        self.assertLess(time.monotonic() - started, 5)

    def test_addresses_are_mapped_through_pt_load(self):
        for style in ("sysv", "gnu"):
            with self.subTest(style):
                data = build_elf(self.SYMBOLS, hash_style=style, vaddr_base=0x400000)
                self.assert_dynamic_complete(ldpreload.ElfReader.parse(data))

    def test_without_section_headers_the_dynamic_segment_is_complete(self):
        # sstrip: no section headers at all, nothing to cross-check; the
        # loader does not need them and neither does the reader.
        for style in ("sysv", "gnu"):
            with self.subTest(style):
                data = build_elf(self.SYMBOLS, strip_sections=True, hash_style=style)
                self.assert_dynamic_complete(ldpreload.ElfReader.parse(data))

    def test_section_headers_not_recovered_are_no_disagreement(self):
        # Headers cut off at the end of the recovered content say nothing.
        data = build_elf(self.SYMBOLS)
        self.assert_dynamic_complete(ldpreload.ElfReader.parse(data[:-10]))

    def test_uncached_section_headers_are_no_disagreement(self):
        # A header table on a page that was not cached reads as zeros: no
        # .dynsym is listed, which is not the file's claim.
        # Padded so that the header table starts a page of its own.
        shoff = build_elf_layout(self.SYMBOLS, rodata=b"x" * 8192)[1]["shoff"]
        rodata = b"x" * (8192 + -shoff % 4096)
        data, offsets = build_elf_layout(self.SYMBOLS, rodata=rodata)
        shoff = offsets["shoff"]
        self.assertEqual(shoff % 4096, 0)
        holed = data[:shoff] + b"\x00" * 4096
        info = ldpreload.ElfReader.parse(holed)
        self.assertEqual(info.notes, [])
        self.assertFalse(info.incomplete)

    def test_forged_section_headers_are_reported(self):
        patched = ForgedSymbolTableTests.patched_dynsym
        data, offsets = build_elf_layout(self.SYMBOLS)
        for label, forged, detail in (
            ("empty .dynsym", patched(data, sh_size=0), "symbols, not"),
            ("no .dynsym", patched(data, sh_type=SHT_PROGBITS), "no .dynsym"),
            (".symtab only", patched(data, sh_type=2), "no .dynsym"),
            ("moved .dynsym", patched(data, sh_offset=offsets["rodata"]), ".dynsym at"),
            # Two of eight entries: readdir and open only.
            ("short .dynsym", patched(data, sh_size=3 * 24), "only in the dynamic segment"),
        ):
            with self.subTest(label):
                info = ldpreload.ElfReader.parse(forged)
                self.assertEqual(info.source, "dynamic")
                # The loader's view, not the headers'.
                self.assertEqual(info.exported, self.EXPORTS)
                self.assertTrue(info.incomplete)
                (note,) = info.notes
                self.assertIn(self.DISAGREE, note)
                self.assertIn(detail, note)

    def test_other_exports_in_the_section_headers_are_reported(self):
        # .dynsym points at a decoy table (kept in .rodata) of the same names
        # in which hide_me is global; the loader's table has it local.
        hidden = [
            (name, kind, STB_LOCAL if name == "hide_me" else binding, defined)
            for name, kind, binding, defined in self.SYMBOLS
        ]
        listed, listed_at = build_elf_layout(self.SYMBOLS)
        decoy = listed[listed_at["dynsym"] : listed_at["dynsym"] + 8 * 24]
        data, offsets = build_elf_layout(hidden, rodata=decoy)
        forged = ForgedSymbolTableTests.patched_dynsym(data, sh_offset=offsets["rodata"])
        info = ldpreload.ElfReader.parse(forged)
        self.assertEqual(info.exported, ["fopen", "open", "readdir"])
        self.assertTrue(info.incomplete)
        (note,) = info.notes
        self.assertIn(self.DISAGREE, note)
        self.assertIn("only in .dynsym: hide_me", note)

    def test_no_pt_dynamic_falls_back_to_section_headers(self):
        data, offsets = build_elf_layout(self.SYMBOLS)
        info = ldpreload.ElfReader.parse(patch_phdr(data, offsets, 1, "type", 0))
        self.assert_fallback(info)
        self.assertEqual(info.exported, self.EXPORTS)

    def test_dynamic_pointers_outside_the_data(self):
        data, offsets = build_elf_layout(self.SYMBOLS, hash_style="both")
        for tag in (DT_SYMTAB, DT_STRTAB, DT_HASH, DT_GNU_HASH):
            for value in (len(data) + 0x10000, (1 << 64) - 8):
                with self.subTest(tag=tag, value=value):
                    info = ldpreload.ElfReader.parse(
                        patch_dynamic(data, offsets, tag, value)
                    )
                    self.assertTrue(info.incomplete)
        # Neither hash table: no symbol count.
        data, offsets = build_elf_layout(self.SYMBOLS)
        self.assert_fallback(
            ldpreload.ElfReader.parse(
                patch_dynamic(data, offsets, DT_HASH, new_tag=0x70000000)
            )
        )
        # A string table size beyond the file.
        self.assert_fallback(
            ldpreload.ElfReader.parse(patch_dynamic(data, offsets, DT_STRSZ, 1 << 40))
        )

    def test_wrong_symbol_entry_size(self):
        data, offsets = build_elf_layout(self.SYMBOLS)
        info = ldpreload.ElfReader.parse(patch_dynamic(data, offsets, DT_SYMENT, 16))
        self.assert_fallback(info)
        self.assertIn("DT_SYMENT 16 is not 24", info.notes)

    def test_dynamic_segment_without_dt_null(self):
        data, offsets = build_elf_layout(self.SYMBOLS)
        # The segment ends where the entries end, and the last is no DT_NULL.
        end = offsets["phdr"]
        unterminated = patch_dynamic(data, offsets, DT_NULL, new_tag=0x70000000)
        unterminated = patch_phdr(unterminated, offsets, 0, "filesz", end)
        info = ldpreload.ElfReader.parse(unterminated)
        self.assert_fallback(info)
        self.assertIn("dynamic segment has no DT_NULL terminator", info.notes)
        # More entries than are walked.
        with mock.patch.object(ldpreload, "ELF_DYNAMIC_MAX", 3):
            info = ldpreload.ElfReader.parse(data)
        self.assert_fallback(info)
        self.assertIn("dynamic segment has no DT_NULL terminator", info.notes)

    def test_huge_hash_counts(self):
        data, offsets = build_elf_layout(self.SYMBOLS)
        for label, position, value in (
            ("nbucket", 0, 0xFFFFFFFF),
            ("nchain", 4, 0xFFFFFFFF),
            ("nchain past the data", 4, 0x10000),
        ):
            with self.subTest(label):
                image = bytearray(data)
                struct.pack_into("<I", image, offsets["hash"] + position, value)
                started = time.monotonic()
                self.assert_fallback(ldpreload.ElfReader.parse(bytes(image)))
                self.assertLess(time.monotonic() - started, 1)
        data, offsets = build_elf_layout(self.SYMBOLS, hash_style="gnu")
        gnu = offsets["gnu_hash"]
        bucket = gnu + 16 + 8  # header, one 64-bit bloom word
        for label, position, value in (
            ("nbuckets", gnu, 0xFFFFFFFF),
            ("bloom size", gnu + 8, 0xFFFFFFFF),
            ("bucket", bucket, 0xFFFFFFF0),
            ("bucket below symoffset", gnu + 4, 5),
        ):
            with self.subTest(label):
                image = bytearray(data)
                struct.pack_into("<I", image, position, value)
                started = time.monotonic()
                self.assert_fallback(ldpreload.ElfReader.parse(bytes(image)))
                self.assertLess(time.monotonic() - started, 1)

    def test_gnu_hash_chain_without_an_end(self):
        data, offsets = build_elf_layout(self.SYMBOLS, hash_style="gnu")
        chain = offsets["gnu_hash"] + 16 + 8 + 4
        image = bytearray(data)
        for index in range(len(self.SYMBOLS)):
            struct.pack_into("<I", image, chain + 4 * index, 2)  # all even
        # The walk runs on into what follows the chain; whatever it ends on,
        # the count no longer matches.
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assertTrue(info.incomplete)
        # A chain longer than the symbol cap is not walked to its end.
        with mock.patch.object(ldpreload, "ELF_SYMBOL_MAX", 3):
            info = ldpreload.ElfReader.parse(bytes(image))
        self.assertTrue(info.incomplete)
        # One that runs off its segment has no count at all.
        end = chain + 4 * len(self.SYMBOLS)
        amap = ldpreload._AddressMap([(0, 0, end)], 64)
        self.assertIsNone(
            ldpreload.ElfReader._gnu_hash_count(
                bytes(image), "<", 64, amap, offsets["gnu_hash"]
            )
        )

    def test_nchain_smaller_than_the_chains_reach(self):
        # The loader follows buckets and chains without checking them against
        # nchain; an nchain of 1 would otherwise read as "defines nothing".
        data, offsets = build_elf_layout(self.SYMBOLS, strip_sections=True)
        image = bytearray(data)
        struct.pack_into("<I", image, offsets["hash"] + 4, 1)
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assertTrue(info.incomplete)
        # What the chains reach is read all the same.
        self.assertEqual(info.exported, self.EXPORTS)
        self.assertIn("DT_HASH chains reach past nchain 1", " ".join(info.notes))

    def test_string_table_size_does_not_hide_names(self):
        # The loader reads names without regard to DT_STRSZ; a size of 1 must
        # not turn every export into an empty name that is skipped.
        data, offsets = build_elf_layout(self.SYMBOLS, strip_sections=True)
        info = ldpreload.ElfReader.parse(patch_dynamic(data, offsets, DT_STRSZ, 1))
        self.assertEqual(info.exported, self.EXPORTS)
        # A name that cannot be read at all leaves the read incomplete.
        image = bytearray(data)
        struct.pack_into("<I", image, offsets["dynsym"] + 24, 0xFFFFFF)  # readdir's st_name
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assertTrue(info.incomplete)

    def test_hash_tables_disagreeing(self):
        data, offsets = build_elf_layout(self.SYMBOLS, hash_style="both")
        image = bytearray(data)
        struct.pack_into("<I", image, offsets["hash"] + 4, len(self.SYMBOLS) + 2)
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assertTrue(info.incomplete)
        self.assertIn("DT_HASH and DT_GNU_HASH disagree", " ".join(info.notes))

    def test_gnu_hash_without_hashed_symbols(self):
        # An object that defines nothing: no bucket is used and symoffset is
        # only a lower bound, which a .dynsym of more entries does not contradict.
        for style in ("gnu", "both"):
            with self.subTest(style):
                info = ldpreload.ElfReader.parse(build_elf([], hash_style=style))
                self.assert_dynamic_complete(info, exported=[])
        imports = [("write", STT_FUNC, STB_GLOBAL, False), ("read", STT_FUNC, STB_GLOBAL, False)]
        data, offsets = build_elf_layout(imports, hash_style="gnu")
        image = bytearray(data)
        struct.pack_into("<I", image, offsets["gnu_hash"] + 16 + 8, 0)  # empty bucket
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assert_dynamic_complete(info, exported=[])

    def test_huge_program_header_count(self):
        data = bytearray(build_elf(self.SYMBOLS))
        struct.pack_into("<H", data, 56, 0xFFFF)
        started = time.monotonic()
        info = ldpreload.ElfReader.parse(bytes(data))
        self.assertLess(time.monotonic() - started, 1)
        self.assert_fallback(info)
        self.assertIn("implausible program header count 65535", info.notes)
        struct.pack_into("<H", data, 54, 0)  # e_phentsize
        struct.pack_into("<H", data, 56, 2)
        self.assert_fallback(ldpreload.ElfReader.parse(bytes(data)))

    def test_segment_overflow_and_unmappable_addresses(self):
        data, offsets = build_elf_layout(self.SYMBOLS)
        top = 1 << 64
        for label, fields in (
            ("p_offset wraps", {"offset": top - 0x10}),
            ("p_filesz wraps", {"filesz": top - 1, "offset": 0x10, "vaddr": 0x10}),
            ("p_vaddr wraps", {"vaddr": top - 0x10}),
            ("p_vaddr elsewhere", {"vaddr": 0x10000000}),
        ):
            with self.subTest(label):
                image = data
                for field, value in fields.items():
                    image = patch_phdr(image, offsets, 0, field, value)
                self.assert_fallback(ldpreload.ElfReader.parse(image))
        # PT_DYNAMIC at an address no PT_LOAD maps.
        self.assert_fallback(
            ldpreload.ElfReader.parse(patch_phdr(data, offsets, 1, "vaddr", 0x10000000))
        )

    def test_32_bit_segment_overflow(self):
        data, offsets = build_elf_layout(self.SYMBOLS, bits=32)
        image = bytearray(data)
        struct.pack_into("<I", image, offsets["phdr"] + 4, 0xFFFFFFF0)  # p_offset
        info = ldpreload.ElfReader.parse(bytes(image))
        self.assert_fallback(info)

    def test_overlapping_segments_are_ambiguous(self):
        amap = ldpreload._AddressMap([(0, 0, 0x100), (0, 0x1000, 0x100)], 64)
        self.assertIsNone(amap.offset(0x10, 8))
        self.assertTrue(amap.ambiguous)
        amap = ldpreload._AddressMap([(0, 0, 0x100), (0x80, 0x80, 0x100)], 64)
        self.assertEqual(amap.offset(0x90, 8), (0x90, 0x100))
        self.assertFalse(amap.ambiguous)
        # The range has to lie within one segment's file part.
        self.assertIsNone(amap.offset(0xF0, 0x100))

    def test_uncached_symbol_string_or_hash_page_is_incomplete(self):
        symbols = [(f"filler{n:04}", STT_FUNC, STB_LOCAL, True) for n in range(1500)]
        for style in ("sysv", "gnu"):
            data, offsets = build_elf_layout(symbols + self.HOOK, hash_style=style)
            self.assert_dynamic_complete(
                ldpreload.ElfReader.parse(data), exported=["readdir"]
            )
            table = offsets["hash" if style == "sysv" else "gnu_hash"]
            for label, start in (
                ("string table", offsets["dynstr"]),
                ("symbol table", offsets["dynsym"]),
                ("hash table", table),
            ):
                with self.subTest(style=style, table=label):
                    page = (start + 4095) // 4096 * 4096
                    holed = data[:page] + b"\x00" * 4096 + data[page + 4096 :]
                    info = ldpreload.ElfReader.parse(holed)
                    self.assertEqual(info.source, "dynamic")
                    self.assertTrue(info.incomplete)

    def test_forged_library_is_not_assumed_safe_and_says_why(self):
        path = "/usr/lib64/libquiet.so"
        helper = [("helper", STT_FUNC, STB_GLOBAL, True)]
        honest = build_elf(helper)
        forged = ForgedSymbolTableTests.patched_dynsym(honest, sh_size=0)
        for label, data, benign in (("honest", honest, True), ("forged", forged, False)):
            with self.subTest(label):
                entry = ldpreload.PreloadEntry(
                    preload_path="LD_PRELOAD",
                    library=path,
                    env_var="LD_PRELOAD",
                    env_pids={100: "bash"},
                    recovered=ldpreload.RecoveredFile(path=path, inode_addr=1, data=data),
                    elf=ldpreload.ElfReader.parse(data),
                )
                plugin = make_plugin({"filter-safe-env": True, "skip-maps": True})
                kept = plugin._assess_env_entries([entry])
                self.assertEqual(entry.benign, benign)
                if not benign:
                    plugin._entries = kept
                    ((_, row),) = plugin._generator()
                    self.assertEqual(len(row), 7)
                    self.assertIn(self.DISAGREE, row[6])
                    self.assertIn("symbol table not fully readable", row[6])

    def test_real_shared_objects_read_completely_and_consistently(self):
        # Python's own extension modules and the libraries this process has
        # mapped (libc, the loader, ...): real linker output on every system
        # the tests run on. Each is read through its dynamic segment, in full,
        # without a disagreement with its section headers.
        import sysconfig

        modules = set()
        directory = pathlib.Path(sysconfig.get_config_var("DESTSHARED") or "")
        if directory.is_dir():
            modules.update(sorted(directory.glob("*.so"))[:100])
        mapped = set()
        maps = pathlib.Path("/proc/self/maps")
        if maps.exists():
            for line in maps.read_text().splitlines():
                name = line.split(maxsplit=5)[5:]
                if name and ".so" in name[0] and name[0].startswith("/"):
                    mapped.add(pathlib.Path(name[0]))
        seen = 0
        for path in sorted(modules | mapped):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if not data.startswith(b"\x7fELF"):
                continue
            seen += 1
            with self.subTest(path.name):
                info = ldpreload.ElfReader.parse(data)
                self.assertEqual(info.source, "dynamic")
                self.assertEqual(info.notes, [])
                self.assertFalse(info.incomplete)
                if path in modules:
                    self.assertTrue(info.exported)  # PyInit_<module>
        if not seen:
            self.skipTest("no shared objects found")


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class ControlCharacterTests(unittest.TestCase):
    """Names from the image are shown with their control characters escaped,
    and kept as they are internally."""

    CONTROL = re.compile("[\x00-\x1f\x7f-\x9f  ]")

    def test_display_escapes(self):
        display = ldpreload._display
        self.assertEqual(display("/lib/a.so"), "/lib/a.so")
        self.assertEqual(display("a\nb\tc\rd"), "a\\nb\\tc\\rd")
        self.assertEqual(display("\x00\x1b[2J\x7f"), "\\x00\\x1b[2J\\x7f")
        self.assertEqual(display("\x85\x9b "), "\\x85\\x9b\\u2028")
        self.assertEqual(display("größe ünïcode $LIB"), "größe ünïcode $LIB")
        for code in list(range(0x20)) + [0x7F]:
            self.assertIsNone(self.CONTROL.search(display(f"a{chr(code)}b")), code)
        # Escaping twice changes nothing more.
        self.assertEqual(display(display("a\nb")), "a\\nb")

    def test_rows_carry_no_control_characters(self):
        library = "/tmp/evil.so\n/etc/ld.so.preload\t2026-01-01\tlibc.so.6\r\x1b[2K\x7f"
        elf = ldpreload.ElfInfo(valid=True, bits=64, exported=["helper\nreaddir", "open\tx"])
        recovered = ldpreload.RecoveredFile(
            path="/tmp/dir\n/evil.so", inode_addr=1, data=b"\x7fELF", note="note\rhere"
        )
        entries = [
            ldpreload.PreloadEntry(
                preload_path="/etc/x\n/etc/ld.so.preload",
                library=library,
                recovered=recovered,
                elf=elf,
                detection="disguised preload file",
            ),
            ldpreload.PreloadEntry(
                preload_path="LD_PRELOAD",
                library="evil\n.so",
                env_var="LD_PRELOAD",
                env_pids={7: "ba\nsh\t"},
                recovered=recovered,
                elf=elf,
                reasons=["hidden file"],
            ),
        ]
        loader = ldpreload.LoaderCheck(
            ldpreload.RecoveredFile(path="/lib\n64/ld-2.17.so", inode_addr=2, data=b""),
            "patched",
            reads="/etc/a\tb",
        )
        artifact = ldpreload.RecoveredFile(
            path="/lib64/ld-2.17.so.tmp\n", inode_addr=3, data=b"", note="odd\x0bnote"
        )
        plugin = make_plugin(
            {"skip-maps": True, "all-symbols": True},
            _entries=entries,
            _loader_checks=[loader],
            _linker_artifacts=[artifact],
        )
        rows = [row for _, row in plugin._generator()]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(len(row), 7)
            for cell in row:
                if isinstance(cell, str):
                    self.assertIsNone(self.CONTROL.search(cell), repr(cell))
        self.assertEqual(rows[0][0], "/etc/x\\n/etc/ld.so.preload")
        self.assertEqual(
            rows[0][2],
            "/tmp/evil.so\\n/etc/ld.so.preload\\t2026-01-01\\tlibc.so.6\\r\\x1b[2K\\x7f",
        )
        self.assertEqual(rows[0][4], "helper\\nreaddir, open\\tx")
        self.assertIn("note\\rhere", rows[0][6])
        self.assertIn("7 (ba\\nsh\\t)", rows[1][6])
        self.assertIn("resolved to /tmp/dir\\n/evil.so", rows[1][6])
        self.assertEqual(rows[2][0], "/lib\\n64/ld-2.17.so")
        self.assertIn("reads /etc/a\\tb", rows[2][6])
        self.assertEqual(rows[3][0], "/lib64/ld-2.17.so.tmp\\n")
        self.assertIn("odd\\x0bnote", rows[3][6])
        # Only the display is escaped.
        self.assertEqual(entries[0].library, library)
        self.assertEqual(entries[1].env_pids, {7: "ba\nsh\t"})

    def test_folded_cells_keep_only_their_own_line_breaks(self):
        entry = ldpreload.PreloadEntry(
            preload_path="/etc/ld.so.preload",
            library="/lib/a.so",
            detection="a note " * 20 + "with\na\tname",
        )
        plugin = make_plugin({"skip-maps": True, "wrap": 40}, _entries=[entry])
        ((_, row),) = plugin._generator()
        self.assertTrue(row[6].startswith("\n"))
        self.assertIn("with\\na\\tname", row[6].replace("\n", " "))
        self.assertNotIn("\t", row[6])

    def test_timeline_descriptions_are_escaped(self):
        stamp = datetime.datetime(2026, 7, 10, tzinfo=datetime.timezone.utc)
        preload = ldpreload.RecoveredFile(
            path="/etc/ld.so\n.preload", inode_addr=1, data=b"", modification_time=stamp
        )
        plugin = make_plugin(_entries=[], _preload_files=[preload])
        ((description, _, _),) = plugin.generate_timeline()
        self.assertEqual(description, "ld.so.preload file /etc/ld.so\\n.preload")

    def test_log_lines_are_escaped(self):
        with self.assertLogs(ldpreload.vollog, "INFO") as logs:
            ldpreload.vollog.info("%s=%s in PID %d (%s)", "LD_PRELOAD", "a\n.so", 7, "ba\tsh")
            ldpreload.vollog.warning("failed: %s", ValueError("bad\rvalue"))
            list(ldpreload.LdPreload._safe_iter(iter(()), "list"))
        self.assertEqual(
            [record.getMessage() for record in logs.records],
            ["LD_PRELOAD=a\\n.so in PID 7 (ba\\tsh)", "failed: bad\\rvalue"],
        )

    def test_environment_hits_are_logged_escaped(self):
        task = SimpleNamespace(pid=7, comm="ba\nsh")
        plugin = make_plugin(_context=None)
        plugin._read_environment = lambda task: b"LD_PRELOAD=/tmp/a\n.so\x00"
        with mock.patch.object(
            ldpreload.pslist.PsList, "list_tasks", lambda *args: iter([task])
        ), mock.patch.object(
            ldpreload.utility, "array_to_string", lambda comm: comm
        ), self.assertLogs(ldpreload.vollog, "INFO") as logs:
            (entry,) = plugin._collect_env_preloads("kernel")
        self.assertEqual(entry.library, "/tmp/a\n.so")
        (record,) = logs.records
        self.assertEqual(
            record.getMessage(),
            "LD_PRELOAD=/tmp/a\\n.so in the environment of PID(s) 7 (ba\\nsh)",
        )


@unittest.skipUnless(HAVE_FRAMEWORK, "volatility3 is not importable")
class RequirementTests(unittest.TestCase):
    def test_every_versioned_framework_component_in_use_is_required(self):
        required = {
            requirement.name: requirement
            for requirement in ldpreload.LdPreload.get_requirements()
            if isinstance(requirement, ldpreload.requirements.VersionRequirement)
        }
        self.assertEqual(
            sorted(required), ["linuxutils", "pagecache", "pslist", "timeliner"]
        )
        # get_path_mnt() and path_for_file() are LinuxUtilities' interface.
        self.assertIs(
            required["linuxutils"]._component, ldpreload.linux_symbols.LinuxUtilities
        )

    def test_requirements_are_met_by_the_installed_framework(self):
        for requirement in ldpreload.LdPreload.get_requirements():
            if isinstance(requirement, ldpreload.requirements.VersionRequirement):
                wanted = tuple(requirement._version)
                have = tuple(requirement._component.version)
                # Same major version, at least the wanted minor and patch.
                self.assertEqual(have[0], wanted[0], requirement.name)
                self.assertGreaterEqual(have[1:], wanted[1:], requirement.name)

    def test_plugin_version(self):
        self.assertEqual(ldpreload.LdPreload._version, (1, 8, 0))


if __name__ == "__main__":
    unittest.main()
