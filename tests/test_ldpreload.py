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

import datetime
import importlib.util
import pathlib
import struct
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
    for name, value in attrs.items():
        setattr(plugin, name, value)
    return plugin


# -- a minimal ELF builder -----------------------------------------------------

STT_FUNC, STT_OBJECT = 2, 1
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
SHT_PROGBITS, SHT_STRTAB, SHT_DYNSYM = 1, 3, 11


def build_elf(symbols, bits=64, rodata=b"", shentsize=None, truncate_at=None):
    """A shared-object image with .dynstr, .dynsym, .rodata and .shstrtab.

    ``symbols`` is a list of ``(name, type, binding, defined)``.
    """
    endian = "<"
    sym_size = 24 if bits == 64 else 16
    shdr_size = 64 if bits == 64 else 40
    ehdr_size = 64 if bits == 64 else 52

    dynstr = b"\x00"
    name_offsets = []
    for name, *_ in symbols:
        name_offsets.append(len(dynstr))
        dynstr += name.encode() + b"\x00"

    dynsym = b"\x00" * sym_size  # the mandatory null symbol
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

    body = b""
    offsets = {}
    for label, blob in (
        ("dynstr", dynstr),
        ("dynsym", dynsym),
        ("rodata", rodata),
        ("shstrtab", shstrtab),
    ):
        offsets[label] = ehdr_size + len(body)
        body += blob
        body += b"\x00" * (-len(body) % 8)
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

    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + b"\x00" * 8
    if bits == 64:
        ehdr = ident + struct.pack(
            endian + "HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 0, 0, shentsize, shnum, 4
        )
    else:
        ehdr = ident + struct.pack(
            endian + "HHIIIIIHHHHHH", 3, 3, 1, 0, 0, shoff, 0, 52, 0, 0, shentsize, shnum, 4
        )
    data = ehdr + body + headers
    if truncate_at is not None:
        data = data[:truncate_at]
    return data


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
        data = build_elf(self.SYMBOLS, shentsize=0)
        info = ldpreload.ElfReader.parse(data)
        self.assertTrue(info.valid)
        self.assertEqual(info.exported, [])
        self.assertIsNone(ldpreload.ElfReader.section_range(data, ".rodata"))

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
        entry = self.entry("/opt/splunkforwarder/lib/libdlwrapper.so")
        (kept,) = self.assess(entry)
        self.assertTrue(kept.benign)
        self.assertEqual(kept.reasons, [])
        self.assertEqual(self.assess(entry, **{"filter-safe-env": True}), [])

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

    def get_type(self, name):
        return SimpleNamespace(size=8)

    def object(self, type_name, offset, absolute=False):
        size = self.sizes.get(offset, len(self.files.get(offset, b"")))
        return SimpleNamespace(
            vol=SimpleNamespace(offset=offset), is_valid=lambda: True, i_size=size
        )

    def read(self, context, module_name, inode, path):
        self.reads.append(path)
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

    def test_target_above_scan_limit_within_budget_is_read(self):
        data = b"/lib/evil.so\n" + b"#" * (2 * ldpreload.PRELOAD_SCAN_MAX_SIZE) + b"\n"
        kernel = FakeKernel({5: data})
        target = self.read_target(kernel, "/etc/custom.so.1", {"/etc/custom.so.1": 5})
        self.assertIsNotNone(target)

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


if __name__ == "__main__":
    unittest.main()
