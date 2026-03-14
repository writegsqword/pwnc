"""DwarfSource: load type information from DWARF debug info."""

import os
import struct
import zlib
import multiprocessing

from ..resolver import Source
from ..base import Type
from .info import (parse_compilation_units, parse_single_cu,
                   discover_cu_boundaries, index_type_names)
from .builder import build_types_from_cu

# ELF section flag for compressed sections
_SHF_COMPRESSED = 0x800

# Module-level storage for worker processes (populated before fork)
_worker_sections = None


def _parse_and_build_cu(boundary):
    """Worker function: parse one CU and build its types.

    Runs in a forked child process. Section data is accessed from the
    module-level _worker_sections which is inherited from the parent
    via fork (COW-shared, no copy needed for read-only access).

    Returns dict of name -> Type.
    """
    sections = _worker_sections
    try:
        cu = parse_single_cu(
            boundary,
            sections["debug_info"],
            sections["debug_abbrev"],
            sections["debug_str"],
            sections["debug_line_str"],
        )
        if cu.root is None:
            return {}
        return build_types_from_cu(cu.root, cu.addr_size)
    except Exception:
        return {}


class DwarfSource(Source):
    """Type source that loads from DWARF debug info sections.

    Accepts a file path (string) or a pwnc.minelf.ELF instance.

    Modes:
        lazy=False (default): parses all CUs at construction.
            Per-CU parsing is parallelized across processes.
        lazy=True: indexes names first, parses individual CUs on demand.
    """

    def __init__(self, elf_or_path, lazy=False, workers=None):
        if isinstance(elf_or_path, str):
            from pwnc.minelf import ELF
            with open(elf_or_path, "rb") as f:
                elf = ELF(f.read())
        else:
            elf = elf_or_path

        # Read DWARF sections
        self._debug_info = self._get_section(elf, b".debug_info")
        self._debug_abbrev = self._get_section(elf, b".debug_abbrev")
        self._debug_str = self._get_section(elf, b".debug_str")
        self._debug_line_str = self._get_section(elf, b".debug_line_str",
                                                  required=False)

        self.lazy = lazy
        self._types = {}
        self._lazy_index = None
        self._cu_boundaries = None  # cached CU boundary list
        self._workers = workers

        if lazy:
            self._cu_boundaries = discover_cu_boundaries(self._debug_info)
            self._lazy_index = index_type_names(
                self._debug_info, self._debug_abbrev, self._debug_str,
                self._debug_line_str, self._cu_boundaries
            )
        else:
            self._load_all()

    def _get_section(self, elf, name, required=True):
        section = elf.section_from_name(name)
        if section is None:
            if not required:
                return None
            raise ValueError(f"ELF has no {name.decode()} section")
        content = bytes(elf.section_content(section))

        # Check for SHF_COMPRESSED flag
        if section.flags & _SHF_COMPRESSED:
            content = self._decompress_section(content)

        # Store as memoryview so DwarfReader doesn't copy on each instantiation
        if isinstance(content, memoryview):
            return content
        return memoryview(bytearray(content))

    @staticmethod
    def _decompress_section(data):
        """Decompress an ELF SHF_COMPRESSED section."""
        if len(data) < 24:
            raise ValueError("compressed section too small for header")

        ch_type = struct.unpack_from("<I", data, 0)[0]
        if ch_type != 1:
            raise ValueError(
                f"unsupported compression type {ch_type} "
                f"(only ELFCOMPRESS_ZLIB=1 is supported)"
            )

        ch_size = struct.unpack_from("<Q", data, 8)[0]
        compressed_data = data[24:]
        decompressed = zlib.decompress(compressed_data)

        if len(decompressed) != ch_size:
            raise ValueError(
                f"decompressed size {len(decompressed)} != "
                f"expected {ch_size}"
            )

        return decompressed

    def _load_all(self):
        """Parse all compilation units and merge types.

        Uses multiprocessing to parse CUs in parallel when there are
        enough CUs to benefit. Falls back to sequential for small binaries.
        """
        boundaries = discover_cu_boundaries(self._debug_info)
        self._cu_boundaries = boundaries

        num_workers = self._workers
        if num_workers is None:
            num_workers = min(os.cpu_count() or 1, len(boundaries))

        if num_workers > 1 and len(boundaries) > 1:
            results = self._load_parallel(boundaries, num_workers)
        else:
            results = self._load_sequential(boundaries)

        # Merge: first CU's types win on name collisions
        for types_dict in results:
            for name, ty in types_dict.items():
                if name not in self._types:
                    self._types[name] = ty

    def _load_sequential(self, boundaries):
        """Parse all CUs sequentially. Used for small binaries."""
        results = []
        for b in boundaries:
            cu = parse_single_cu(b, self._debug_info, self._debug_abbrev,
                                 self._debug_str, self._debug_line_str)
            if cu.root is None:
                results.append({})
                continue
            results.append(build_types_from_cu(cu.root, cu.addr_size))
        return results

    def _load_parallel(self, boundaries, num_workers):
        """Parse CUs in parallel using multiprocessing with fork.

        Section data is shared with workers via a module-level global
        that is inherited through fork (COW, no serialization cost).
        """
        global _worker_sections
        _worker_sections = {
            "debug_info": self._debug_info,
            "debug_abbrev": self._debug_abbrev,
            "debug_str": self._debug_str,
            "debug_line_str": self._debug_line_str,
        }

        try:
            ctx = multiprocessing.get_context("fork")
            with ctx.Pool(processes=num_workers) as pool:
                results = pool.map(_parse_and_build_cu, boundaries)
        finally:
            _worker_sections = None

        return results

    @staticmethod
    def _to_key(name):
        """Encode a user-provided str name to bytes for internal lookup."""
        if isinstance(name, str):
            return name.encode("utf-8")
        return name

    def _lazy_load(self, key):
        """Lazy-load a type by parsing only the CU that contains it."""
        if key not in self._lazy_index:
            raise KeyError(key)

        cu_offset, die_offset = self._lazy_index[key]

        # Find the CU boundary for this offset
        boundary = None
        if self._cu_boundaries is not None:
            for b in self._cu_boundaries:
                if b.offset == cu_offset:
                    boundary = b
                    break

        if boundary is None:
            self._cu_boundaries = discover_cu_boundaries(self._debug_info)
            for b in self._cu_boundaries:
                if b.offset == cu_offset:
                    boundary = b
                    break

        if boundary is None:
            raise KeyError(key)

        cu = parse_single_cu(boundary, self._debug_info, self._debug_abbrev,
                             self._debug_str, self._debug_line_str)
        if cu.root is not None:
            types = build_types_from_cu(cu.root, cu.addr_size)
            self._types.update(types)

    def __getitem__(self, name: str) -> Type:
        key = self._to_key(name)
        if key in self._types:
            return self._types[key]

        if self.lazy and self._lazy_index is not None:
            if key in self._lazy_index:
                self._lazy_load(key)
                if key in self._types:
                    return self._types[key]

        raise KeyError(name)

    def __contains__(self, name: str) -> bool:
        key = self._to_key(name)
        if key in self._types:
            return True
        if self.lazy and self._lazy_index is not None:
            return key in self._lazy_index
        return False

    def names(self) -> list[str]:
        if self.lazy and self._lazy_index is not None:
            return [k.decode("utf-8", errors="replace")
                    for k in self._lazy_index.keys()]
        return [k.decode("utf-8", errors="replace")
                for k in self._types.keys()]

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"no type named '{name}'")
