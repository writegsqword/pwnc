"""Walk .debug_info DIEs using abbreviation tables, produce DIE tree."""

from .reader import DwarfReader
from .abbrev import parse_abbrev_table
from .constants import *


class DIE:
    __slots__ = ("offset", "tag", "attrs", "children")

    def __init__(self, offset, tag):
        self.offset = offset
        self.tag = tag
        self.attrs = {}      # attribute -> value
        self.children = []   # list of DIE

    def attr(self, name, default=None):
        return self.attrs.get(name, default)

    def __repr__(self):
        tag_name = TAG_NAMES.get(self.tag, f"0x{self.tag:02x}")
        return f"DIE({tag_name} @ 0x{self.offset:x})"


class CompilationUnit:
    __slots__ = ("offset", "length", "version", "abbrev_offset", "addr_size", "root")

    def __init__(self):
        self.offset = 0
        self.length = 0
        self.version = 0
        self.abbrev_offset = 0
        self.addr_size = 0
        self.root = None  # root DIE (DW_TAG_compile_unit)


# ── CU boundary: lightweight metadata for parallelization ──────


class CUBoundary:
    """Lightweight CU descriptor used to parallelize parsing.

    Contains only header metadata — no DIE tree. Enough info to
    independently parse the CU later.
    """
    __slots__ = ("offset", "die_start", "cu_end", "version",
                 "abbrev_offset", "addr_size", "offset_size")

    def __init__(self, offset, die_start, cu_end, version,
                 abbrev_offset, addr_size, offset_size):
        self.offset = offset
        self.die_start = die_start
        self.cu_end = cu_end
        self.version = version
        self.abbrev_offset = abbrev_offset
        self.addr_size = addr_size
        self.offset_size = offset_size


def discover_cu_boundaries(debug_info):
    """Scan .debug_info headers to find CU boundaries without parsing DIEs.

    Returns a list of CUBoundary objects.
    """
    reader = DwarfReader(debug_info)
    boundaries = []

    debug_info_len = len(debug_info)
    while reader.pos < debug_info_len:
        cu_offset = reader.pos
        length = reader.read_u32()
        if length == 0xFFFFFFFF:
            raise NotImplementedError("64-bit DWARF not supported")

        offset_size = 4
        cu_end = reader.pos + length
        version = reader.read_u16()

        if version >= 5:
            _unit_type = reader.read_u8()
            addr_size = reader.read_u8()
            abbrev_offset = reader.read_u32()
        else:
            abbrev_offset = reader.read_u32()
            addr_size = reader.read_u8()

        die_start = reader.pos
        boundaries.append(CUBoundary(cu_offset, die_start, cu_end, version,
                                     abbrev_offset, addr_size, offset_size))
        reader.pos = cu_end

    return boundaries


def parse_single_cu(boundary, debug_info, debug_abbrev, debug_str,
                    debug_line_str=None):
    """Parse a single CU's DIE tree given its boundary metadata.

    Returns a CompilationUnit with its root DIE.
    """
    abbrev_table = parse_abbrev_table(debug_abbrev, boundary.abbrev_offset)
    reader = DwarfReader(debug_info, boundary.die_start)

    cu = CompilationUnit()
    cu.offset = boundary.offset
    cu.version = boundary.version
    cu.abbrev_offset = boundary.abbrev_offset
    cu.addr_size = boundary.addr_size

    cu.root = _parse_die_tree(reader, abbrev_table, boundary.addr_size,
                              debug_str, boundary.offset, boundary.cu_end,
                              debug_line_str, boundary.offset_size)
    return cu


# ── legacy entry point (sequential) ────────────────────────────


def parse_compilation_units(debug_info, debug_abbrev, debug_str,
                            debug_line_str=None):
    """Parse all compilation units from .debug_info (sequential).

    Returns a list of CompilationUnit objects.
    """
    boundaries = discover_cu_boundaries(debug_info)
    cus = []
    for b in boundaries:
        cu = parse_single_cu(b, debug_info, debug_abbrev, debug_str,
                             debug_line_str)
        cus.append(cu)
    return cus


# ── DIE tree parsing ────────────────────────────────────────────


def _parse_die_tree(reader, abbrev_table, addr_size, debug_str, cu_offset,
                    cu_end, debug_line_str=None, offset_size=4):
    """Parse a tree of DIEs until end of CU or a null entry at the current depth."""
    dies = []

    while reader.pos < cu_end:
        die_offset = reader.pos
        code = reader.read_uleb128()

        if code == 0:
            break

        if code not in abbrev_table:
            raise ValueError(f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        abbrev = abbrev_table[code]
        die = DIE(die_offset, abbrev.tag)

        for attr, form, implicit_value in abbrev.attrs:
            value = reader.read_form(form, addr_size, debug_str, cu_offset,
                                     debug_line_str, implicit_value, offset_size)
            die.attrs[attr] = value

        if abbrev.has_children:
            die.children = _parse_children(reader, abbrev_table, addr_size,
                                           debug_str, cu_offset, cu_end,
                                           debug_line_str, offset_size)

        dies.append(die)

    if len(dies) == 1:
        return dies[0]
    return dies[0] if dies else None


def _parse_children(reader, abbrev_table, addr_size, debug_str, cu_offset,
                    cu_end, debug_line_str=None, offset_size=4):
    """Parse children DIEs until a null entry."""
    children = []

    while reader.pos < cu_end:
        die_offset = reader.pos
        code = reader.read_uleb128()

        if code == 0:
            break

        if code not in abbrev_table:
            raise ValueError(f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        abbrev = abbrev_table[code]
        die = DIE(die_offset, abbrev.tag)

        for attr, form, implicit_value in abbrev.attrs:
            value = reader.read_form(form, addr_size, debug_str, cu_offset,
                                     debug_line_str, implicit_value, offset_size)
            die.attrs[attr] = value

        if abbrev.has_children:
            die.children = _parse_children(reader, abbrev_table, addr_size,
                                           debug_str, cu_offset, cu_end,
                                           debug_line_str, offset_size)

        children.append(die)

    return children


# ── type name indexing (for lazy mode) ──────────────────────────


def index_type_names(debug_info, debug_abbrev, debug_str,
                     debug_line_str=None, boundaries=None):
    """Build a lightweight index: type_name -> (cu_offset, die_offset).

    Used by lazy mode to know which types exist without fully parsing them.
    If boundaries is provided, skips the CU header scan.
    """
    reader = DwarfReader(debug_info)
    index = {}

    TYPE_TAGS = {
        DW_TAG_structure_type, DW_TAG_class_type, DW_TAG_union_type,
        DW_TAG_enumeration_type, DW_TAG_typedef, DW_TAG_base_type,
    }

    if boundaries is None:
        boundaries = discover_cu_boundaries(debug_info)

    for boundary in boundaries:
        reader.pos = boundary.die_start
        abbrev_table = parse_abbrev_table(debug_abbrev, boundary.abbrev_offset)

        _index_dies(reader, abbrev_table, boundary.addr_size, debug_str,
                    boundary.offset, boundary.cu_end, TYPE_TAGS, index,
                    debug_line_str, boundary.offset_size)

        reader.pos = boundary.cu_end

    return index


def _precompute_abbrev_info(abbrev_table, type_tags):
    """Pre-analyze abbreviation entries for fast indexing.

    For each abbrev, determine:
    - Whether it's a type tag we care about
    - The index of DW_AT_sibling in its attrs (for skipping subtrees)
    - The index of DW_AT_name (for capturing type names)
    """
    info = {}
    for code, entry in abbrev_table.items():
        is_type = entry.tag in type_tags
        sibling_idx = -1
        name_idx = -1
        decl_idx = -1
        bytesize_idx = -1
        for i, (attr, form, implicit) in enumerate(entry.attrs):
            if attr == DW_AT_sibling:
                sibling_idx = i
            elif attr == DW_AT_name:
                name_idx = i
            elif attr == DW_AT_declaration:
                decl_idx = i
            elif attr == DW_AT_byte_size:
                bytesize_idx = i
        info[code] = (is_type, sibling_idx, name_idx, decl_idx,
                      bytesize_idx, entry.has_children, entry.attrs)
    return info


def _index_dies(reader, abbrev_table, addr_size, debug_str,
                cu_offset, cu_end, type_tags, index,
                debug_line_str=None, offset_size=4):
    """Scan DIEs and index type names without building full DIE tree.

    Uses three optimizations:
    1. DW_AT_sibling skipping — jump past subtrees we don't need
    2. skip_form() — advance cursor without constructing Python objects
    3. Only read attributes we need (name, declaration, byte_size)
    """
    abbrev_info = _precompute_abbrev_info(abbrev_table, type_tags)
    _index_dies_fast(reader, abbrev_info, addr_size, debug_str,
                     cu_offset, cu_end, index, debug_line_str, offset_size)


def _index_dies_fast(reader, abbrev_info, addr_size, debug_str,
                     cu_offset, cu_end, index, debug_line_str, offset_size):
    """Inner indexing loop with fast attribute skipping."""
    while reader.pos < cu_end:
        die_offset = reader.pos
        code = reader.read_uleb128()

        if code == 0:
            return

        if code not in abbrev_info:
            raise ValueError(f"unknown abbreviation code {code} at offset 0x{die_offset:x}")

        is_type, sibling_idx, name_idx, decl_idx, bytesize_idx, \
            has_children, attrs = abbrev_info[code]

        if not is_type:
            # Not a type DIE. Try to skip as efficiently as possible.
            if sibling_idx >= 0 and has_children:
                # Has DW_AT_sibling — read just enough to get the sibling
                # offset, then jump there (skipping entire subtree).
                for i, (attr, form, implicit) in enumerate(attrs):
                    if i == sibling_idx:
                        sibling_off = reader.read_form(
                            form, addr_size, debug_str, cu_offset,
                            debug_line_str, implicit, offset_size)
                        # Skip remaining attrs
                        for j in range(i + 1, len(attrs)):
                            reader.skip_form(attrs[j][1], addr_size, offset_size)
                        # Jump to sibling (skips all children)
                        reader.pos = sibling_off
                        break
                    else:
                        reader.skip_form(form, addr_size, offset_size)
            else:
                # No sibling — skip all attrs, recurse into children
                # (children may still contain type definitions)
                for attr, form, implicit in attrs:
                    reader.skip_form(form, addr_size, offset_size)
                if has_children:
                    _index_dies_fast(reader, abbrev_info, addr_size, debug_str,
                                     cu_offset, cu_end, index,
                                     debug_line_str, offset_size)
        else:
            # Type DIE — read name, declaration, byte_size; skip the rest
            name = None
            is_declaration = False
            has_byte_size = False

            for i, (attr, form, implicit) in enumerate(attrs):
                if i == name_idx:
                    name = reader.read_form(
                        form, addr_size, debug_str, cu_offset,
                        debug_line_str, implicit, offset_size)
                elif i == decl_idx:
                    val = reader.read_form(
                        form, addr_size, debug_str, cu_offset,
                        debug_line_str, implicit, offset_size)
                    if val:
                        is_declaration = True
                elif i == bytesize_idx:
                    reader.skip_form(form, addr_size, offset_size)
                    has_byte_size = True
                else:
                    reader.skip_form(form, addr_size, offset_size)

            if name is not None and not (is_declaration and not has_byte_size):
                if name not in index:
                    index[name] = (cu_offset, die_offset)

            if has_children:
                # Recurse into children to find nested type definitions
                _index_dies_fast(reader, abbrev_info, addr_size, debug_str,
                                 cu_offset, cu_end, index,
                                 debug_line_str, offset_size)


def _skip_children(reader, abbrev_info, addr_size, offset_size):
    """Skip all children DIEs until the null terminator."""
    while True:
        code = reader.read_uleb128()
        if code == 0:
            return

        if code not in abbrev_info:
            return

        _, _, _, _, _, has_children, attrs = abbrev_info[code]

        for attr, form, implicit in attrs:
            reader.skip_form(form, addr_size, offset_size)
        if has_children:
            _skip_children(reader, abbrev_info, addr_size, offset_size)
