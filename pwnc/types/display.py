import fnmatch


def _type_str(ty):
    """Short type string for a field (e.g. 'u32', 'f32', 'struct Vec3')."""
    from .primitives import Int, Bits, Float, Double, Ptr
    from .containers import Struct, Union, Array, Enum

    if isinstance(ty, Bits):
        return f"bits({ty.nbits})"
    if isinstance(ty, Int):
        prefix = "i" if ty.signed else "u"
        return f"{prefix}{ty.nbits}"
    if isinstance(ty, Float):
        return "f32"
    if isinstance(ty, Double):
        return "f64"
    if isinstance(ty, Ptr):
        if ty.child is None:
            return "void*"
        return f"{_type_str(ty.child)}*"
    if isinstance(ty, Array):
        if ty.count == 0:
            return f"{_type_str(ty.child)}[]"
        return f"{_type_str(ty.child)}[{ty.count}]"
    if isinstance(ty, Enum):
        return f"enum {ty.name} : {_type_str(ty.child)}" if ty.name else f"enum : {_type_str(ty.child)}"
    if isinstance(ty, Struct):
        return f"struct {ty.name}"
    if isinstance(ty, Union):
        return f"union {ty.name}"
    return str(ty)


def _field_type_str(ty):
    """Type prefix for field display (no array suffix, that goes after the name)."""
    from .containers import Array, Enum
    from .primitives import Ptr

    if isinstance(ty, Array):
        return _type_str(ty.child)
    return _type_str(ty)


def _field_suffix(ty):
    """Suffix after field name (array brackets)."""
    from .containers import Array

    if isinstance(ty, Array):
        if ty.count == 0:
            return "[]"
        return f"[{ty.count}]"
    return ""


def format_type(ty, depth=None, filter=None, _indent=0, _seen=None):
    from .primitives import Int, Bits, Float, Double, Ptr
    from .containers import Struct, Union, Array, Enum

    if _seen is None:
        _seen = set()

    if isinstance(ty, (Int, Float, Double, Ptr)):
        return str(ty)

    if isinstance(ty, Bits):
        return str(ty)

    if isinstance(ty, Array):
        return str(ty)

    if isinstance(ty, Enum):
        return str(ty)

    if isinstance(ty, (Struct, Union)):
        return _format_container(ty, depth, filter, _indent, _seen)

    return str(ty)


def _format_container(ty, depth, filter, indent, seen):
    from .primitives import Bits
    from .containers import Struct, Union, Array, Enum

    kind = "struct" if isinstance(ty, Struct) else "union"
    prefix = "    " * indent
    inner_prefix = "    " * (indent + 1)

    mode_str = f", {ty.mode}" if isinstance(ty, Struct) else ""
    header = f"{prefix}{kind} {ty.name} {{  /* 0x{ty.nbytes:02x} bytes{mode_str} */"

    lines = [header]

    ty_id = id(ty)
    is_repeat = ty_id in seen
    seen.add(ty_id)

    if is_repeat or (depth is not None and depth < 1):
        lines = [f"{prefix}{kind} {ty.name} {{ ... }}"]
        return "\n".join(lines)

    child_depth = depth - 1 if depth is not None else None

    # build a set of padding offsets for display
    pad_entries = []
    if isinstance(ty, Struct):
        pad_entries = list(ty._padding)

    # merge fields and padding, sorted by offset
    entries = []
    for fname, ftype, byte_off, bit_off in ty._layout:
        entries.append(("field", fname, ftype, byte_off, bit_off))
    for pad_off, pad_size in pad_entries:
        entries.append(("padding", None, None, pad_off, pad_size))

    entries.sort(key=lambda e: (e[3], 0 if e[0] == "field" else 1))

    for entry in entries:
        if entry[0] == "padding":
            _, _, _, pad_off, pad_size = entry
            lines.append(f"{inner_prefix}/* 0x{pad_off:02x} padding({pad_size}) */")
        else:
            _, fname, ftype, byte_off, bit_off = entry

            # apply filter
            if filter is not None and not fnmatch.fnmatch(fname, filter):
                continue

            if isinstance(ftype, Bits):
                offset_str = f"0x{byte_off:02x}:{bit_off}"
            else:
                offset_str = f"0x{byte_off:02x}"

            # nested container
            if isinstance(ftype, (Struct, Union)):
                nested_kind = "struct" if isinstance(ftype, Struct) else "union"
                if ftype_id_seen(ftype, seen) or (child_depth is not None and child_depth < 1):
                    lines.append(f"{inner_prefix}/* {offset_str} */ {nested_kind} {ftype.name} {{ ... }} {fname};")
                else:
                    nested = _format_container(ftype, child_depth, None, indent + 1, seen)
                    # split nested into lines, first line gets offset prefix
                    nested_lines = nested.split("\n")
                    lines.append(f"{inner_prefix}/* {offset_str} */ {nested_lines[0].lstrip()}")
                    for nl in nested_lines[1:-1]:
                        lines.append(nl)
                    # closing brace + field name
                    lines.append(f"{inner_prefix}}} {fname};")
            elif isinstance(ftype, Enum):
                type_label = _type_str(ftype)
                lines.append(f"{inner_prefix}/* {offset_str} */ {type_label} {fname};")
            elif isinstance(ftype, Array):
                elem_type = _field_type_str(ftype)
                suffix = _field_suffix(ftype)
                # offset with extra spacing for alignment with bit fields
                if any(isinstance(ft, Bits) for _, ft in ty._fields):
                    lines.append(f"{inner_prefix}/* {offset_str}   */ {elem_type} {fname}{suffix};")
                else:
                    lines.append(f"{inner_prefix}/* {offset_str} */ {elem_type} {fname}{suffix};")
            else:
                type_label = _type_str(ftype)
                # if struct has bit fields, add spacing for non-bit fields
                if isinstance(ty, Struct) and any(isinstance(ft, Bits) for _, ft in ty._fields) and not isinstance(ftype, Bits):
                    lines.append(f"{inner_prefix}/* {offset_str}   */ {type_label} {fname};")
                else:
                    lines.append(f"{inner_prefix}/* {offset_str} */ {type_label} {fname};")

    lines.append(f"{prefix}}}")
    return "\n".join(lines)


def ftype_id_seen(ftype, seen):
    return id(ftype) in seen


def format_value(val, depth=None, filter=None, _indent=0):
    from .primitives import Int, Bits, Float, Double, Ptr
    from .containers import Struct, Union, Array, Enum
    from .value import Value, ArrayValue

    ty = val._type
    prefix = "    " * _indent
    inner_prefix = "    " * (_indent + 1)

    if isinstance(ty, (Struct, Union)):
        name = ty.name
        lines = [f"{prefix}{name} {{"]

        child_depth = depth - 1 if depth is not None else None

        for fname, ftype, byte_off, bit_off in ty._layout:
            if filter is not None and not fnmatch.fnmatch(fname, filter):
                continue

            field_offset = val._base_offset + byte_off
            field_val = Value(ftype, val._provider, field_offset)

            if isinstance(ftype, Bits) and bit_off is not None:
                field_val._bit_offset = bit_off

            if isinstance(ftype, (Struct, Union)):
                if depth is not None and depth <= 1:
                    lines.append(f"{inner_prefix}{fname} = {ftype.name} {{ ... }}")
                else:
                    nested = format_value(field_val, depth=child_depth, _indent=_indent + 1)
                    nested_lines = nested.split("\n")
                    lines.append(f"{inner_prefix}{fname} = {nested_lines[0].lstrip()}")
                    for nl in nested_lines[1:]:
                        lines.append(nl)
            elif isinstance(ftype, Array):
                arr_val = ArrayValue(ftype, val._provider, field_offset)
                lines.append(f"{inner_prefix}{fname} = {arr_val}")
            elif isinstance(ftype, Enum):
                raw_val = Value(ftype.child, val._provider, field_offset)._resolve()
                name_str = ftype._reverse.get(raw_val)
                if name_str:
                    lines.append(f"{inner_prefix}{fname} = {name_str} ({raw_val})")
                else:
                    lines.append(f"{inner_prefix}{fname} = {raw_val}")
            elif isinstance(ftype, Bits):
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = {resolved}")
            elif isinstance(ftype, Ptr):
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = 0x{resolved:x}")
            else:
                resolved = field_val._resolve()
                lines.append(f"{inner_prefix}{fname} = {resolved}")

        lines.append(f"{prefix}}}")
        return "\n".join(lines)

    # Primitives
    return str(val)
