import math
from .base import Type, BoundField
from .primitives import Bits


class Align:
    def __init__(self, n):
        self.alignment = n


class Pad:
    def __init__(self, n):
        self.size = n


def _natural_alignment(ty):
    """Get the natural alignment of a type for cstyle layout."""
    from .primitives import Int, Float, Double, Ptr
    if isinstance(ty, (Int, Float, Double, Ptr)):
        return ty.nbytes
    if isinstance(ty, Bits):
        return 1
    if isinstance(ty, Array):
        return _natural_alignment(ty.child)
    if isinstance(ty, Enum):
        return _natural_alignment(ty.child)
    if isinstance(ty, Struct):
        if not ty._fields:
            return 1
        return max((_natural_alignment(f[1]) for f in ty._fields), default=1)
    if isinstance(ty, Union):
        if not ty._fields:
            return 1
        return max((_natural_alignment(f[1]) for f in ty._fields), default=1)
    return 1


def _align_up(offset, alignment):
    return (offset + alignment - 1) // alignment * alignment


class Struct(Type):
    def __init__(self, name, fields, mode="packed"):
        self.name = name
        self.mode = mode
        self._fields = []       # list of (name, type) tuples for real fields
        self._layout = []       # list of (name, type, byte_offset, bit_offset_or_None)
        self._padding = []      # list of (byte_offset, size) for padding entries
        self._field_map = {}    # name -> index in _layout

        current_byte = 0
        current_bit = 0  # bit offset within current byte (for Bits fields)
        in_bitfield = False

        for item in fields:
            if isinstance(item, Align):
                # finish any pending bitfield
                if in_bitfield and current_bit > 0:
                    remaining = 8 - current_bit
                    current_bit = 0
                    in_bitfield = False
                    # the partial byte was already counted
                aligned = _align_up(current_byte, item.alignment)
                if aligned > current_byte:
                    self._padding.append((current_byte, aligned - current_byte))
                    current_byte = aligned
            elif isinstance(item, Pad):
                if in_bitfield and current_bit > 0:
                    current_bit = 0
                    in_bitfield = False
                self._padding.append((current_byte, item.size))
                current_byte += item.size
            else:
                fname, ftype = item
                is_bits = isinstance(ftype, Bits)

                if is_bits:
                    if not in_bitfield:
                        in_bitfield = True
                        current_bit = 0
                    # check if this Bits field fits in the current byte
                    if current_bit + ftype.nbits > 8:
                        # move to next byte
                        current_byte += 1
                        current_bit = 0

                    bit_off = current_bit
                    self._fields.append((fname, ftype))
                    idx = len(self._layout)
                    self._layout.append((fname, ftype, current_byte, bit_off))
                    self._field_map[fname] = idx
                    current_bit += ftype.nbits
                    # if we filled a byte exactly, advance
                    while current_bit >= 8:
                        current_byte += 1
                        current_bit -= 8
                else:
                    # non-Bits field: close bitfield if open
                    if in_bitfield and current_bit > 0:
                        # partial byte used, advance past it
                        current_byte += 1
                        current_bit = 0
                    in_bitfield = False

                    if mode == "cstyle":
                        alignment = _natural_alignment(ftype)
                        aligned = _align_up(current_byte, alignment)
                        if aligned > current_byte:
                            self._padding.append((current_byte, aligned - current_byte))
                            current_byte = aligned

                    self._fields.append((fname, ftype))
                    idx = len(self._layout)
                    self._layout.append((fname, ftype, current_byte, None))
                    self._field_map[fname] = idx
                    current_byte += ftype.nbytes

        # close trailing bitfield
        if in_bitfield and current_bit > 0:
            current_byte += 1
            current_bit = 0

        # cstyle trailing padding
        if mode == "cstyle" and self._fields:
            struct_align = max((_natural_alignment(f[1]) for f in self._fields), default=1)
            aligned = _align_up(current_byte, struct_align)
            if aligned > current_byte:
                self._padding.append((current_byte, aligned - current_byte))
                current_byte = aligned

        super().__init__(current_byte * 8)

    @classmethod
    def _from_layout(cls, name, layout, padding, nbytes, mode="packed"):
        """Create a Struct with a pre-built layout (used by DWARF builder)."""
        obj = object.__new__(cls)
        obj.name = name
        obj.mode = mode
        obj._fields = [(f[0], f[1]) for f in layout]
        obj._layout = list(layout)
        obj._padding = list(padding)
        obj._field_map = {f[0]: i for i, f in enumerate(layout)}
        Type.__init__(obj, nbytes * 8)
        return obj

    def _get_field(self, name):
        idx = self._field_map[name]
        fname, ftype, byte_off, bit_off = self._layout[idx]
        return BoundField(ftype, byte_off, bit_off)

    def __getattr__(self, name):
        try:
            fm = object.__getattribute__(self, "_field_map")
        except AttributeError:
            raise AttributeError(name)
        if name not in fm:
            raise AttributeError(f"struct '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __getitem__(self, name):
        if name not in self._field_map:
            raise KeyError(f"struct '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __str__(self):
        return self.display()

    def __repr__(self):
        return self.__str__()


class Union(Type):
    def __init__(self, name, fields):
        self.name = name
        self._fields = []
        self._layout = []
        self._field_map = {}

        max_size = 0
        for item in fields:
            fname, ftype = item
            self._fields.append((fname, ftype))
            idx = len(self._layout)
            self._layout.append((fname, ftype, 0, None))
            self._field_map[fname] = idx
            if ftype.nbytes > max_size:
                max_size = ftype.nbytes

        super().__init__(max_size * 8)

    def _get_field(self, name):
        idx = self._field_map[name]
        fname, ftype, byte_off, bit_off = self._layout[idx]
        return BoundField(ftype, byte_off, bit_off)

    def __getattr__(self, name):
        try:
            fm = object.__getattribute__(self, "_field_map")
        except AttributeError:
            raise AttributeError(name)
        if name not in fm:
            raise AttributeError(f"union '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __getitem__(self, name):
        if name not in self._field_map:
            raise KeyError(f"union '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __str__(self):
        return self.display()

    def __repr__(self):
        return self.__str__()


class Array(Type):
    def __init__(self, child, count):
        self.child = child
        self.count = count
        super().__init__(child.nbits * count)

    def __str__(self):
        if self.count == 0:
            return f"{self.child}[]"
        return f"{self.child}[{self.count}]"

    def __repr__(self):
        return self.__str__()


class Enum(Type):
    def __init__(self, child, members, name=None):
        self.child = child
        self.name = name
        self.members = dict(members)
        self._reverse = {v: k for k, v in self.members.items()}
        super().__init__(child.nbits)

    def __str__(self):
        if self.name:
            return f"enum {self.name} : {self.child}"
        return f"enum : {self.child}"

    def __repr__(self):
        return self.__str__()
