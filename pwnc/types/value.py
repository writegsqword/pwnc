import struct as _struct
from .provider import BufferProvider, ByteOrder
from .primitives import Int, Bits, Float, Double, Ptr
from .containers import Struct, Union, Array, Enum

class Value:
    def __init__(self, type, provider, base_offset):
        object.__setattr__(self, "_type", type)
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_base_offset", base_offset)

    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, value):
        self._type = value

    @property
    def address(self):
        return self._provider.address + self._base_offset

    def ref(self, bits=64):
        try:
            addr = self.address
        except TypeError:
            raise TypeError("ref() requires a remote-backed value (no address available for local buffers)")
        ptr_type = Ptr(self._type, bits=bits)
        bo = self._provider.byteorder
        byte_order = "little" if bo == ByteOrder.Little else "big"
        buf = addr.to_bytes(ptr_type.nbytes, byte_order)
        return Value(ptr_type, BufferProvider(bytearray(buf), bo), 0)

    @property
    def offset(self):
        return self._base_offset

    @property
    def nbytes(self):
        return self._type.nbytes

    @property
    def nbits(self):
        return self._type.nbits

    @property
    def bytes(self):
        return self._provider.read(self._base_offset, self._type.nbytes)

    def use(self, data):
        return self._type.use(data)

    def detach(self):
        raw = self._provider.read(self._base_offset, self._type.nbytes)
        new_provider = BufferProvider(bytearray(raw), self._provider.byteorder)
        return Value(self._type, new_provider, 0)

    def cast(self, target):
        if isinstance(target, Value):
            target = target._type
        return Value(target, self._provider, self._base_offset)

    def _resolve(self):
        """Resolve this value to a Python object (int, float, etc.)."""

        ty = self._type

        if isinstance(ty, Bits):
            # Need to find the bit position within the containing struct
            # Bits fields are read as part of the byte at base_offset
            # The bit_offset is tracked by the parent Value access
            raw = self._provider.read(self._base_offset, 1)
            byte_val = raw[0]
            # bit_offset is stored on the Value when created from struct access
            bit_off = getattr(self, '_bit_offset', 0)
            mask = (1 << ty.nbits) - 1
            return (byte_val >> bit_off) & mask

        if isinstance(ty, (Int, Ptr)):
            raw = self._provider.read(self._base_offset, ty.nbytes)
            bo = "little" if self._provider.byteorder == ByteOrder.Little else "big"
            val = int.from_bytes(raw, bo)
            if isinstance(ty, Int) and ty.signed:
                # sign extend
                if val >= (1 << (ty.nbits - 1)):
                    val -= (1 << ty.nbits)
            return val

        if isinstance(ty, Float):
            raw = self._provider.read(self._base_offset, 4)
            fmt = "<f" if self._provider.byteorder == ByteOrder.Little else ">f"
            return _struct.unpack(fmt, raw)[0]

        if isinstance(ty, Double):
            raw = self._provider.read(self._base_offset, 8)
            fmt = "<d" if self._provider.byteorder == ByteOrder.Little else ">d"
            return _struct.unpack(fmt, raw)[0]

        if isinstance(ty, Enum):
            # resolve the underlying integer
            inner_val = Value(ty.child, self._provider, self._base_offset)._resolve()
            return inner_val

        # containers return self (not resolved to a primitive)
        return self

    def _write(self, ty, offset, value):
        """Write a Python value to the provider at the given offset."""

        if isinstance(value, Value):
            if isinstance(value._type, (Int, Enum, Ptr)):
                value = value._resolve()

        if isinstance(ty, Enum):
            ty = ty.child

        bo = self._provider.byteorder

        if isinstance(ty, Bits):
            bit_off = getattr(self, '_bit_offset', 0)
            mask = (1 << ty.nbits) - 1
            raw = bytearray(self._provider.read(offset, 1))
            raw[0] = (raw[0] & ~(mask << bit_off)) | ((value & mask) << bit_off)
            self._provider.write(offset, bytes(raw))
        elif isinstance(ty, (Int, Ptr)):
            byte_order = "little" if bo == ByteOrder.Little else "big"
            if isinstance(ty, Int) and ty.signed and value < 0:
                value = value + (1 << ty.nbits)
            data = value.to_bytes(ty.nbytes, byte_order)
            self._provider.write(offset, data)
        elif isinstance(ty, Float):
            fmt = "<f" if bo == ByteOrder.Little else ">f"
            self._provider.write(offset, _struct.pack(fmt, value))
        elif isinstance(ty, Double):
            fmt = "<d" if bo == ByteOrder.Little else ">d"
            self._provider.write(offset, _struct.pack(fmt, value))
        else:
            raise TypeError(f"cannot write to field of type {type(ty).__name__}")

    def __setattr__(self, name, value):
        ty = self._type
        if not isinstance(ty, (Struct, Union)):
            raise AttributeError(f"cannot set fields on {type(ty).__name__} value")

        # Use __getitem__ on the type to get the BoundField (bypasses
        # Struct attribute priority, works for all field names)
        bf = ty[name]
        field_offset = self._base_offset + bf.offset
        field_type = bf._type

        if isinstance(field_type, Bits):
            child_val = Value(field_type, self._provider, field_offset)
            object.__setattr__(child_val, '_bit_offset', bf.bit_offset if bf.bit_offset is not None else 0)
            child_val._write(field_type, field_offset, value)
        elif isinstance(field_type, (Int, Float, Double, Ptr, Enum)):
            self._write(field_type, field_offset, value)
        else:
            raise TypeError(
                f"cannot assign to field '{name}' of type "
                f"{type(field_type).__name__}; only primitive fields are writable"
            )

    def __getattr__(self, name):
        ty = self._type

        if isinstance(ty, (Struct, Union)):
            bf = getattr(ty, name)  # returns BoundField
            new_offset = self._base_offset + bf.offset
            child_val = Value(bf._type, self._provider, new_offset)

            # for Bits fields, attach bit_offset
            if isinstance(bf._type, Bits) and bf.bit_offset is not None:
                object.__setattr__(child_val, '_bit_offset', bf.bit_offset)

            # if child is a primitive, resolve immediately
            if isinstance(bf._type, (Int, Float, Double, Enum)):
                return child_val._resolve()

            # if child is Array, return a ArrayValue
            if isinstance(bf._type, Array):
                return ArrayValue(bf._type, self._provider, new_offset)

            # containers return Value (lazy)
            return child_val

        raise AttributeError(f"Value has no attribute '{name}'")

    def __getitem__(self, index):
        if isinstance(self._type, Ptr):
            if self._type.child is None:
                raise TypeError("cannot dereference void pointer")
            addr = self._resolve()
            child = self._type.child
            target_addr = addr + index * child.nbytes
            new_provider = self._provider.rebase(target_addr)
            child_val = Value(child, new_provider, 0)
            if isinstance(child, (Int, Float, Double, Enum)):
                return child_val._resolve()
            if isinstance(child, Array):
                return ArrayValue(child, new_provider, 0)
            return child_val
        if isinstance(self._type, Array):
            return ArrayValue(self._type, self._provider, self._base_offset)[index]
        raise TypeError(f"Value of type {type(self._type).__name__} is not subscriptable")

    def __setitem__(self, index, value):
        if isinstance(self._type, Ptr):
            if self._type.child is None:
                raise TypeError("cannot dereference void pointer")
            addr = self._resolve()
            child = self._type.child
            target_addr = addr + index * child.nbytes
            new_provider = self._provider.rebase(target_addr)
            child_val = Value(child, new_provider, 0)
            child_val._write(child, 0, value)
            return
        if isinstance(self._type, Array):
            ArrayValue(self._type, self._provider, self._base_offset)[index] = value
            return
        raise TypeError(f"Value of type {type(self._type).__name__} does not support item assignment")

    def display(self, depth=None, filter=None):
        from .display import format_value
        return format_value(self, depth=depth, filter=filter)

    def __str__(self):
        ty = self._type
        if isinstance(ty, (Int, Float, Double, Ptr)):
            val = self._resolve()
            if isinstance(ty, Ptr):
                return f"0x{val:x}"
            return str(val)

        if isinstance(ty, Enum):
            val = self._resolve()
            name = ty._reverse.get(val)
            if name:
                return f"{name} ({val})"
            return str(val)

        if isinstance(ty, Array):
            return str(ArrayValue(ty, self._provider, self._base_offset))

        return self.display()

    def __repr__(self):
        return self.__str__()

    def __int__(self):
        return self._resolve()

    def __float__(self):
        return float(self._resolve())

    # --- Arithmetic helpers ---

    def _to_python(self):
        val = self._resolve()
        if val is self:
            raise TypeError(f"cannot perform arithmetic on {type(self._type).__name__} value")
        return val

    @staticmethod
    def _other_val(other):
        if isinstance(other, Value):
            return other._to_python()
        return other

    def _ptr_result(self, addr):
        new_provider = self._provider.rebase(addr)
        return Value(self._type, new_provider, 0)

    # --- Arithmetic operators ---

    def __add__(self, other):
        if isinstance(self._type, Ptr):
            n = self._other_val(other)
            child = self._type.child
            if child is None:
                return self._ptr_result(self._resolve() + n)
            return self._ptr_result(self._resolve() + n * child.nbytes)
        return self._to_python() + self._other_val(other)

    def __radd__(self, other):
        if isinstance(self._type, Ptr):
            child = self._type.child
            if child is None:
                return self._ptr_result(other + self._resolve())
            return self._ptr_result(other * child.nbytes + self._resolve())
        return other + self._to_python()

    def __sub__(self, other):
        if isinstance(self._type, Ptr):
            if isinstance(other, Value) and isinstance(other._type, Ptr):
                child = self._type.child
                if child is None or child.nbytes == 0:
                    return self._resolve() - other._resolve()
                return (self._resolve() - other._resolve()) // child.nbytes
            n = self._other_val(other)
            child = self._type.child
            if child is None:
                return self._ptr_result(self._resolve() - n)
            return self._ptr_result(self._resolve() - n * child.nbytes)
        return self._to_python() - self._other_val(other)

    def __rsub__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other - self._resolve())
        return other - self._to_python()

    def __mul__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() * self._other_val(other))
        return self._to_python() * self._other_val(other)

    def __rmul__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other * self._resolve())
        return other * self._to_python()

    def __truediv__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(int(self._resolve() / self._other_val(other)))
        return self._to_python() / self._other_val(other)

    def __rtruediv__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(int(other / self._resolve()))
        return other / self._to_python()

    def __floordiv__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() // self._other_val(other))
        return self._to_python() // self._other_val(other)

    def __rfloordiv__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other // self._resolve())
        return other // self._to_python()

    def __mod__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() % self._other_val(other))
        return self._to_python() % self._other_val(other)

    def __rmod__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other % self._resolve())
        return other % self._to_python()

    def __pow__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() ** self._other_val(other))
        return self._to_python() ** self._other_val(other)

    def __rpow__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other ** self._resolve())
        return other ** self._to_python()

    # --- Bitwise operators ---

    def __and__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() & self._other_val(other))
        return self._to_python() & self._other_val(other)

    def __rand__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other & self._resolve())
        return other & self._to_python()

    def __or__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() | self._other_val(other))
        return self._to_python() | self._other_val(other)

    def __ror__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other | self._resolve())
        return other | self._to_python()

    def __xor__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() ^ self._other_val(other))
        return self._to_python() ^ self._other_val(other)

    def __rxor__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other ^ self._resolve())
        return other ^ self._to_python()

    def __lshift__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() << self._other_val(other))
        return self._to_python() << self._other_val(other)

    def __rlshift__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other << self._resolve())
        return other << self._to_python()

    def __rshift__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve() >> self._other_val(other))
        return self._to_python() >> self._other_val(other)

    def __rrshift__(self, other):
        if isinstance(self._type, Ptr):
            return self._ptr_result(other >> self._resolve())
        return other >> self._to_python()

    # --- Unary operators ---

    def __neg__(self):
        if isinstance(self._type, Ptr):
            return self._ptr_result(-self._resolve())
        return -self._to_python()

    def __pos__(self):
        if isinstance(self._type, Ptr):
            return self._ptr_result(self._resolve())
        return +self._to_python()

    def __invert__(self):
        if isinstance(self._type, Ptr):
            mask = (1 << self._type.nbits) - 1
            return self._ptr_result(self._resolve() ^ mask)
        return ~self._to_python()

    # --- Comparison operators ---

    def __eq__(self, other):
        try:
            return self._to_python() == self._other_val(other)
        except TypeError:
            return NotImplemented

    def __ne__(self, other):
        try:
            return self._to_python() != self._other_val(other)
        except TypeError:
            return NotImplemented

    def __lt__(self, other):
        try:
            return self._to_python() < self._other_val(other)
        except TypeError:
            return NotImplemented

    def __le__(self, other):
        try:
            return self._to_python() <= self._other_val(other)
        except TypeError:
            return NotImplemented

    def __gt__(self, other):
        try:
            return self._to_python() > self._other_val(other)
        except TypeError:
            return NotImplemented

    def __ge__(self, other):
        try:
            return self._to_python() >= self._other_val(other)
        except TypeError:
            return NotImplemented

    def __bool__(self):
        return bool(self._to_python())


class ArrayValue(Value):
    def __init__(self, type, provider, base_offset):
        super().__init__(type, provider, base_offset)

    def __getitem__(self, index):
        child = self._type.child
        elem_offset = self._base_offset + index * child.nbytes
        elem_val = Value(child, self._provider, elem_offset)

        if isinstance(child, (Int, Float, Double, Enum)):
            return elem_val._resolve()

        return elem_val

    def __setitem__(self, index, value):
        child = self._type.child
        elem_offset = self._base_offset + index * child.nbytes
        elem_val = Value(child, self._provider, elem_offset)
        elem_val._write(child, elem_offset, value)

    def __len__(self):
        return self._type.count

    def __str__(self):
        ty = self._type
        if ty.count == 0:
            return "[]"

        max_show = 8
        items = []
        for i in range(min(ty.count, max_show)):
            items.append(str(self[i]))

        if ty.count > max_show:
            return "[" + ", ".join(items[:-1]) + ", ...]"
        return "[" + ", ".join(items) + "]"
