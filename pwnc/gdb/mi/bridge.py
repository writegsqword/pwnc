"""GDB-side bridge script — runs inside the GDB Python interpreter.

Provides RPC access to GDB's Python API over a Unix socket.
Loaded by GdbProcess via: python exec(open('bridge.py').read())
"""

import io
import os
import pickle
import queue
import socket
import struct
import threading
import traceback


# --- Wire format helpers (duplicated here to avoid import from host) ---

class Call:
    __slots__ = ('id', 'method', 'args', 'kwargs')
    def __init__(self, id, method, args, kwargs):
        self.id = id
        self.method = method
        self.args = args
        self.kwargs = kwargs

class Return:
    __slots__ = ('id', 'value')
    def __init__(self, id, value):
        self.id = id
        self.value = value

class Error:
    __slots__ = ('id', 'exception')
    def __init__(self, id, exception):
        self.id = id
        self.exception = exception

class Release:
    __slots__ = ('oid',)
    def __init__(self, oid):
        self.oid = oid


# --- Object store for proxy references ---

object_store = {}


# --- GDB type proxy serialization ---

import gdb

PROXY_TYPES = (
    gdb.InferiorThread,
    gdb.Inferior,
    gdb.Progspace,
    gdb.Frame,
    gdb.Symbol,
    gdb.Block,
    gdb.Breakpoint,
)


class BridgePickler(pickle.Pickler):
    def persistent_id(self, obj):
        for cls in PROXY_TYPES:
            if isinstance(obj, cls):
                oid = id(obj)
                object_store[oid] = obj
                return (type(obj).__name__, oid)
        return None


class BridgeUnpickler(pickle.Unpickler):
    """Client-side objects aren't proxied back — use default unpickling."""
    pass


# --- RPC handlers ---

handlers = {}


def handler(name):
    def decorator(fn):
        handlers[name] = fn
        return fn
    return decorator


# --- Generic proxy handlers ---

@handler("proxy.call")
def proxy_call(oid, method_name, args, kwargs):
    obj = object_store[oid]
    return getattr(obj, method_name)(*args, **kwargs)


@handler("proxy.get")
def proxy_get(oid, attr_name):
    obj = object_store[oid]
    return getattr(obj, attr_name)


@handler("proxy.set")
def proxy_set(oid, attr_name, value):
    obj = object_store[oid]
    setattr(obj, attr_name, value)


@handler("proxy.release")
def proxy_release(oid):
    object_store.pop(oid, None)


# --- Utility handlers ---

@handler("selected_inferior")
def selected_inferior():
    return gdb.selected_inferior()


@handler("selected_frame")
def selected_frame():
    return gdb.selected_frame()


@handler("selected_thread")
def selected_thread():
    return gdb.selected_thread()


@handler("lookup_symbol")
def lookup_symbol(name):
    result = gdb.lookup_symbol(name)
    return result  # (Symbol, is_field_of_this) or (None, False)


@handler("read_memory")
def read_memory(addr, size):
    inf = gdb.selected_inferior()
    mv = inf.read_memory(addr, size)
    return bytes(mv)


@handler("write_memory")
def write_memory(addr, data):
    inf = gdb.selected_inferior()
    inf.write_memory(addr, data)


@handler("skip_instruction")
def skip_instruction():
    frame = gdb.selected_frame()
    arch = frame.architecture()
    pc = frame.pc()
    insn = arch.disassemble(pc, count=1)[0]
    new_pc = pc + insn['length']
    gdb.execute(f"set $pc = {new_pc}")


@handler("get_register")
def get_register(name):
    frame = gdb.selected_frame()
    return int(frame.read_register(name))


@handler("set_register")
def set_register(name, value):
    gdb.execute(f"set ${name} = {value}")


@handler("create_breakpoint")
def create_breakpoint(spec, **kwargs):
    return gdb.Breakpoint(spec, **kwargs)


# --- GDB type → pwnc type descriptor ---

@handler("resolve_type")
def resolve_type(name):
    """Look up a symbol, return (type_desc, address) for pwnc.types construction."""
    result = gdb.lookup_symbol(name)
    sym = result[0]
    if sym is None:
        return None

    try:
        addr = int(sym.value().address)
    except Exception:
        addr = None

    try:
        gdb_type = sym.type
        desc = gdb_type_to_pwnc(gdb_type)
    except Exception:
        desc = None

    return (desc, addr)


def gdb_type_to_pwnc(gdb_type):
    """Convert a gdb.Type to a serializable dict describing a pwnc.types.Type."""
    t = gdb_type.strip_typedefs()
    code = t.code

    if code == gdb.TYPE_CODE_INT:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": t.is_signed}
    elif code == gdb.TYPE_CODE_CHAR:
        return {"kind": "int", "bits": 8, "signed": t.is_signed}
    elif code == gdb.TYPE_CODE_BOOL:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": False}
    elif code == gdb.TYPE_CODE_FLT:
        if t.sizeof == 4:
            return {"kind": "float"}
        else:
            return {"kind": "double"}
    elif code == gdb.TYPE_CODE_PTR:
        return {"kind": "ptr", "child": gdb_type_to_pwnc(t.target()), "bits": t.sizeof * 8}
    elif code == gdb.TYPE_CODE_ARRAY:
        target = t.target()
        low, high = t.range()
        count = high - low + 1
        return {"kind": "array", "child": gdb_type_to_pwnc(target), "count": count}
    elif code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        fields = []
        for f in t.fields():
            fields.append({
                "name": f.name,
                "type": gdb_type_to_pwnc(f.type),
                "offset": f.bitpos // 8,
                "bit_offset": f.bitpos % 8,
            })
        kind = "struct" if code == gdb.TYPE_CODE_STRUCT else "union"
        return {"kind": kind, "name": t.tag or t.name or "<anon>",
                "fields": fields, "size": t.sizeof}
    elif code == gdb.TYPE_CODE_ENUM:
        members = {f.name: f.enumval for f in t.fields()}
        try:
            child_desc = gdb_type_to_pwnc(t.target())
        except Exception:
            child_desc = {"kind": "int", "bits": t.sizeof * 8, "signed": False}
        return {"kind": "enum", "child": child_desc,
                "members": members, "name": t.tag or t.name}
    elif code == gdb.TYPE_CODE_VOID:
        return {"kind": "void"}
    else:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": False}


@handler("get_endian")
def get_endian():
    """Return the target byte order as 'little' or 'big'."""
    endian = gdb.execute("show endian", to_string=True)
    if "little" in endian:
        return "little"
    return "big"


# --- Socket server ---

def _recvall(sock, n):
    parts = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        parts.append(chunk)
        remaining -= len(chunk)
    return b''.join(parts)


def _send_msg(sock, msg):
    buf = io.BytesIO()
    p = BridgePickler(buf)
    p.dump(msg)
    data = buf.getvalue()
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)


def _recv_msg(sock):
    header = _recvall(sock, 4)
    if header is None:
        return None
    length = struct.unpack('>I', header)[0]
    data = _recvall(sock, length)
    if data is None:
        return None
    buf = io.BytesIO(data)
    u = BridgeUnpickler(buf)
    return u.load()


def _handle_client(conn_sock):
    """Handle a single client connection."""
    while True:
        msg = _recv_msg(conn_sock)
        if msg is None:
            break

        if isinstance(msg, Call):
            h = handlers.get(msg.method)
            if h is None:
                _send_msg(conn_sock, Error(id=msg.id,
                          exception=f"Unknown method: {msg.method}"))
                continue

            # execute handler via gdb.post_event for thread safety
            result_q = queue.Queue()

            def do_call(handler=h, call_msg=msg, rq=result_q):
                try:
                    result = handler(*call_msg.args, **call_msg.kwargs)
                    rq.put(Return(id=call_msg.id, value=result))
                except Exception:
                    rq.put(Error(id=call_msg.id,
                                exception=traceback.format_exc()))

            gdb.post_event(do_call)
            response = result_q.get()
            _send_msg(conn_sock, response)

        elif isinstance(msg, Release):
            object_store.pop(msg.oid, None)


def start_bridge(socket_path):
    """Start the bridge server on a Unix socket.

    Called by GdbProcess after spawning GDB.
    """
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)

    # signal ready by printing to stdout (captured by GdbProcess)
    print(f"BRIDGE_READY:{socket_path}", flush=True)

    def accept_loop():
        while True:
            try:
                conn_sock, _ = server.accept()
                _handle_client(conn_sock)
            except Exception:
                traceback.print_exc()
                break

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()


# --- Auto-start when sourced ---

import sys as _sys

if __name__ == '__main__' or '_PWNC_BRIDGE_SOCKET' in os.environ:
    _socket_path = os.environ.get('_PWNC_BRIDGE_SOCKET', '')
    if _socket_path:
        start_bridge(_socket_path)
