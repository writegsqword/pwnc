"""pwnc.gdb.mi — GDB MI3 library with typed memory access.

Public API:
    Gdb          — main GDB controller
    debug(prog)  — spawn GDB on a program
    attach(pid)  — attach to a running process
"""

import os
import socket
import tempfile

from .process import GdbProcess
from .protocol import Connection
from .proxy import (
    PROXY_CLASSES, ProxyBase, BreakpointProxy, InferiorProxy,
    FrameProxy, ThreadProxy,
)
from pwnc.types.provider import BytesProvider, ByteOrder
from pwnc.types.primitives import Int, Float, Double, Ptr
from pwnc.types.containers import Struct, Union, Array, Enum


# --- Type descriptor → pwnc.types reconstruction ---

def pwnc_type_from_desc(desc):
    """Reconstruct a pwnc.types.Type from a serializable dict descriptor."""
    if desc is None:
        return None
    kind = desc["kind"]
    if kind == "int":
        return Int(desc["bits"], signed=desc.get("signed", False))
    if kind == "float":
        return Float()
    if kind == "double":
        return Double()
    if kind == "ptr":
        return Ptr(pwnc_type_from_desc(desc["child"]), bits=desc["bits"])
    if kind == "array":
        return Array(pwnc_type_from_desc(desc["child"]), desc["count"])
    if kind == "struct":
        fields = [(f["name"], pwnc_type_from_desc(f["type"])) for f in desc["fields"]]
        return Struct(desc["name"], fields)
    if kind == "union":
        fields = [(f["name"], pwnc_type_from_desc(f["type"])) for f in desc["fields"]]
        return Union(desc["name"], fields)
    if kind == "enum":
        return Enum(pwnc_type_from_desc(desc["child"]),
                    desc["members"], name=desc.get("name"))
    if kind == "void":
        return None
    # fallback
    return Int(desc.get("bits", 8), signed=False)


# --- Remote bytes provider ---

class GdbRemoteBytesProvider(BytesProvider):
    """BytesProvider that reads/writes memory via GDB bridge RPC."""

    def __init__(self, conn, base_addr, byteorder):
        self._conn = conn
        self._base_addr = base_addr
        self.byteorder = byteorder

    def read(self, offset, size):
        return bytes(self._conn.call("read_memory",
                                     self._base_addr + offset, size))

    def write(self, offset, data):
        self._conn.call("write_memory",
                        self._base_addr + offset, bytes(data))


# --- Symbol accessor ---

class SymbolAccessor:
    """Attribute-style symbol lookup: gdb.sym.main → typed Value."""

    def __init__(self, conn, byteorder):
        object.__setattr__(self, '_conn', conn)
        object.__setattr__(self, '_byteorder', byteorder)

    def __getattr__(self, name):
        result = self._conn.call("resolve_type", name)
        if result is None:
            raise AttributeError(f"Symbol '{name}' not found")

        desc, addr = result
        if addr is None:
            raise AttributeError(f"Symbol '{name}' has no address")

        # convert type descriptor to pwnc type
        if desc is not None:
            ptype = pwnc_type_from_desc(desc)
        else:
            # fallback: u8*
            ptype = Ptr(Int(8), bits=64)

        if ptype is None:
            ptype = Ptr(Int(8), bits=64)

        provider = GdbRemoteBytesProvider(self._conn, addr, self._byteorder)
        return ptype.use(provider)


# --- Registers ---

class Registers:
    """Attribute-style register access: gdb.reg.rax → int."""

    def __init__(self, conn):
        object.__setattr__(self, '_conn', conn)

    def __getattr__(self, name):
        return self._conn.call("get_register", name)

    def __setattr__(self, name, value):
        self._conn.call("set_register", name, value)


# --- Main GDB class ---

class Gdb:
    """GDB controller with MI3 interface, bridge RPC, and typed access."""

    def __init__(self, gdb_path="gdb", env=None):
        self.process = GdbProcess(gdb_path=gdb_path, env=env)
        self.conn: Connection | None = None
        self.sym: SymbolAccessor | None = None
        self.reg: Registers | None = None
        self._socket_path: str | None = None
        self._bridge_sock: socket.socket | None = None

    def _start_bridge(self):
        """Start the bridge inside GDB and connect to it."""
        # create a temp socket path
        self._socket_path = tempfile.mktemp(prefix="pwnc_bridge_", suffix=".sock")

        # find the bridge script
        bridge_path = os.path.join(os.path.dirname(__file__), "bridge.py")

        # set env var and source the bridge
        self.process.console(
            f'python import os; os.environ["_PWNC_BRIDGE_SOCKET"] = "{self._socket_path}"'
        )
        self.process.console(f'python exec(open("{bridge_path}").read())')

        # connect to the bridge socket
        self._bridge_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # retry connection briefly (bridge needs a moment to bind)
        import time
        for _ in range(50):
            try:
                self._bridge_sock.connect(self._socket_path)
                break
            except (ConnectionRefusedError, FileNotFoundError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Failed to connect to GDB bridge")

        self.conn = Connection(
            self._bridge_sock,
            proxy_classes=PROXY_CLASSES,
        )

        # detect byte order
        endian = self.conn.call("get_endian")
        bo = ByteOrder.Little if endian == "little" else ByteOrder.Big

        self.sym = SymbolAccessor(self.conn, bo)
        self.reg = Registers(self.conn)

    # --- Execution control ---

    def run(self, *args):
        """Start the program. MI: -exec-run"""
        self.process.command("exec-run")

    def cont(self):
        """Continue execution. MI: -exec-continue"""
        self.process.command("exec-continue")

    def interrupt(self):
        """Interrupt (pause) execution. MI: -exec-interrupt"""
        self.process.command("exec-interrupt")

    def stepi(self):
        """Step one machine instruction (into calls). MI: -exec-step-instruction"""
        self.process.command("exec-step-instruction")

    def nexti(self):
        """Step one machine instruction (over calls). MI: -exec-next-instruction"""
        self.process.command("exec-next-instruction")

    def step(self):
        """Step one source line (into calls). MI: -exec-step"""
        self.process.command("exec-step")

    def next(self):
        """Step one source line (over calls). MI: -exec-next"""
        self.process.command("exec-next")

    def skip(self):
        """Skip current instruction without executing it."""
        self.conn.call("skip_instruction")

    def wait(self):
        """Block until inferior stops. Returns stop reason dict."""
        return self.process.wait_for_stop()

    # --- Breakpoints ---

    def bp(self, location, **kwargs) -> BreakpointProxy:
        """Set a breakpoint. Returns a BreakpointProxy."""
        return self.conn.call("create_breakpoint", location, **kwargs)

    # --- Direct access ---

    def inferior(self) -> InferiorProxy:
        """Get the selected inferior."""
        return self.conn.call("selected_inferior")

    def frame(self) -> FrameProxy:
        """Get the selected frame."""
        return self.conn.call("selected_frame")

    def thread(self) -> ThreadProxy:
        """Get the selected thread."""
        return self.conn.call("selected_thread")

    # --- Console ---

    def execute(self, cmd: str) -> str:
        """Execute a GDB CLI command and return its output."""
        return self.process.console(cmd)

    # --- Memory convenience ---

    def read(self, addr, size) -> bytes:
        """Read memory from the inferior."""
        return bytes(self.conn.call("read_memory", addr, size))

    def write(self, addr, data):
        """Write memory to the inferior."""
        self.conn.call("write_memory", addr, bytes(data))

    # --- Lifecycle ---

    def close(self):
        """Shut down GDB and clean up."""
        if self.conn:
            self.conn.close()
        self.process.close()
        if self._socket_path and os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- Convenience constructors ---

def debug(program, *args, gdb_path="gdb", env=None, **kwargs) -> Gdb:
    """Spawn GDB on a program, start the bridge, and return a Gdb instance."""
    g = Gdb(gdb_path=gdb_path, env=env)
    extra = []
    if args:
        extra.append("--args")
        extra.extend(str(a) for a in args)
    g.process.start(program=program, extra_args=extra if extra else None)
    g._start_bridge()
    return g


def attach(pid_or_name, gdb_path="gdb", env=None, **kwargs) -> Gdb:
    """Attach GDB to a running process (by PID or name)."""
    g = Gdb(gdb_path=gdb_path, env=env)

    if isinstance(pid_or_name, int):
        g.process.start(pid=pid_or_name)
    else:
        # look up PID by name
        import shutil
        pidof = shutil.which("pidof")
        if pidof:
            import subprocess
            result = subprocess.run([pidof, pid_or_name],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                pid = int(result.stdout.strip().split()[0])
                g.process.start(pid=pid)
            else:
                raise RuntimeError(f"Process '{pid_or_name}' not found")
        else:
            raise RuntimeError("pidof not available; pass a PID instead")

    g._start_bridge()
    return g
