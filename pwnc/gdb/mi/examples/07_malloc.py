from pwnc.gdb.mi import debug, Gdb

g = debug("../../../../tests/mi/libc.so.6")

def cb_malloc(g: Gdb):
    print(f"size = {g.reg.rdi:#x}")
    retaddr = int.from_bytes(g.read(g.reg.rsp, 8), "little")
    print(f"retaddr = {retaddr:#x}")
    print(g.sym.main_arena)

g.bp("write", cb_malloc)
g.run()
g.wait()