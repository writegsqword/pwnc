from pwnc.gdb.mi import debug, Gdb

g = debug("/bin/ls")

def cb_malloc(g: Gdb):
    print(f"size = {g.reg.rdi:#x}")
    retaddr = int.from_bytes(g.read(g.reg.rsp, 8), "little")
    print(f"retaddr = {retaddr:#x}")

g.bp("malloc", cb_malloc)
g.run()
g.wait()
print(g.sym.memcmp)