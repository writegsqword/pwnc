# gdbmi plugin

Scripting gdb console and gdb python api from a python script.

## gdb management

Spawn a gdb subprocess in `mi3` interpreter mode. Allows execution of commands directly to the gdb console via python, as well as spawning a `console` interpreter in the same session but attached to a new terminal.

## python execution

Run a small bridge program inside of gdb to allow access to the python api. Communicate over a unix socket to send values back and forth, which should be serialized and deserialized using pickle. For important classes make proxy objects that can be used in the script and refer to objects on the gdb side (Inferior, Breakpoint, Function, Frame, etc).
