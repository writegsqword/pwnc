from ...util import *
from ... import err


def command(args: Args):
    libc_path = None

    potential_libcs = find_recursive("libc")
    if len(potential_libcs) == 0:
        err.warn("failed to locate libc. manually specify with --libc")

    if len(potential_libcs) == 1:
        libc_path = potential_libcs[0]
    else:
        err.warn("more than one potential libc found. selecting based on least path components.")
        potential_libcs = sorted(potential_libcs, key=lambda path: len(path.parts))
        first_match = len(potential_libcs[0].parts)
        second_match = len(potential_libcs[1].parts)
        if first_match == second_match:
            err.warn("more than one potential libc of the same path components.")
            

        else:
            libc_path = potential_libcs[0]