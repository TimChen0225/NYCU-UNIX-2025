import re

with open("got_map.txt", "r") as f:
    lines = f.readlines()

got_hooks = []

for line in lines:
    match = re.match(r"gop_(\d+)\s+([0-9a-fA-Fx]+)", line)
    if match:
        index = int(match.group(1))
        offset = match.group(2)
        got_hooks.append((index, offset))

with open("got_map.h", "w") as out:
    out.write("#ifndef GOT_MAP_LOCAL_H\n")
    out.write("#define GOT_MAP_LOCAL_H\n\n")
    out.write("#include <stdint.h>\n\n")
    out.write("typedef struct {\n")
    out.write("    int index;\n")
    out.write("    uintptr_t got_offset;\n")
    out.write("} got_hook_t;\n\n")
    out.write("got_hook_t got_hooks[] = {\n")
    for index, offset in got_hooks:
        out.write(f"    {{ {index}, 0x{offset} }},\n")
    out.write("};\n\n")
    out.write("#endif // GOT_MAP_LOCAL_H\n")
