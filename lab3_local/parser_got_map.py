import re

with open("got_map_local.txt", "r") as f:
    lines = f.readlines()

got_hooks = []

for line in lines:
    match = re.match(r"gop_(\d+)\s+([0-9a-fA-Fx]+)", line)
    if match:
        index = int(match.group(1))
        offset = match.group(2)
        got_hooks.append((index, offset))

# 輸出為 C struct 陣列
print("typedef struct {")
print("    int index;")
print("    uintptr_t got_offset;")
print("} got_hook_t;\n")

print("got_hook_t got_hooks[] = {")
for index, offset in got_hooks:
    print(f"    {{ {index}, {offset} }},")
print("};")
