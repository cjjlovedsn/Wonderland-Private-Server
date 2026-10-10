import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

fields = {}
for f in range(0x1a60, 0x1a80, 2):
    pat = f.to_bytes(2, "little") + b"\x00\x00"
    pos = 0
    hits = []
    while True:
        i = data.find(pat, pos)
        if i < 0: break
        pos = i + 1
        va = base + i
        if not (0x401000 <= va <= 0x9b4d24): continue
        for back in (7, 6, 5, 3, 2):
            chunk = data[i-back:i-back+26]
            found = False
            for ins in md.disasm(chunk, va-back):
                if ins.address <= va < ins.address + len(ins.bytes):
                    if ins.mnemonic in ("mov","cmp","movzx","lea"):
                        hits.append((va, f"{ins.mnemonic} {ins.op_str}"))
                        found = True
                    break
            if found: break
    if hits:
        fields[f] = hits

for f in sorted(fields):
    print(f"\n### +0x{f:x}")
    for va, s_ in fields[f][:12]:
        print(f"  ~{va:08x}: {s_}")
