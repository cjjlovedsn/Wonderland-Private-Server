import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

for pat, name in ((b"\x68\x1a\x00\x00", "+0x1a68"), (b"\x6a\x1a\x00\x00", "+0x1a6a")):
    print(f"\n### {name}")
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0: break
        pos = i + 1
        va = base + i
        if not (0x401000 <= va <= 0x9b4d24): continue
        for back in (8, 7, 6, 5, 3, 2):
            chunk = data[i-back:i-back+30]
            found = False
            for ins in md.disasm(chunk, va-back):
                if ins.address <= va < ins.address + len(ins.bytes):
                    if ins.mnemonic in ("mov","cmp","movzx"):
                        print(f"  ~{va:08x}: {ins.mnemonic} {ins.op_str}")
                        found = True
                    break
            if found: break
