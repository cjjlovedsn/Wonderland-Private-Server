import pefile, re
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# any instruction that embeds the address as imm32: search raw little-endian
for tbl in (0x9cda64, 0x9cd1dc):
    pat = tbl.to_bytes(4, "little")
    print(f"\n### refs to 0x{tbl:08x}:")
    start = 0
    n = 0
    while True:
        i = data.find(pat, start)
        if i < 0 or n > 30: break
        va = base + i
        start = i + 1
        # skip if inside our own address (data area) — only show code refs (0x401000..0x9b4d24 text)
        if va > 0x9b4d24 or va < 0x401000:
            continue
        # try to disasm at va-6..va-2 to find containing instruction
        found = False
        for back in (7,6,5,4,3,2):
            chunk = data[i-back:i-back+24]
            for ins in md.disasm(chunk, va-back):
                if ins.address <= va < ins.address + len(ins.bytes):
                    print(f"  ~{va:08x}: {ins.mnemonic} {ins.op_str}")
                    found = True
                    break
            if found: break
        if not found:
            print(f"  ~{va:08x}: (imm32 embedded)")
        n += 1
