import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def rd32(va):
    return struct.unpack("<I", data[va-base:va-base+4])[0]

# find the jmp using a table near 0x754b1e: search jmp [eax*4+X] with X <= 0x754b1e < X+4*N
print("== indirect jmps with table covering 0x754b1e ==")
for m in re.finditer(rb"\xff\x24\x85....", data):
    va = base + m.start()
    tbl = struct.unpack("<I", m.group()[3:7])[0]
    if tbl <= 0x754b1e <= tbl + 4*300:
        print(f"  jmp @ {va:08x} -> table {tbl:08x}")

# also jmp [eax*4+X] via 0f b6 variants; dump raw table region
print("\n== table dwords 0x754ae0..0x754b60 ==")
for va in range(0x754ae0, 0x754b60, 4):
    print(f"  {va:08x}: {rd32(va):08x}")
