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

print("== dwords 0x7699f0..0x769a50 ==")
for va in range(0x7699f0, 0x769a50, 4):
    print(f"  {va:08x}: {rd32(va):08x}")

# find jmp/cmp referencing table 0x769a0b or nearby: search ff 24 85 xx xx xx xx with target near
print("\n== indirect jmps with tables in 0x769900..0x769b00 ==")
for m in re.finditer(rb"\xff\x24\x85....", data):
    va = base + m.start()
    if 0x769000 <= va <= 0x76a000:
        tbl = struct.unpack("<I", m.group()[3:7])[0]
        print(f"  jmp @ {va:08x} -> table {tbl:08x}")

print("\n== disasm 0x769960..0x769a0b ==")
for i in md.disasm(data[0x769960-base:0x769a0b-base], 0x769960):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
