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

def dump_tbl(addr, n, label, base_case):
    print(f"-- {label}: cases {base_case}..{base_case+n-1}")
    for k in range(n):
        t = rd32(addr + 4*k)
        print(f"   case {base_case+k:#04x} -> {t:08x}")

print("==== jump tables of 0x8c3e84 ====")
dump_tbl(0x8c3ef6, 35, "table1", 0)
dump_tbl(0x8c3fa0, 11, "table2 (0x2a..0x34)", 0x2a)
dump_tbl(0x8c3fea, 5,  "table3 (0x36..0x3a)", 0x36)

# the >0x3b chain at 0x8c3ffe
print("\n==== disasm 0x8c3ffe..0x8c4040 (chain for >0x3b + case1 start) ====")
for i in md.disasm(data[0x8c3ffe-base:0x8c4040-base], 0x8c3ffe):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")

print("\n==== case 1 handler @ 0x8c4025 ====")
cnt = 0
for i in md.disasm(data[0x8c4025-base:0x8c4025-base+0x180], 0x8c4025):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
    cnt += 1
    if i.mnemonic == 'jmp' and cnt > 8:
        break

print("\n==== case 4 handler @ 0x8c433d ====")
cnt = 0
for i in md.disasm(data[0x8c433d-base:0x8c433d-base+0x400], 0x8c433d):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
    cnt += 1
    if cnt > 150: break

print("\n==== caller context 0x769c00..0x769c70 ====")
for i in md.disasm(data[0x769c00-base:0x769c70-base], 0x769c00):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
