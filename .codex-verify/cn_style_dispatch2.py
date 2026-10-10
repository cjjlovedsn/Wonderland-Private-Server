import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def rd32(va):
    off = va - base
    return int.from_bytes(data[off:off+4], "little")

print("style dispatcher 2 jump table @ 0x8c9a52 (16 entries):")
for i in range(16):
    tgt = rd32(0x8c9a52 + i*4)
    print(f"  sub {i:2d} (0x{i:02x}): -> 0x{tgt:08x}")

def dis(va, n, label):
    print(f"\n==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

dis(0x769c4d, 0x120, "AC62 dense57 entry 0x769c4d")
