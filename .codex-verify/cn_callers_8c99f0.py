import pefile, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(va, n, label):
    print(f"\n==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

# find E8/E9 calls to 0x8c99f0 in text
tgt = 0x8c99f0
for off in range(0, len(data)-5):
    if data[off] in (0xE8, 0xE9):
        rel = struct.unpack("<i", data[off+1:off+5])[0]
        va = base + off
        if va + 5 + rel == tgt:
            kind = "call" if data[off]==0xE8 else "jmp"
            print(f"{kind} to 0x8c99f0 from {va:#x}")

dis(0x8c99f0, 0x90, "style packet fn head 0x8c99f0")
