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

dis(0x8cc2a0, 0x80, "setter fn for +0x1a66 (tail)")

# find function start: scan back for prologue
for va in range(0x8cc321, 0x8cc321-0x200, -1):
    off = va - base
    if data[off:off+3] == b"\x55\x8b\xec" and data[off-1] in (0xc3, 0x90):
        print(f"prologue: {va:#x}")
        dis(va, 0x60, "setter head")
        # find callers
        for off2 in range(0, len(data)-5):
            if data[off2] == 0xE8:
                rel = struct.unpack("<i", data[off2+1:off2+5])[0]
                va2 = base + off2
                if va2 + 5 + rel == va:
                    print(f"  caller at {va2:#x}")
        break
