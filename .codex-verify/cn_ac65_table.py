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

print("AC65 sub jump table @ 0x769d98:")
for i in range(15):
    va = 0x769d98 + i*4
    tgt = rd32(va)
    print(f"  sub {i:2d} (0x{i:02x}): entry@{va:08x} -> 0x{tgt:08x}")

def dis(va, n, label):
    print(f"\n==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
        if i.mnemonic == 'jmp':
            break

# disassemble dispatcher head first to confirm table bounds
dis(0x769d65, 0x40, "AC65 dispatcher head")
