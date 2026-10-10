import pefile
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

dis(0x8c55b0, 0x60, "case 0x0e handler region")
dis(0x8c55f0, 0x50, "case 0x0f handler region")
dis(0x8cc2a0, 0xb0, "floor setter 0x8cc2f4 head+all")
dis(0x8cb400, 0x60, "reset fn 0x8cb4xx")
dis(0x8cb660, 0xa0, "render reader floor 0x8cb688")
dis(0x8cbd50, 0x60, "render reader wall 0x8cbd70")
dis(0x8c1e00, 0x50, "wall default 0x9897 writer 0x8c1e2d")
