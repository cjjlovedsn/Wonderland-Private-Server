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

dis(0x8c5c10, 0x80, "case0x16")
dis(0x8c60f3, 0x80, "case0x18")
dis(0x8c66db, 0x60, "case0x1f")
dis(0x8c6930, 0x60, "case0x20")
dis(0x8cb134, 0xa0, "style getter 0x8cb134")
