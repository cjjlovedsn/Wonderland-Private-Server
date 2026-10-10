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

dis(0x8c55fb, 0x120, "case 0x0f (sub15) start")
dis(0x8c5635, 0x100, "case 0x10 (sub16) start")
dis(0x8c56ca, 0xa0, "case 0x11 (sub17)")
