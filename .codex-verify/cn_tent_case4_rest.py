import pefile, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(va, n, label, stop_jmp_to_default=True):
    print(f"==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")

dis(0x8c45b1, 0x260, "case 4 rest (batch parse loop)")
dis(0x8c06b0, 0x180, "method 0x8c06b0 (store record / spawn)")
dis(0x8cf4a8, 0x100, "method 0x8cf4a8 (post-store action)")
