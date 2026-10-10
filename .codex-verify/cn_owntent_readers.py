import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(va, n, label):
    print(f"==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
    print()

dis(0x7fd340, 0x90, "reader 0x7fd3xx")
dis(0x80e160, 0xb0, "reader 0x80e1xx")
dis(0x8bbf50, 0x60, "reader 0x8bbfxx")
dis(0x546b60, 0x120, "reader 0x546bxx")
