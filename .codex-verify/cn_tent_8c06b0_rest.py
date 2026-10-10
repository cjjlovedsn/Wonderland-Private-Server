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
        print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")

dis(0x8c06f4, 0x360, "0x8c06b0 body")
dis(0x8cf4a8, 0x120, "method 0x8cf4a8")
dis(0x8c4809, 0x110, "case4 per-record loop body")
