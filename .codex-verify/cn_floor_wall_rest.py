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

dis(0x8cc34f, 0xa8, "floor setter else-branch (sprite load)")
dis(0x8cc80f, 0x30, "wall switch default")
dis(0x8cc425, 0x90, "wall setter itemDB branch")
