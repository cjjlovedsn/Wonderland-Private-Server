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

dis(0x8c9c01, 0x120, "AC64 sub2")
dis(0x8ca01d, 0x120, "AC64 sub3")
dis(0x8ca1e6, 0x100, "AC64 sub4")
dis(0x8ca67c, 0xd0, "AC64 sub5")
dis(0x8ca910, 0xd0, "AC64 sub6/7/8")
dis(0x8cac00, 0xd0, "AC64 sub9")
dis(0x8cace7, 0x80, "AC64 sub0x0a")
dis(0x8cae60, 0x40, "AC64 sub0x0b")
dis(0x8cae73, 0xd0, "AC64 sub0x0c")
dis(0x8caf57, 0x30, "AC64 sub0x0d")
dis(0x8caf68, 0x60, "AC64 sub0x0e")
dis(0x8cafe1, 0x20, "AC64 sub0x0f")
