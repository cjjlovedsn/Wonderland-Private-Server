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
    cnt = 0
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
        cnt += 1
        if i.mnemonic == 'jmp' and cnt > 6:
            break

dis(0x8c87f3, 0x110, "case 61 byte=1 branch")
dis(0x8c8803, 0x110, "case 61 byte=2 branch")
dis(0x8c39c8, 0x150, "case 59 -> 0x8c39c8")
dis(0x8cd880, 0x180, "case 60 -> 0x8cd880")
