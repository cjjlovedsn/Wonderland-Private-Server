import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

for i in md.disasm(data[0x4fafa0-base:0x4fafa0-base+0x60], 0x4fafa0):
    print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
