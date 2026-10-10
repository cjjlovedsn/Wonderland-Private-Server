import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

lo = 0x769c00 - 0x10000
starts = [lo + m.start() for m in re.finditer(rb"\x55\x8b\xec", data[lo-base:0x769c00-base])]
print("candidate starts (last 12):", [hex(x) for x in starts[-12:]])

# disasm backward context: 0x769b80..0x769c60
for i in md.disasm(data[0x769b80-base:0x769c60-base], 0x769b80):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
