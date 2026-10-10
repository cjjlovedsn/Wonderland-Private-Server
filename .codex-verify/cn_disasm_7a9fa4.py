import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

fn = 0x7a9fa4
end = 0x7aad08
off = fn - base
print(f"==== disasm {fn:#x}..{end:#x} ====")
for i in md.disasm(data[off:off + (end - fn)], fn):
    print(f"{i.address:08x} {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")

print("\n==== callers of 0x7a9fa4 (E8 rel32) ====")
for m in re.finditer(rb"\xe8", data):
    va = base + m.start()
    rel = struct.unpack("<i", data[m.start()+1:m.start()+5])[0]
    if va + 5 + rel == fn:
        print(f"  call at {va:08x}")
