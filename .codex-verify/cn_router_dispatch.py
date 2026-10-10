import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# find router start: prologue before 0x769c00, within 0x3000
lo = 0x769c00 - 0x3000
starts = [lo + m.start() for m in re.finditer(rb"\x55\x8b\xec", data[lo-base:0x769c00-base])]
print("candidate starts:", [hex(x) for x in starts[-10:]])
fn = starts[-1]
print(f"router start guess: {fn:#x}")

# disassemble from start, stop at the first indirect jump / big switch
off = fn - base
for i in md.disasm(data[off:off+0x400], fn):
    print(f"{i.address:08x} {i.bytes.hex():<18} {i.mnemonic} {i.op_str}")
    if i.mnemonic == 'jmp' and 'ptr [' in i.op_str:
        print("  ^^ switch jump table found")
        break
