import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# find function start before 0x8c402c: scan back for 55 8B EC preceded by ret/int3/pad
target = 0x8c402c
lo = target - 0x800
starts = []
for m in re.finditer(rb"\x55\x8b\xec", data[lo-base:target-base]):
    starts.append(lo + m.start())
print("candidate prologues:", [hex(x) for x in starts[-8:]])
fn = starts[-1]
print(f"chosen fn start: {fn:#x}")

# disassemble to next ret-ish or 0x600 bytes
off = fn - base
count = 0
for i in md.disasm(data[off:off+0x900], fn):
    print(f"{i.address:08x} {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")
    count += 1
    if count > 400:
        break

print("\n==== callers ====")
for m in re.finditer(rb"\xe8", data):
    va = base + m.start()
    rel = struct.unpack("<i", data[m.start()+1:m.start()+5])[0]
    if va + 5 + rel == fn:
        print(f"  call at {va:08x}")
