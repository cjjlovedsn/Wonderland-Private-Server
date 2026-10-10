import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

COPY = 0x405488

def call_target(va):
    off = va - base
    if data[off] != 0xE8:
        return None
    rel = struct.unpack("<i", data[off+1:off+5])[0]
    return va + 5 + rel

# mov ecx, 0x39 = B9 39 00 00 00 ; then look for call 0x405488 within 24 bytes
print("== mov ecx,0x39 .. call Copy(0x405488) sites ==")
sites = []
for m in re.finditer(rb"\xb9\x39\x00\x00\x00", data):
    va = base + m.start()
    for d in range(5, 29):
        t = call_target(va + d)
        if t == COPY:
            sites.append(va)
            print(f"  ecx=0x39 @ {va:08x}  call@{va+d:08x}")
            break

# also mov edx, 6 (Copy index 6) then mov ecx, 2 -> slot read; and edx=8
print("\n== Copy(pkt,6,2) sites (mov edx,6; mov ecx,2; .. call Copy) ==")
for m in re.finditer(rb"\xba\x06\x00\x00\x00", data):
    va = base + m.start()
    chunk = data[m.start():m.start()+32]
    m2 = re.search(rb"\xb9\x02\x00\x00\x00", chunk)
    if m2:
        # find call within chunk after ecx set
        for d in range(m2.end(), 32):
            t = call_target(va + d)
            if t == COPY:
                print(f"  Copy(pkt,6,2) @ {va:08x} call@{va+d:08x}")
                break

# Copy(pkt,8,0x39): edx=8 then ecx=0x39
print("\n== Copy(pkt,8,0x39) sites ==")
for m in re.finditer(rb"\xba\x08\x00\x00\x00", data):
    va = base + m.start()
    chunk = data[m.start():m.start()+32]
    m2 = re.search(rb"\xb9\x39\x00\x00\x00", chunk)
    if m2:
        for d in range(m2.end(), 32):
            t = call_target(va + d)
            if t == COPY:
                print(f"  Copy(pkt,8,57) @ {va:08x} call@{va+d:08x}")
                break
