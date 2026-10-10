import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

ids = [0x9871, 0x9866, 0x98d6, 0x98ed, 0x98f0, 0x98bc, 0x98f2]

def sites_for(v):
    out = []
    b2 = struct.pack("<H", v)
    pats = [
        b"\x66\x3d" + b2,             # cmp ax, imm16
        b"\x66\x81\xf8" + b2,          # cmp ax
        b"\x66\x81\xf9" + b2,          # cmp cx
        b"\x66\x81\xfa" + b2,          # cmp dx
        b"\x3d" + struct.pack("<I", v),  # cmp eax, imm32
        b"\x81\xf8" + struct.pack("<I", v),
        b"\x81\xf9" + struct.pack("<I", v),
        b"\x81\xba" + struct.pack("<I", v),
        b"\x81\xbf" + struct.pack("<I", v),
        b"\x66\x81\x3d" + b2,
    ]
    for p in pats:
        for m in re.finditer(re.escape(p), data):
            out.append(base + m.start())
    return out

allmap = {}
for v in ids:
    ss = sites_for(v)
    allmap[v] = ss
    print(f"{v:#06x}: {len(ss)} sites -> {[hex(x) for x in ss[:12]]}")

# cluster: any two distinct ids within 700 bytes
print("\n== clusters (two+ distinct magic IDs within 700B) ==")
flat = [(va, v) for v, ss in allmap.items() for va in ss]
flat.sort()
for i in range(len(flat)):
    va, v = flat[i]
    neigh = [(va2, v2) for va2, v2 in flat[i+1:] if va2 - va <= 700 and v2 != v]
    if neigh:
        print(f"  {va:08x} id={v:#06x} near {[(hex(a), hex(x)) for a, x in neigh[:6]]}")
