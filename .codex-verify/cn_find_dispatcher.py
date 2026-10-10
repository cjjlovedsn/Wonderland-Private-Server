import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

def find_all(pat):
    return [base + m.start() for m in re.finditer(re.escape(pat), data)]

# cmp r32, imm8 : 83 F8+r imm8  (eax,ecx,edx,ebx,esp,ebp,esi,edi)
def cmp_sites(v):
    out = []
    for r in range(8):
        out += find_all(bytes([0x83, 0xF8 + r, v]))
    return sorted(out)

# mov r32, imm32 : B8+r imm32
def mov_sites(v):
    out = []
    for r in (0, 1, 2, 3, 6, 7):
        out += find_all(bytes([0xB8 + r]) + struct.pack("<I", v))
    return sorted(out)

c33 = cmp_sites(0x33)
c15 = cmp_sites(0x15)
c3d = cmp_sites(0x3D)
m3b = mov_sites(0x3B)
m39 = mov_sites(0x39)
print(f"cmp 0x33: {len(c33)}, cmp 0x15: {len(c15)}, cmp 0x3d: {len(c3d)}, mov 0x3b: {len(m3b)}, mov 0x39: {len(m39)}")

# window: cmp 0x33 AND cmp 0x15 within 600B
print("\n== cmp,0x33 + cmp,0x15 within 600B ==")
cand = []
for a in c33:
    for b in c15:
        if 0 < b - a <= 600 or 0 < a - b <= 600:
            cand.append((min(a, b), max(a, b)))
seen = set()
for lo, hi in cand:
    if lo in seen: continue
    seen.add(lo)
    extra = []
    for c in c3d:
        if lo - 300 <= c <= hi + 900: extra.append(f"cmp3d@{c:08x}")
    for m in m3b:
        if lo - 300 <= m <= hi + 900: extra.append(f"mov3b@{m:08x}")
    for m in m39:
        if lo - 300 <= m <= hi + 1200: extra.append(f"mov39@{m:08x}")
    print(f"  0x33@{lo:08x}..0x15@{hi:08x}  {' '.join(extra)}")
