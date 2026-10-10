import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# all imm-load encodings for a byte value v: mov al/cl/dl/bl (B0..B3),
# mov eax/ecx/edx/ebx (B8..BB,BE,BF), push imm8 (6A), push imm32 (68)
def loads(v):
    pats = []
    for op in (0xB0, 0xB1, 0xB2, 0xB3):
        pats.append((re.escape(bytes([op, v])), 2))
    for op in (0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF):
        pats.append((re.escape(bytes([op])) + struct.pack("<I", v), 5))
    pats.append((re.escape(b"\x6a" + bytes([v])), 2))
    pats.append((re.escape(b"\x68" + struct.pack("<I", v)), 5))
    return pats

def sites(v):
    out = []
    for pat, ln in loads(v):
        for m in re.finditer(pat, data):
            out.append((base + m.start(), ln))
    return sorted(out)

ac_sites = sites(0x3E)
sub_sites = sites(0x3D)
print(f"0x3E loads: {len(ac_sites)}, 0x3D loads: {len(sub_sites)}")

print("\n== pairs (0x3E then 0x3D within 24B, or 0x3D then 0x3E within 24B) ==")
for va, ln in ac_sites:
    for va2, ln2 in sub_sites:
        d = va2 - va
        if 0 < d <= 24:
            print(f"  3E@{va:08x} -> 3D@{va2:08x} (gap {d})")
for va, ln in sub_sites:
    for va2, ln2 in ac_sites:
        d = va2 - va
        if 0 < d <= 24:
            print(f"  3D@{va:08x} -> 3E@{va2:08x} (gap {d})")
