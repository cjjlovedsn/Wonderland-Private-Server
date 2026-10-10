import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

# known AC combos as little-endian words: A | B<<8
combos = {
    (8,2): 0x0208, (12,1): 0x010C, (15,1): 0x010F, (15,4): 0x040F,
    (15,9): 0x090F, (19,4): 0x0413, (23,4): 0x0417,
    (62,1): 0x013E, (62,3): 0x033E, (62,4): 0x043E, (62,14): 0x0E3E,
    (62,15): 0x0F3E, (65,1): 0x0141,
}

# cmp eax, imm32 ; cmp reg32, imm32 (81 F8-r) ; cmp ax, imm16 (66 3D / 66 81 F8-r)
print("== dword/word compares against combined AC value ==")
for (a, b), v in sorted(combos.items()):
    iw = v.to_bytes(2, "little")
    idw = v.to_bytes(4, "little")
    pats = [
        (b"\x3d" + idw, "cmp eax,%d"),
        (b"\x81\xf8" + idw, "cmp eax"),
        (b"\x81\xf9" + idw, "cmp ecx"),
        (b"\x81\xfe" + idw, "cmp esi"),
        (b"\x81\xff" + idw, "cmp edi"),
        (b"\x66\x3d" + iw, "cmp ax"),
        (b"\x66\x81\xf8" + iw, "cmp ax"),
        (b"\x66\x81\xf9" + iw, "cmp cx"),
        (b"\x66\x81\x3d" + b"...." + iw, "cmp [mem]"),
        (b"\x66\x81\x3e" + b"...." + iw, "cmp [esi]"),
    ]
    hits = []
    for p, lbl in pats:
        for m in re.finditer(re.escape(p), data):
            hits.append((base + m.start(), lbl))
    if hits:
        print(f"AC {a},{b} (0x{v:04x}):")
        for va, lbl in hits[:10]:
            print(f"  {va:08x}  {lbl}")
