import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

# Find candidate AC dispatch sites: "cmp al, imm8 ; je/jne" and "cmp byte [..], imm8 ; je"
# for AC 23 (0x17) and 62 (0x3E), then show context clusters.
def scan_imm(imm):
    hits = []
    i = 0
    while i < n - 6:
        b = data[i]
        if b == 0x3C and data[i+1] == imm:  # cmp al, imm8
            j = i + 2
            if data[j] == 0x74:  # je short
                hits.append((i, "cmp al", data[j+1]))
            elif data[j:j+2] == b"\x0f\x84":  # je near
                hits.append((i, "cmp al", int.from_bytes(data[j+2:j+6], "little")))
        if b == 0x80:  # cmp r/m8, imm8
            modrm = data[i+1]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if reg == 7 and mod == 3 and data[i+2] == imm:  # cmp reg8, imm8
                j = i + 3
                if data[j] == 0x74:
                    hits.append((i, "cmp reg8", data[j+1]))
                elif data[j:j+2] == b"\x0f\x84":
                    hits.append((i, "cmp reg8", int.from_bytes(data[j+2:j+6], "little")))
        i += 1
    return hits

for ac, imm in (("AC23", 0x17), ("AC62", 0x3E)):
    hits = scan_imm(imm)
    print(f"== {ac} (0x{imm:02x}) cmp+je sites: {len(hits)}")
    for off, kind, jtarget in hits:
        va = base + off
        # decode branch target va (short rel from end of jcc = off + len + 1)
        # we stored raw operand for short; recompute properly:
        print(f"  va={va:08x} {kind}")
