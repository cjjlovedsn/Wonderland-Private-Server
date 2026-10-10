import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

events = []  # (offset, imm)
i = 0
while i < n - 4:
    b = data[i]
    if b == 0x3C:  # cmp al, imm8
        if data[i+2] == 0x74:          # je short
            events.append((i, data[i+1])); i += 4; continue
        if data[i+2:i+4] == b"\x0f\x84":  # je near
            events.append((i, data[i+1])); i += 8; continue
    if b == 0x80:  # cmp r/m8, imm8
        modrm = data[i+1]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if reg == 7:  # /7 = cmp
            if mod == 3:  # cmp reg8, imm8
                if data[i+3] == 0x74:
                    events.append((i, data[i+2])); i += 5; continue
                if data[i+3:i+5] == b"\x0f\x84":
                    events.append((i, data[i+2])); i += 9; continue
            elif mod == 1:  # cmp [r+disp8], imm8
                if data[i+4] == 0x74:
                    events.append((i, data[i+3])); i += 6; continue
                if data[i+4:i+6] == b"\x0f\x84":
                    events.append((i, data[i+3])); i += 10; continue
    i += 1

print("cmp+je events:", len(events))
targets = {3, 4, 6, 7}
ev = sorted(events)
clusters = []
k = 0
while k < len(ev):
    m = k
    seen = set()
    while m < len(ev) and ev[m][0] - ev[k][0] <= 1024:
        seen.add(ev[m][1]); m += 1
    if targets <= seen:
        clusters.append((ev[k][0], ev[m-1][0], sorted(x for x in seen if 1 <= x <= 12)))
        k = m
    else:
        k += 1

print("clusters (cmp je, 1KB window, imm subset 1..12):")
for st, en, imms in clusters:
    print("va=%08x-%08x imms=%s" % (base + st, base + en, imms))

# jump tables: jmp dword [reg*4 + disp32]
jt = []
for pat in (b"\xff\x24\x85", b"\xff\x24\x8d", b"\xff\x24\x95", b"\xff\x24\x9d", b"\xff\x24\xa5", b"\xff\x24\xad", b"\xff\x24\xb5", b"\xff\x24\xbd"):
    i = data.find(pat)
    while i >= 0:
        jt.append(i); i = data.find(pat, i + 1)
print("\nindexed jump tables:", len(jt))
for off in jt[:80]:
    print("  va=%08x" % (base + off))
