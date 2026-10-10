import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

# collect cmp al, imm8; jcc (3C ib 7x) and cmp al,imm8; jcc far (0F 8x)
cmps = []
i = 0
n = len(data)
while i < n - 3:
    if data[i] == 0x3C:
        j = i + 2
        if 0x70 <= data[j] <= 0x7F and data[j] != 0x78 and data[j] != 0x79:  # jcc short (take je/jne/etc, exclude js/jns)
            cmps.append((i, data[i+1], data[j], data[j+1]))
        i = j
    else:
        i += 1

# window scan: find clusters of <=768 bytes containing imm set superset {3,4,6,7} with je (74)
targets = {3, 4, 6, 7}
events = sorted([(off, imm) for off, imm, jcc, _ in cmps if jcc == 0x74])
res = []
for k in range(len(events)):
    seen = set()
    for m in range(k, len(events)):
        if events[m][0] - events[k][0] > 768: break
        seen.add(events[m][1])
        if targets <= seen:
            res.append((events[k][0], events[m][0], sorted(seen)))
            break

# merge overlapping clusters
merged = []
for st, en, imms in res:
    if merged and st <= merged[-1][1]:
        if en > merged[-1][1]:
            merged[-1] = (merged[-1][0], en, sorted(set(merged[-1][2]) | set(imms)))
        merged[-1] = (merged[-1][0], max(en, merged[-1][1]), sorted(set(merged[-1][2]) | set(imms)))
    else:
        merged.append((st, en, imms))

print("clusters with cmp al,{3,4,6,7}+je within 768B: %d" % len(merged))
for st, en, imms in merged:
    print("va=%08x-%08x imms=%s" % (base + st, base + en, [x for x in imms if 1 <= x <= 40]))
