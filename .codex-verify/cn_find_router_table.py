import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

# handler block addresses in router
handlers = [0x769bfd, 0x769c11, 0x769c25, 0x769c39, 0x769c4d, 0x769c61]

# scan for dwords equal to any handler, record locations
locs = {}
for h in handlers:
    b = struct.pack("<I", h)
    for m in re.finditer(re.escape(b), data):
        va = base + m.start()
        locs.setdefault(va, []).append(h)

# find consecutive runs: table entries 4 bytes apart
vals = sorted(locs.items())
runs = []
for va, hs in vals:
    placed = False
    for r in runs:
        if va - r[-1][0] == 4:
            r.append((va, hs))
            placed = True
            break
    if not placed:
        runs.append([(va, hs)])

for r in runs:
    if len(r) >= 3:
        print(f"table run @ {r[0][0]:08x}..{r[-1][0]:08x} ({len(r)} entries):")
        for va, hs in r:
            print(f"   {va:08x}: {['%08x' % h for h in hs]}")
