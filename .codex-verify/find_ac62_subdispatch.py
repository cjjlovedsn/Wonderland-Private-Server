import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

events = []
i = 0
while i < n - 4:
    if data[i] == 0x3C:  # cmp al, imm8
        j = i + 2
        if data[j] == 0x74:  # je short
            events.append((i, data[i+1])); i = j + 2; continue
        if data[j:j+2] == b"\x0f\x84":  # je near
            events.append((i, data[i+1])); i = j + 6; continue
    i += 1

print("cmp al,imm8 + je events:", len(events))

# clusters containing {4, 14, 15} within 512 bytes
targets = {4, 14, 15}
evs = sorted(events)
found = []
for k in range(len(evs)):
    seen = set()
    for m in range(k, len(evs)):
        if evs[m][0] - evs[k][0] > 512: break
        seen.add(evs[m][1])
    if targets <= seen:
        found.append((base + evs[k][0], base + evs[min(m, len(evs)-1)][0], sorted(seen)))
# dedupe overlapping
out = []
for f in found:
    if out and f[0] - out[-1][0] < 512 and f[2] == out[-1][2]:
        out[-1] = (out[-1][0], max(out[-1][1], f[1]), out[-1][2])
    else:
        out.append(f)
for va, va2, imms in out:
    print(f"  cluster near {va:08x}..{va2:08x} imms={imms}")
