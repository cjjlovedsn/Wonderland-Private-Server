import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

def tail_len(modrm):
    mod = modrm >> 6
    rm = modrm & 7
    if mod == 0:
        if rm == 4: return 1  # SIB
        if rm == 5: return 4  # disp32
        return 0
    if mod == 1:
        return 2 if rm == 4 else 1  # SIB+disp8 or disp8
    if mod == 2:
        return 5 if rm == 4 else 4  # SIB+disp32 or disp32
    return -1

hits = []
for m in re.finditer(rb"\x80", data):
    i = m.start()
    modrm = data[i+1]
    if (modrm & 0x38) != 0x30 or (modrm >> 6) == 3:
        continue
    l = tail_len(modrm)
    if l < 0:
        continue
    if data[i+2+l] == 0xAD:
        hits.append(base + i)

print("xor byte [mem], 0xAD sites:", len(hits))
for h in hits:
    print(f"  {h:08x}")

print()
print("xor al, 0xAD (34 AD) count:", len(re.findall(rb"\x34\xad", data)))
for m in re.finditer(rb"\x34\xad", data):
    print(f"  {base + m.start():08x}")
