import pefile, sys

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

target = int(sys.argv[1], 16)
hits = []
i = 0
while i < n - 5:
    if data[i] == 0xE8:  # call rel32
        rel = int.from_bytes(data[i+1:i+5], "little", signed=True)
        va = base + i
        if va + 5 + rel == target:
            hits.append(va)
    i += 1
print(f"callers of {target:08x}: {[f'{h:08x}' for h in hits]}")

# Also scan for jmp [reg*4+disp32] tables (FF 24 85 / FF 24 8D / FF 24 95 ...)
print("\njump tables (ff 24 85/8d/95/9d/b5):")
i = 0
tables = []
while i < n - 6:
    if data[i] == 0xFF and data[i+1] == 0x24 and data[i+2] in (0x85, 0x8D, 0x95, 0x9D, 0xB5):
        disp = int.from_bytes(data[i+3:i+7], "little")
        tables.append((base + i, data[i+2], disp))
    i += 1
print(f"count={len(tables)}")
for va, modrm, disp in tables[:40]:
    print(f"  va={va:08x} modrm=24 {modrm:02x} disp={disp:08x} -> rva={disp - img:#x}")
