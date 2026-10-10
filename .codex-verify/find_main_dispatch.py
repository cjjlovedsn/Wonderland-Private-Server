import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

# Delphi case dispatch: bounds check then indirect jump.
# Find "jmp [eax*4+disp32]" (FF 24 85) and look backwards ~32 bytes for
# cmp al,imm8 + ja/jae (3C ib 77/73/0F87/0F83) or cmp eax,imm32 (3D id).
hits = []
i = 0
while i < n - 6:
    if data[i] == 0xFF and data[i+1] == 0x24 and data[i+2] == 0x85:
        disp = int.from_bytes(data[i+3:i+7], "little")
        # check disp is within .text-ish range of image
        if img + 0x1000 <= disp < base + n:
            # look back for bounds check
            window = data[max(0, i-32):i]
            found = None
            for j in range(len(window) - 4):
                if window[j] == 0x3C and window[j+2] in (0x77, 0x73):  # cmp al,imm; ja/jae
                    found = ("cmp al", window[j+1])
                    break
                if window[j:j+2] == b"\x3d":  # cmp eax, imm32
                    found = ("cmp eax", int.from_bytes(window[j+2:j+6], "little", signed=True))
                    break
            if found:
                hits.append((base + i, disp, found))
    i += 1

print(f"dispatch-shaped sites: {len(hits)}")
for va, disp, (kind, imm) in hits:
    # count table entries: consecutive dwords in .text
    off = disp - base
    cnt = 0
    while off + 4 <= n:
        v = int.from_bytes(data[off:off+4], "little")
        if base <= v < base + n:
            cnt += 1
            off += 4
        else:
            break
    print(f"  jmp@{va:08x} table@{disp:08x} entries~{cnt}  bound={kind} {imm if kind=='cmp al' else hex(imm)}")
