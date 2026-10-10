import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

# pattern: 83 C0 ib        add eax, -base
#          83 F8 ib        cmp eax, range      (or 3D id cmp eax,imm32)
#          77 xx / 0F 87   ja
#          FF 24 85 id     jmp [eax*4+table]
res = []
i = 0
while i < n - 20:
    if data[i] == 0x83 and data[i+1] == 0xC0:  # add eax, imm8
        base_adj = data[i+2]
        j = i + 3
        # skip optional bytes until cmp eax (83 F8) within 8 bytes
        k = j
        while k < j + 8 and not (data[k] == 0x83 and data[k+1] == 0xF8):
            k += 1
        if k < j + 8 and data[k] == 0x83 and data[k+1] == 0xF8:
            rng = data[k+2]
            m = k + 3
            if data[m] == 0x77:
                m += 2
            elif data[m:m+2] == b"\x0f\x87":
                m += 6
            else:
                continue
            if data[m] == 0xFF and data[m+1] == 0x24 and data[m+2] == 0x85:
                disp = int.from_bytes(data[m+3:m+7], "little")
                res.append((base + i, 256 - base_adj if base_adj > 127 else -base_adj, rng, disp, base + m))
                i = m
                continue
    i += 1

print(f"Delphi case dispatchers: {len(res)}")
for va, casebase, rng, table, jmpva in sorted(res):
    # entries = rng+1; check table region looks like code pointers
    off = table - base
    ok = 0
    for e in range(rng + 1):
        if off + 4*e + 4 <= n:
            v = int.from_bytes(data[off+4*e:off+4*e+4], "little")
            if base <= v < base + n:
                ok += 1
    print(f"  dispatch@{va:08x} case {casebase}..{casebase+rng} ({rng+1} entries, {ok} valid) table@{table:08x}")
