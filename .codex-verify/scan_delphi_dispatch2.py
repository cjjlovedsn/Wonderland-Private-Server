import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

# add eax,imm8 (83 C0 ib) then within 8 bytes: cmp eax,imm8 (83 F8 ib), then ja short (77 xx) or ja near (0F 87 id), then jmp [eax*4+disp32] (FF 24 85 id)
pat = re.compile(
    rb"\x83\xc0(.)"              # add eax, imm8
    rb".{0,6}?"
    rb"\x83\xf8(.)"              # cmp eax, imm8
    rb"(?:\x77.|\x0f\x87....)",  # ja
    re.S)

res = []
for m in pat.finditer(data):
    e = m.end()
    if e + 7 <= n and data[e] == 0xFF and data[e+1] == 0x24 and data[e+2] == 0x85:
        base_adj = m.group(1)[0]
        rng = m.group(2)[0]
        disp = int.from_bytes(data[e+3:e+7], "little")
        casebase = 256 - base_adj if base_adj > 127 else -base_adj
        res.append((base + m.start(), casebase, rng, disp))

print(f"Delphi case dispatchers: {len(res)}")
for va, casebase, rng, table in sorted(res):
    off = table - base
    ok = 0
    for k in range(rng + 1):
        if 0 <= off + 4*k and off + 4*k + 4 <= n:
            v = int.from_bytes(data[off+4*k:off+4*k+4], "little")
            if base <= v < base + n:
                ok += 1
    hi = casebase + rng
    mark = " <== covers 62" if casebase <= 62 <= hi else ""
    mark += " <== covers 65" if casebase <= 65 <= hi else ""
    print(f"  dispatch@{va:08x} case {casebase}..{hi} ({rng+1} entries, {ok} valid){mark}")
