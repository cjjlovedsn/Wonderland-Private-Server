import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase

# search ALL sections for anchors (code may not be in section 0)
secs = []
for s in pe.sections:
    secs.append((img + s.VirtualAddress, s.get_data(), s.Name.rstrip(b"\0").decode(errors="replace")))

def scan_imm(val32, label):
    print(f"== {label} (0x{val32:x}) ==")
    b3 = struct.pack("<I", val32)
    b2 = struct.pack("<H", val32)
    pats = [
        (b"\x3d" + b3, "cmp eax"),
        (b"\x81\xf8" + b3, "cmp eax"),
        (b"\x81\xf9" + b3, "cmp ecx"),
        (b"\x81\xba" + b3, "cmp edx"),
        (b"\x81\xbe" + b3, "cmp esi"),
        (b"\x81\xbf" + b3, "cmp edi"),
        (b"\x68" + b3, "push"),
        (b"\xb8" + b3, "mov eax"),
        (b"\xba" + b3, "mov edx"),
        (b"\xbf" + b3, "mov edi"),
        (b"\x66\x3d" + b2, "cmp ax"),
        (b"\x66\x81\xf8" + b2, "cmp ax"),
        (b"\x66\x81\xf9" + b2, "cmp cx"),
    ]
    hits = []
    for base, data, name in secs:
        for p, lbl in pats:
            for m in re.finditer(re.escape(p), data):
                hits.append((base + m.start(), lbl, name))
    for va, lbl, sec in hits[:20]:
        print(f"  {va:08x} {lbl} [{sec}]")
    if not hits:
        print("  (none)")

scan_imm(39062, "floor color")
scan_imm(39064, "wallpaper color")

# BGM0011 string occurrences + code xrefs to their addresses
print("== 'BGM0011' ASCII / Big5 occurrences ==")
for base, data, name in secs:
    for m in re.finditer(rb"BGM00", data):
        tail = data[m.start():m.start()+16]
        print(f"  {base + m.start():08x} [{name}] {tail!r}")
