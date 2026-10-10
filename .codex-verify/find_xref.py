import pefile, re, struct, sys

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase

secs = []
for s in pe.sections:
    secs.append((img + s.VirtualAddress, s.get_data(), s.Name.rstrip(b"\0").decode(errors="replace")))

def xrefs(va):
    b = struct.pack("<I", va)
    out = []
    for base, data, name in secs:
        for m in re.finditer(re.escape(b), data):
            out.append(base + m.start())
    return out

for target in [int(a, 16) for a in sys.argv[1:]]:
    print(f"== xrefs to 0x{target:08x} ==")
    for va in xrefs(target):
        print(f"  {va:08x}")
