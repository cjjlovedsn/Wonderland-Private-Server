import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

for target in (0x769c4d, 0x769c61):
    b = struct.pack("<I", target)
    hits = [base + m.start() for m in re.finditer(re.escape(b), data)]
    print(f"refs to {target:08x}: {[hex(h) for h in hits]}")
