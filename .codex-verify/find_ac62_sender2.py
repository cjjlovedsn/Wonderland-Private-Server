import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

def scan(label, immbytes):
    print(f"== mov word, {label} ==")
    pats = [
        rb"\x66\xc7\x05...." + immbytes,                 # [abs32]
        rb"\x66\xc7\x45." + immbytes,                    # [ebp+d8]
        rb"\x66\xc7\x40." + immbytes,                    # [eax+d8] (and 41/42..47)
        rb"\x66\xc7\x85...." + immbytes,                 # [ebp+d32]
        rb"\x66\xc7\x80...." + immbytes,                 # [eax+d32]
    ]
    seen = set()
    for p in pats:
        for m in re.finditer(p, data):
            va = base + m.start()
            if va in seen: continue
            seen.add(va)
            print(f"  {va:08x}")

scan("62,3", b"\x3e\x03")
scan("62,1", b"\x3e\x01")
scan("62,61", b"\x3e\x3d")
