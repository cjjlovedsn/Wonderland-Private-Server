import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()

def dump(va, n=0x60):
    off = va - base
    chunk = data[off:off+n]
    print(f"--- {va:#x} ---")
    # print as hex + printable
    for i in range(0, n, 16):
        row = chunk[i:i+16]
        hexs = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"{va+i:08x}  {hexs:<48}  {asc}")

for va in (0x8c9878, 0x8c9884, 0x8cb1e4, 0x8c8b90, 0x8c8ba4):
    dump(va)
