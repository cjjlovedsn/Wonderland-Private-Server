import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

def scan(label, ac, sub):
    print(f"== {label}: stores of {ac:#x} then {sub:#x} nearby ==")
    seen = set()
    # push imm8 ac (6A ac) then within 12 bytes push imm8 sub (6A sub)
    for m in re.finditer(rb"\x6a" + bytes([ac]), data):
        tail = data[m.end():m.end()+16]
        if re.finditer(rb"\x6a" + bytes([sub]), tail):
            # ensure direct adjacency-ish (no long gap)
            idx = tail.find(b"\x6a" + bytes([sub]))
            if idx <= 12:
                va = base + m.start()
                seen.add(va)
    # mov dl/CL etc: B2 ac (dl), B1 sub (cl) — Delphi param regs
    for m in re.finditer(rb"\xb2" + bytes([ac]), data):
        tail = data[m.end():m.end()+12]
        idx = tail.find(b"\xb1" + bytes([sub]))
        if 0 <= idx <= 10:
            seen.add(base + m.start())
    for va in sorted(seen):
        print(f"  {va:08x}")

scan("62,3", 0x3E, 0x03)
scan("62,1", 0x3E, 0x01)
scan("62,61", 0x3E, 0x3D)
