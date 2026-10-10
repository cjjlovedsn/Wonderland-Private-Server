import pefile, re, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
end_va = base + len(data)

md = Cs(CS_ARCH_X86, CS_MODE_32)

def va2off(va):
    return va - base

# --- 1. full disassembly of 0x568af4 ---
fn = 0x568af4
off = va2off(fn)
print("==== disasm 0x568af4 ====")
for i in md.disasm(data[off:off+0x500], fn):
    print(f"{i.address:08x} {i.bytes.hex():<20} {i.mnemonic} {i.op_str}")
    if i.mnemonic == "ret":
        break

# --- 2. callers of 0x568af4 (E8 rel32) ---
print("\n==== callers of 0x568af4 ====")
target = fn
for m in re.finditer(rb"\xe8", data):
    va = base + m.start()
    rel = struct.unpack("<i", data[m.start()+1:m.start()+5])[0]
    if va + 5 + rel == target:
        print(f"  call at {va:08x}")

# --- 3. 62:61 sender candidates ---
def scan(label, ac, sub):
    print(f"\n== {label}: imm {ac:#x} then {sub:#x} nearby ==")
    seen = set()
    for m in re.finditer(rb"\x6a" + bytes([ac]), data):
        tail = data[m.end():m.end()+16]
        idx = tail.find(b"\x6a" + bytes([sub]))
        if 0 <= idx <= 12:
            seen.add(base + m.start())
    for m in re.finditer(rb"\xb2" + bytes([ac]), data):
        tail = data[m.end():m.end()+12]
        idx = tail.find(b"\xb1" + bytes([sub]))
        if 0 <= idx <= 10:
            seen.add(base + m.start())
    # mov byte ptr [reg], ac ; ... mov byte ptr [reg+1], sub  (buffer writes)
    for va in sorted(seen):
        print(f"  {va:08x}")

scan("62,61", 0x3E, 0x3D)
scan("61,2 (AC61 sub2 probe)", 0x3D, 0x02)
scan("23,54 (enter tent)", 0x17, 0x36)
