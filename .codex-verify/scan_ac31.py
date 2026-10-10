import pefile, capstone, sys

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
text = pe.sections[0]
for s in pe.sections:
    if s.Name.startswith(b"CODE"):
        text = s
        break
base_va = img + text.VirtualAddress
data = text.get_data()
print("text VA=%08x size=%x" % (base_va, len(data)))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def find(pat):
    out, i = [], 0
    while True:
        i = data.find(pat, i)
        if i < 0: return out
        out.append(i); i += 1

# patterns: word-store of payload head (0x1F,sub) or pushes with 0x1F
pats = {
    "1F02raw": b"\x1f\x02",
    "1F03raw": b"\x1f\x03",
    "1F04raw": b"\x1f\x04",
}
hits = {}
for name, p in pats.items():
    offs = find(p)
    hits[name] = offs
    print("%s: %d hits" % (name, len(offs)))

# Show hits whose 3 bytes before look like an immediate store/push context
def ctx_ok(off):
    pre = data[max(0,off-6):off]
    good = any(pre.endswith(x) for x in (b"\xc7\x45", b"\xc7\x05", b"\xc7\x43", b"\xc7\x83", b"\xc6\x45", b"\xc6\x05", b"\x66\xc7"))
    return good

for name in pats:
    for off in hits[name]:
        va = base_va + off
        tag = "CTX" if ctx_ok(off) else "   "
        pre = data[max(0,off-8):off+8].hex()
        print("%s %s va=%08x  %s" % (name, tag, va, pre))
