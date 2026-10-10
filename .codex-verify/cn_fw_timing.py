import pefile, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def find_start(va, maxback=0x600):
    for v in range(va, va - maxback, -1):
        off = v - base
        if data[off:off+3] == b"\x55\x8b\xec" and data[off-1] in (0xc3, 0x90, 0xcc):
            return v
    return None

def callers(fn):
    out = []
    for off2 in range(0, len(data) - 5):
        if data[off2] == 0xE8:
            rel = struct.unpack("<i", data[off2+1:off2+5])[0]
            va2 = base + off2
            if va2 + 5 + rel == fn:
                out.append(va2)
    return out

for anchor, name in [(0x8cb428, "reset floor/wall"), (0x8c1e2a, "init wall default"), (0x8cb685, "render floor")]:
    st = find_start(anchor)
    if st:
        cs = callers(st)
        print("### %s: anchor %#x -> fn start %#x, callers (%d): %s" % (name, anchor, st, len(cs), [hex(c) for c in cs[:20]]))
    else:
        print("### %s: no start found" % name)
