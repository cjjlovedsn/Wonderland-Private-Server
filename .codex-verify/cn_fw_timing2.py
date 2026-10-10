import pefile, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(va, n, label):
    print(f"\n==== {label} @ {va:#x} ====")
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")

def find_start(va, maxback=0x800, relaxed=True):
    for v in range(va, va - maxback, -1):
        off = v - base
        if data[off:off+3] == b"\x55\x8b\xec":
            if relaxed or data[off-1] in (0xc3, 0x90, 0xcc):
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

dis(0x8cb61c, 0x70, "render fn head")
dis(0x5539c0, 0x90, "render caller region 0x553a1a")

for anchor, name in [(0x8cb428, "reset floor/wall"), (0x8c1e2a, "init wall default")]:
    st = find_start(anchor)
    if st:
        cs = callers(st)
        print("### %s: anchor %#x -> fn start %#x, callers (%d): %s" % (name, anchor, st, len(cs), [hex(c) for c in cs[:20]]))
    else:
        print("### %s: no start found" % name)
