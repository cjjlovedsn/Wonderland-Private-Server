import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

targets = {
    b"\x20\x21\x00\x00": "+0x2120",
    b"\x21\x21\x00\x00": "+0x2121",
    b"\x58\x52\x00\x00": "+0x5258",
    b"\x5a\x52\x00\x00": "+0x525a",
    b"\xcc\x22\x00\x00": "+0x22cc",
}
hits = {v: [] for v in targets.values()}
for pat, name in targets.items():
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0: break
        hits[name].append(base + i)
        start = i + 1

for name, vas in hits.items():
    print(f"\n### {name}: {len(vas)} raw hits")
    for va in vas[:40]:
        # disassemble a window before to identify instruction
        win = 16
        for back in range(win-1, -1, -1):
            chunk = data[va-back-base:va-back-base+40]
            ok = False
            for ins in md.disasm(chunk, va-back):
                if ins.address <= va and va < ins.address + len(ins.bytes):
                    if ins.mnemonic in ("mov","movzx","cmp","lea","push"):
                        print(f"  {va:08x}: {ins.mnemonic} {ins.op_str}")
                        ok = True
                    break
            if ok: break
