import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

targets = {
    b"\x4d\x1b\x00\x00": "+0x1b4d",
    b"\x52\x1b\x00\x00": "+0x1b52",
    b"\x4c\x1b\x00\x00": "+0x1b4c",
    b"\xda\x1b\x00\x00": "+0x1bda",
}
for pat, name in targets.items():
    print(f"\n### {name}")
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0: break
        start = i + 1
        va = base + i
        if va > 0x9b4d24 or va < 0x401000: continue
        found = False
        for back in (7,6,5,4,3,2):
            chunk = data[i-back:i-back+28]
            for ins in md.disasm(chunk, va-back):
                if ins.address <= va < ins.address + len(ins.bytes):
                    print(f"  ~{va:08x}: {ins.mnemonic} {ins.op_str}")
                    found = True
                    break
            if found: break
