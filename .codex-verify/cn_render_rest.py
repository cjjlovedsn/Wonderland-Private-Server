import pefile
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

dis(0x5dd77c, 0x1b0, "tent render after table lookup")

# find writes to the two table globals
import struct
for tbl, nm in ((0x9cda64, "tableA"), (0x9cd1dc, "tableB")):
    pat = tbl.to_bytes(4, "little")
    pos = 0
    print(f"\n### dest writes / refs for {nm} 0x{tbl:08x}:")
    while True:
        i = data.find(pat, pos)
        if i < 0: break
        pos = i + 1
        va = base + i
        if not (0x401000 <= va <= 0x9b4d24): continue
        # check preceding opcode for a store
        op = data[i-1]
        if op in (0xa3,) or (i >= 2 and data[i-2] in (0x89, 0x8b, 0xc7, 0xa1)):
            found = False
            for back in (6,5,2):
                chunk = data[i-back:i-back+30]
                for ins in md.disasm(chunk, va-back):
                    if ins.address <= va < ins.address + len(ins.bytes):
                        print(f"  {va:08x}: {ins.mnemonic} {ins.op_str}")
                        found = True
                        break
                if found: break
