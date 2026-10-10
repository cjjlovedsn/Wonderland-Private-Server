import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# search for cmp/mov with imm32 in the 39050..39070 range (dye candidates) and 36000..36016 (tent items)
for lo, hi, tag in ((39050, 39080, "dye"), (36000, 36016, "tentitems")):
    print(f"\n### imm32 refs {tag} {lo}..{hi}")
    for val in range(lo, hi):
        pat = val.to_bytes(4, "little")
        pos = 0
        while True:
            i = data.find(pat, pos)
            if i < 0: break
            pos = i + 1
            va = base + i
            if not (0x401000 <= va <= 0x9b4d24): continue
            # context: previous bytes should contain cmp/mov opcode; disasm window
            for back in (6, 5, 2, 1):
                chunk = data[i-back:i-back+24]
                try:
                    for ins in md.disasm(chunk, va-back):
                        if ins.address <= va < ins.address + len(ins.bytes):
                            if ins.mnemonic in ("cmp","mov","push","sub","add"):
                                print(f"  {val} @ ~{va:08x}: {ins.mnemonic} {ins.op_str}")
                            raise StopIteration
                        break
                except StopIteration:
                    break
