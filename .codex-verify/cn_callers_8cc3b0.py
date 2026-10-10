import pefile, struct
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

for tgt in (0x8cc3b0,):
    for off in range(0, len(data)-5):
        if data[off] == 0xE8:
            rel = struct.unpack("<i", data[off+1:off+5])[0]
            va = base + off
            if va + 5 + rel == tgt:
                print(f"call to {tgt:#x} from {va:#x}")
                # show context
                for i in md.disasm(data[off-24-base+base-0:off-24], va-24):
                    pass
                chunk = data[off-32:off+8]
                for ins in md.disasm(chunk, va-32):
                    print(f"   {ins.address:08x} {ins.mnemonic} {ins.op_str}")
                print()
