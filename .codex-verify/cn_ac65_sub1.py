import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dis(va, n, label, stop_jmp=True):
    print(f"\n==== {label} @ {va:#x} ====")
    cnt = 0
    for i in md.disasm(data[va-base:va-base+n], va):
        print(f"{i.address:08x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}")
        cnt += 1
        if stop_jmp and i.mnemonic == 'jmp' and cnt > 4:
            break

# sub handlers, brief
for va, lbl in [(0x769dd4,'sub1 wrapper'), (0x769de8,'sub2'), (0x769e0a,'sub3'),
                (0x769e1e,'sub4'), (0x769e58,'sub5'), (0x769e7a,'sub6'),
                (0x769e9c,'sub7'), (0x769eb0,'sub8'), (0x769ed2,'sub11'),
                (0x769ee6,'sub12'), (0x769efa,'sub13'), (0x769f0e,'sub14')]:
    dis(va, 0x28, lbl)

# the real sub1 worker
dis(0x5de744, 0x300, "65:1 worker 0x5de744")
