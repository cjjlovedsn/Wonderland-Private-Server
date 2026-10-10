import pefile, capstone

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# find every 'C6' mov-byte-immediate storing 0x1F: C6 /0 ib with modrm reg field 0
hits = []
i = 0
while i < n - 3:
    if data[i] == 0xC6:
        modrm = data[i+1]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if reg == 0:
            if mod == 1 and data[i+3] == 0x1F:
                hits.append(i); i += 4; continue
            if mod == 0 and rm < 7 and data[i+2] == 0x1F and rm != 4:
                hits.append(i); i += 3; continue
            if mod == 2:
                ln = 6
                if data[i+6] == 0x1F:
                    hits.append(i); i += 7; continue
                i += 1; continue
    i += 1

print("mov byte [mem], 0x1F sites:", len(hits))

def func_context(off, back=80, fwd=160):
    start = max(0, off - back)
    code = data[start:off + fwd]
    txt = []
    for ins in md.disasm(code, base + start):
        mark = " <<<" if ins.address <= base + off < ins.address + ins.size else ""
        txt.append("%08x %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    return txt

for off in hits:
    va = base + off
    # require a call within the following 200 bytes
    if b"\xe8" not in data[off:off+200]:
        continue
    print("\n==== site va=%08x ====" % va)
    for line in func_context(off):
        print(line)
