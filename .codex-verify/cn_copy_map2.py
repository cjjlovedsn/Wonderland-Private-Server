import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()

COPY = 0x405488
LO, HI = 0x8c3e84, 0x8c8a00

def call_target(va):
    off = va - base
    if data[off] != 0xE8:
        return None
    return va + 5 + struct.unpack("<i", data[off+1:off+5])[0]

region = data[LO-base:HI-base]
handlers = [
 (0x8c4025,'case1'),(0x8c40f4,'case2'),(0x8c41cf,'case3'),(0x8c433d,'case4'),
 (0x8c4b06,'case5'),(0x8c4bf2,'case7'),(0x8c4f42,'case0x0a'),(0x8c521e,'case0x0b'),
 (0x8c5510,'case0x0c'),(0x8c5578,'case0x0d'),(0x8c55c1,'case0x0e'),(0x8c55fb,'case0x0f'),
 (0x8c5635,'case0x10'),(0x8c56ca,'case0x11'),(0x8c575f,'case0x12'),(0x8c576f,'case0x15'),
 (0x8c5c10,'case0x16'),(0x8c60f3,'case0x18'),(0x8c65a0,'case0x19'),(0x8c66db,'case0x1f'),
 (0x8c6930,'case0x20'),(0x8c6a82,'case0x21'),(0x8c6c53,'case0x22'),(0x8c6cd7,'case0x29'),
 (0x8c6eec,'case0x2a'),(0x8c7282,'case0x2b'),(0x8c74c4,'case0x2c'),(0x8c7b81,'case0x2d'),
 (0x8c7c11,'case0x2e'),(0x8c7d6e,'case0x2f'),(0x8c7fd1,'case0x30'),(0x8c8364,'case0x31'),
 (0x8c844b,'case0x32'),(0x8c845c,'case0x33'),(0x8c8497,'case0x34'),(0x8c84a7,'case0x35'),
 (0x8c84f0,'case0x36'),(0x8c85ab,'case0x37'),(0x8c8772,'case0x38'),(0x8c8782,'case0x39'),
 (0x8c8796,'case0x3a'),(0x8c8878,'case0x3e'),(0x8c888c,'case0xff'),
]

for m in re.finditer(rb"\xe8....", region):
    va = LO + m.start()
    if call_target(va) != COPY:
        continue
    # backtrack 34 bytes for last "b9 imm32" (ecx) and "ba imm32" (edx)
    lo2 = max(0, m.start()-34)
    back = region[lo2:m.start()]
    ecd = [struct.unpack("<I", x.group(1))[0] for x in re.finditer(rb"\xb9(....)", back)]
    edd = [struct.unpack("<I", x.group(1))[0] for x in re.finditer(rb"\xba(....)", back)]
    ecx = ecd[-1] if ecd else None
    edx = edd[-1] if edd else None
    h = '?'
    for hstart, hname in handlers:
        if va >= hstart:
            h = hname
    print(f"{va:08x} {h:10s} Copy(pkt,{edx},{ecx})")
