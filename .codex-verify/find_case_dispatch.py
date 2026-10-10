import pefile

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()
n = len(data)

# collect ALL cmp al,imm8 (3C ib) regardless of branch flavor
events = []
i = 0
while i < n - 3:
    if data[i] == 0x3C:
        events.append((i, data[i+1], data[i+2]))
        i += 3
        continue
    i += 1

print("total cmp al,imm8:", len(events))

# window scan: 2KB windows containing imm 0x17(23), 0x3E(62), 0x41(65) together
for label, imms in (("with 23&62&65", {0x17, 0x3E, 0x41}), ("with 23&62", {0x17, 0x3E})):
    evs = sorted([(o, imm, jcc) for o, imm, jcc in events if imm in imms])
    print(f"\n== {label}: {len(evs)} events")
    for o, imm, jcc in evs[:40]:
        print(f"  va={base+o:08x} cmp al,{imm:#04x} next={jcc:#04x}")
