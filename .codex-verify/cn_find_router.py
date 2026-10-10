import pefile, re, struct

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

# comparisons of a byte against imm8: 3C ib (cmp al), 80 3D/38/39/3A/3B /7x/5x (cmp byte [x], ib)
pat_cmp_al = re.compile(rb"\x3c([\x00-\xff])")
pat_cmp_m8 = re.compile(rb"\x80\x3d....(.)", re.S)      # cmp [addr], ib
pat_cmp_m8r = re.compile(rb"\x80[\x78-\x7f].(.)", re.S)  # cmp byte [eax..edi+disp8], ib
pat_cmp_m8b = re.compile(rb"\x80\xbb....(.)", re.S)     # cmp byte [ebx+disp32], ib

sites = []
for m in pat_cmp_al.finditer(data):
    sites.append((base + m.start(), m.group(1)[0]))
for m in pat_cmp_m8.finditer(data):
    sites.append((base + m.start(), m.group(1)[0]))
for m in pat_cmp_m8r.finditer(data):
    sites.append((base + m.start(), m.group(1)[0]))
for m in pat_cmp_m8b.finditer(data):
    sites.append((base + m.start(), m.group(1)[0]))

sites.sort()

# sliding window: 40+ byte-comparisons within 8KB = router candidate
WIN = 0x2000
THRESH = 40
i = 0
print("== dense byte-cmp clusters (router candidates) ==")
while i < len(sites):
    j = i
    while j + 1 < len(sites) and sites[j + 1][0] - sites[i][0] < WIN:
        j += 1
    if j - i + 1 >= THRESH:
        acs = sorted(set(v for _, v in sites[i:j+1]))
        print(f"  {sites[i][0]:08x}..{sites[j][0]:08x}  n={j-i+1}  cmp-values n={len(acs)}")
        print(f"    values: {[hex(v) for v in acs]}")
    i = j + 1 if j > i else i + 1
