import pefile, re

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
s = pe.sections[0]
base = img + s.VirtualAddress
data = s.get_data()

# 1) mov word [mem], 0x033E  (62,3)  => 66 C7 05 id 3E 03 ; 66 C7 45 xx 3E 03 etc.
print("== mov word 0x033E (62,3) ==")
for m in re.finditer(rb"\x66\xc7[\x05\x07\x0d\x15\x1d\x35\x3d\x45\x75\x85\x8d][\x00-\xff]{0,4}\x3e\x03", data):
    print(f"  {base + m.start():08x}")

print("== mov word 0x013E (62,1) ==")
for m in re.finditer(rb"\x66\xc7[\x05\x07\x0d\x15\x1d\x35\x3d\x45\x75\x85\x8d][\x00-\xff]{0,4}\x3e\x01", data):
    print(f"  {base + m.start():08x}")

print("== mov word 0x3D3E (62,61) ==")
for m in re.finditer(rb"\x66\xc7[\x05\x07\x0d\x15\x1d\x35\x3d\x45\x75\x85\x8d][\x00-\xff]{0,4}\x3e\x3d", data):
    print(f"  {base + m.start():08x}")

# 2) mov byte [x],0x3E then within 10 bytes mov byte [y],0x03
print("== byte stores 0x3E ... 0x03 ==")
for m in re.finditer(rb"\xc6[\x00\x40-\x47\x45\x85\x8d][\x00-\xff]{0,3}\x3e", data):
    tail = data[m.end():m.end()+12]
    for m2 in re.finditer(rb"\xc6[\x00\x40-\x47\x45\x85\x8d][\x00-\xff]{0,3}\x03", tail):
        print(f"  {base + m.start():08x}")
        break

# 3) push 0x3E; push 0x03  (6A 3E 6A 03) or mov al,0x3E / B0 3E near 6A 03
print("== push 0x3E; push 0x03 ==")
for m in re.finditer(rb"\x6a\x3e\x6a\x03", data):
    print(f"  {base + m.start():08x}")
