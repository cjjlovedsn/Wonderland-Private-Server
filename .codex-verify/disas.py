import pefile, capstone, sys

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
img = pe.OPTIONAL_HEADER.ImageBase
sec = pe.sections[0]
base = img + sec.VirtualAddress
data = sec.get_data()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False

start = int(sys.argv[1], 16)
length = int(sys.argv[2], 16)
off = start - base
code = data[off:off+length]
for ins in md.disasm(code, start):
    print("%08x  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
