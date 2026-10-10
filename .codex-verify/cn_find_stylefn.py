import pefile
from capstone import *

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# scan backwards from 0x8c9a92 for Delphi prologue "55 8b ec"
target = 0x8c9a92
for va in range(target, target-0x1200, -1):
    off = va - base
    if data[off:off+3] == b"\x55\x8b\xec":
        # check preceded by ret/nop/int3 padding
        prev = data[off-1]
        if prev in (0xc3, 0x90, 0xcc, 0x8b):
            print(f"prologue at {va:#x} (prev byte {prev:02x})")
# also: find which dispatcher case jumps into the region 0x8c9800..0x8ca000
# dispatcher cases from earlier extraction: re-derive jump table quickly
import struct
# case table entries were extracted before; print VAs in 0x8c99xx..0x8cb000 region
# search all dwords in dispatcher area 0x8c3e84..0x8c3f90 that point into 0x8c9800-0x8cb000
for va in range(0x8c3e84, 0x8c3fa0):
    off = va - base
    val = int.from_bytes(data[off:off+4], "little")
    if 0x8c9800 <= val <= 0x8cb000:
        print(f"dispatcher dword @ {va:#x} -> {val:#x}")
