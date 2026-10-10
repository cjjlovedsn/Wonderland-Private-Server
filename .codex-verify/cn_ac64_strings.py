import pefile, io, sys

exe = "D:/workspace/Wonderland-Client/WLOnline/aLogin.exe"
pe = pefile.PE(exe)
s = pe.sections[0]
base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
data = s.get_data()

buf = io.StringIO()

def readstr(va):
    off = va - base
    ln = data[off]
    if 1 <= ln < 0x80:
        raw = data[off+1:off+1+ln]
        return f"len-prefix({ln}): {raw.decode('cp950', errors='replace')!r}"
    end = data.find(b"\x00", off)
    raw = data[off:end]
    return f"zstr: {raw.decode('cp950', errors='replace')!r}"

for va in (0x8cb058, 0x8cb064, 0x8cb09c, 0x8cb254, 0x8cb284, 0x8cb608,
           0x8c9878, 0x76f718, 0x76f748, 0x76f764, 0x76f798):
    try:
        buf.write(f"{va:#x}: {readstr(va)}\n")
    except Exception as e:
        buf.write(f"{va:#x}: ERR {e}\n")

# also dump a region of strings around 0x8cb040-0x8cb120 as raw hex+big5 attempt
off = 0x8cb040 - base
chunk = data[off:off+0x100]
hexs = " ".join(f"{b:02x}" for b in chunk)
buf.write(f"\nraw 0x8cb040:\n{hexs}\n")
buf.write(f"big5: {chunk.decode('cp950', errors='replace')!r}\n")

with open("out_ac64_strings.txt", "w", encoding="utf-8") as f:
    f.write(buf.getvalue())
print("written")
