import struct, io

path = "D:/workspace/Wonderland-Private-Server/Data/Item.dat"
raw = open(path, "rb").read()

STRIDE = 48
names = {}
types = {}
for off in range(0, len(raw) - STRIDE, STRIDE):
    rec = raw[off:off+STRIDE]
    if len(rec) < STRIDE: break
    namelen = rec[0]
    if namelen > 20: continue
    name_b = bytes(((b ^ 0x9A) - 9) & 0xFF for b in rec[1:1+20])
    itemtype = ((rec[21] ^ 0x9A) - 9) & 0xFF
    itemid = struct.unpack("<H", rec[22:24])[0]
    itemid = ((itemid ^ 0xEFC3) - 9) & 0xFFFF
    name = name_b[:namelen].decode("cp950", errors="replace") if 0 < namelen <= 20 else ""
    if itemid:
        names[itemid] = name
        types[itemid] = itemtype

out = io.StringIO()
out.write("== items 36000-36020 ==\n")
for i in range(36000, 36021):
    out.write(f"{i}: {names.get(i,'-')!r} type={types.get(i)}\n")
out.write("\n== items 39000-39160 (magic furniture range) ==\n")
for i in range(39000, 39161):
    n = names.get(i)
    if n is not None:
        out.write(f"{i} (0x{i:x}): {n!r} type={types[i]}\n")

open("out_items.txt", "w", encoding="utf-8").write(out.getvalue())
print("total items:", len(names))
print("done")
