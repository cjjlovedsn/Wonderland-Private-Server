import struct, io

path = "D:/workspace/Wonderland-Private-Server/Data/itemDat.wpdat"
raw = open(path, "rb").read()

STRIDE = 47
items = {}
for off in range(0, len(raw) - STRIDE + 1, STRIDE):
    rec = raw[off:off+STRIDE]
    namelen = rec[0]
    if namelen > 20:
        continue
    name_b = rec[1:1+namelen]
    itemid = struct.unpack("<H", rec[22:24])[0]
    itemtype = rec[21]
    icon = struct.unpack("<H", rec[24:26])[0]
    try:
        name = name_b.decode("cp950")
    except Exception:
        name = name_b.decode("cp950", errors="replace")
    items[itemid] = (name, itemtype, icon)

out = io.StringIO()
out.write(f"total={len(items)} rawlen={len(raw)} stride_ok={len(raw)%STRIDE==0}\n\n")
out.write("== items 39020-39250 (tent dye range) ==\n")
for i in range(39020, 39251):
    if i in items:
        n, t, ic = items[i]
        out.write(f"{i} (0x{i:x}): {n!r} type={t} icon={ic}\n")

open("out_wpdat_names.txt", "w", encoding="utf-8").write(out.getvalue())
print("total items:", len(items))
print("done")
