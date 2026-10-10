using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Network;
using Game;
using Wonderland_Private_Server.Utilities;

namespace Network.ActionCodes
{
    public class AC62 : AC
    {
        public override int ID { get { return 62; } }
        public override void ProcessPkt(Player p, RecievePacket r)
        {
            DebugSystem.Write(DebugItemType.Error, $"[DEBUG] AC62 ProcessPkt - Sub={r.B}");
            switch (r.B)
            {
                case 1: DebugSystem.Write(DebugItemType.Error, "[DEBUG] AC62 - Entering Recv1"); Recv1(p, r); break;
                case 3: Recv3(p, r); break;//rotate, move objects in tent.
                case 4: Recv4(p, r); break; // add item type especial
                default: Console.WriteLine(r.A + "," + r.B + " Has not been coded"); break;
            }
        }
        void Recv1(Player p, RecievePacket r)
        {
            // Captured layout (9 samples, 2026-10-09): Slot(1) + X(4 LE) +
            // Y(4 LE) + Floor(4 LE, 1-based) + Rot(1) = 14 bytes payload.
            // Coordinates are the tent's furniture GRID, not world pixels
            // (drag samples span x 30-42 / y 37-46).

            if (r.Buffer.Length < 20)
            {
                DebugSystem.Write(DebugItemType.Error, $"[Tent] Ignored short AC62 packet (Len={r.Buffer.Length})");
                return;
            }

            try
            {
                // Pointer sits on the sub opcode when the handler is entered;
                // consume it so the reads below align with the payload.
                r.Unpack8();

                byte slotIndex = r.Unpack8();       // Inventory slot

                // Read coordinates as 32-bit integers LITTLE ENDIAN (Standard)
                uint x = r.Unpack32();
                uint y = r.Unpack32();
                uint floor = r.Unpack32();
                byte rotation = 0;
                try { rotation = r.Unpack8(); } catch { }

                DebugSystem.Write(DebugItemType.Error, $"[Tent] AC62,1 Place: Slot={slotIndex} Grid=({x},{y}) Flr={floor} Rot={rotation}");

                if (p.Tent != null)
                {
                    if (p.CurMap != p.Tent)
                    {
                        DebugSystem.Write(DebugItemType.Error, $"[Tent] Rejected AC62 placement: {p.CharName} is not inside their own tent.");
                        return;
                    }

                    if (p.Inv == null || slotIndex == 0 || slotIndex > 50 || p.Inv[slotIndex] == null || p.Inv[slotIndex].ItemID == 0)
                    {
                        DebugSystem.Write(DebugItemType.Error, $"[Tent] Rejected AC62 placement: Invalid slot {slotIndex} for {p.CharName}");
                        return;
                    }

                    ushort placeItemId = p.Inv[slotIndex].ItemID;
                    p.Inv.RemoveItem(slotIndex, 1, true);

                    p.Tent.PlaceItem(placeItemId, (int)x, (int)y, (int)floor, rotation);

                    // AC4 reload above is the authoritative confirmation. The
                    // old [62][1][1] ack was misread by the client as a tent
                    // config packet (type 1, colors 0) and rebuilt the room.
                    p.Tent.SendTentItemsToAll();

                    cGlobal.gCharacterDataBase?.SaveTentData(p);
                }
            }
            catch (Exception ex)
            {
                DebugSystem.Write(DebugItemType.Error, $"[Tent] Error in AC62 Recv1: {ex.Message}");
            }
        }
        void Recv3(Player p, RecievePacket r)
        {
            try
            {
                // Consume the sub opcode so Index aligns with the payload.
                r.Unpack8();

                // Packet format based on user capture: Index(2) + X(4) + Y(4) + Floor(4) + Rot?(1)
                ushort index = r.Unpack16();
                uint x = r.Unpack32();
                uint y = r.Unpack32();
                uint floor = r.Unpack32();
                byte rotation = 0;

                try { rotation = r.Unpack8(); } catch { }

                DebugSystem.Write(DebugItemType.Error, $"[Tent] AC62,3 Move: Index {index} to ({x},{y}) Flr {floor} Rot {rotation}");

                if (p.Tent != null)
                {
                    if (p.CurMap != p.Tent)
                    {
                        DebugSystem.Write(DebugItemType.Error, $"[Tent] Rejected AC62 move: {p.CharName} is not inside their own tent.");
                        return;
                    }

                    p.Tent.MoveItem(index, (int)x, (int)y, (int)floor, rotation);
                    p.Tent.SendTentItemsToAll();
                    cGlobal.gCharacterDataBase?.SaveTentData(p);
                }
            }
            catch (Exception t) { Console.WriteLine(t); }
        }
        void Recv4(Player p, RecievePacket r)
        {
            try { }

            catch (Exception t) { Console.WriteLine(t); }
        }
    }
}
