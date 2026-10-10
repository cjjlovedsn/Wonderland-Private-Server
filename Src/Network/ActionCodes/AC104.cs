using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Network;
using Game;
using Game.Code;
using wlo.pserver.core.Game;

namespace Network.ActionCodes
{
    /// <summary>
    /// Handles Daily Lucky Draw / Spin Wheel minigame (AC 104).
    /// </summary>
    public class AC104 : AC
    {
        public override int ID { get { return 104; } }

        private static readonly Random _rng = new Random();

        public const int DailyLimit = 3;

        public class LuckyDrawItem
        {
            public ushort ItemId { get; set; }
            public byte SlotIndex { get; set; }
            public string Name { get; set; }

            public LuckyDrawItem(ushort itemId, byte slotIndex, string name)
            {
                ItemId = itemId;
                SlotIndex = slotIndex;
                Name = name;
            }
        }

        // Sample authentic Lucky Draw Item Rewards & Slot mapping
        private static readonly LuckyDrawItem[] LuckyDrawRewards = new LuckyDrawItem[]
        {
            new LuckyDrawItem(34328, 8, "Tenacious Jade"),
            new LuckyDrawItem(34514, 17, "Glory Halo"),
            new LuckyDrawItem(34148, 14, "Spar"),
            new LuckyDrawItem(30002, 5, "Instant Noodles"),
            new LuckyDrawItem(28014, 11, "Coconut"),
            new LuckyDrawItem(30052, 2, "Raft Voucher")
        };

        public override void ProcessPkt(Player player, RecievePacket p)
        {
            switch (p.B)
            {
                case 1: Recv1(player, p); break; // Spin Wheel Request
                default:
                    DebugSystem.Write($"[AC104] Action Code 104,{p.B} has not been coded");
                    break;
            }
        }

        private static string Today()
        {
            return DateTime.Now.ToString("yyyy-MM-dd");
        }

        private static int GetUsedToday(Player player)
        {
            try
            {
                var db = cGlobal.gCharacterDataBase;
                if (db == null) return DailyLimit; // no database -> fail closed
                var dt = db.GetDataTable($"SELECT used FROM daily_draw WHERE charID={player.CharID} AND day='{Today()}'");
                if (dt != null && dt.Rows.Count > 0) return Convert.ToInt32(dt.Rows[0]["used"]);
            }
            catch (Exception ex)
            {
                DebugSystem.Write($"[AC104.GetUsedToday] Error: {ex.Message}");
            }
            return 0;
        }

        public static byte RemainingCredits(Player player)
        {
            return (byte)Math.Max(0, DailyLimit - GetUsedToday(player));
        }

        private static void RecordDraw(Player player)
        {
            try
            {
                var db = cGlobal.gCharacterDataBase;
                if (db == null) return;
                var dt = db.GetDataTable($"SELECT used FROM daily_draw WHERE charID={player.CharID} AND day='{Today()}'");
                if (dt != null && dt.Rows.Count > 0)
                    db.ExecuteNonQuery($"UPDATE daily_draw SET used = used + 1 WHERE charID={player.CharID} AND day='{Today()}'");
                else
                    db.ExecuteNonQuery($"INSERT INTO daily_draw (charID, day, used) VALUES ({player.CharID}, '{Today()}', 1)");
            }
            catch (Exception ex)
            {
                DebugSystem.Write($"[AC104.RecordDraw] Error: {ex.Message}");
            }
        }

        public static byte[] BuildCategoryMatrix(Player player)
        {
            // Authentic WLO Mall Category Matrix (from itemmall.pcapng); the AC 104 entry
            // carries the player's remaining daily lucky draw credits.
            return new byte[] { 0, 1, 101, 0, 3, 103, 0, 2, 104, 0, RemainingCredits(player), 102, 0, 3 };
        }

        public static void SendCategoryMatrix(Player player)
        {
            SendPacket s = new SendPacket();
            s.Pack8(54);
            s.Pack8(201);
            s.PackArray(BuildCategoryMatrix(player));
            player.Send(s);
        }

        /// <summary>
        /// Handles Spin Wheel Request: C->S [104, 1]
        /// </summary>
        private void Recv1(Player player, RecievePacket p)
        {
            try
            {
                if (RemainingCredits(player) <= 0)
                {
                    player.SendHeadBanner("No lucky draws left today. Come back tomorrow!");
                    DebugSystem.Write($"[AC104] Player {player.CharName} spin rejected: no credits remaining today.");
                    return;
                }

                var reward = LuckyDrawRewards[_rng.Next(LuckyDrawRewards.Length)];

                // 1. Grant reward item to player's inventory (AC 23 Sub 5 delta)
                int granted = player.Inv.AddItem(reward.ItemId, 1);

                // 2. Send wheel landing slot & spin counter: S->C [104, 1, 2, slot_index (1B), counter (1B)]
                SendPacket spinResult = Tools.FromFormat("bbbbb", 104, 1, 2, reward.SlotIndex, (byte)1);
                player.Send(spinResult);

                // 3. Send Lucky Draw global broadcast announcement: S->C [2, 15, 4, item_id (2B), amount (1B), string(player_name)]
                SendPacket broadcastPkt = new SendPacket();
                broadcastPkt.PackArray(new byte[] { 2, 15, 4 });
                broadcastPkt.Pack16(reward.ItemId);
                broadcastPkt.Pack8(1);
                broadcastPkt.PackString(player.CharName);
                player.Send(broadcastPkt);

                // 4. Consume one daily credit and push the refreshed matrix (the same
                //    54:201 table the client initially reads the credit count from).
                RecordDraw(player);
                SendCategoryMatrix(player);

                // 5. Nudge the client to repaint the bag (same finisher the verified gacha flow uses)
                if (granted > 0)
                {
                    player.Send(Tools.FromFormat("bb", 23, 15));
                }
                else
                {
                    player.SendHeadBanner("Bag full - lucky draw prize could not be delivered.");
                }

                DebugSystem.Write($"[AC104] Player {player.CharName} completed Daily Lucky Draw! Won: {reward.Name} (ID: {reward.ItemId}) on Slot {reward.SlotIndex} (delivered: {granted > 0}, credits left: {RemainingCredits(player)})");
            }
            catch (Exception ex)
            {
                DebugSystem.Write($"[AC104.Recv1] Error: {ex.Message}");
            }
        }
    }
}
