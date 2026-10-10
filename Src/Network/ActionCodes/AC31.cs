using System;
using System.Collections.Generic;
using System.Linq;
using Game;
using Game.Code;
using Game.QuestRelated;

namespace Network.ActionCodes
{
    public class AC31 : AC
    {
        public override int ID { get { return 31; } }

        private static string Snapshot(Player p)
        {
            var team = p.PlayerPets == null ? "-" : string.Join(",", p.PlayerPets.OrderBy(kv => kv.Key)
                .Select(kv => kv.Key + ":" + kv.Value.PetName + "#cs" + kv.Value.ClientSlot));
            var hotel = p.HotelPets == null ? "-" : string.Join(",", p.HotelPets.OrderBy(kv => kv.Key)
                .Select(kv => kv.Key + ":" + kv.Value.PetName));
            return "team[" + team + "] hotel[" + hotel + "]";
        }

        public override void ProcessPkt(Player p, RecievePacket r)
        {
            if (r.GetPtr() >= r.Buffer.Length) return;
            byte sub = r.Unpack8();
            byte[] data = r.Buffer.Skip(r.GetPtr()).ToArray();
            DebugSystem.Write("[AC31] in sub=" + sub + " data=[" + BitConverter.ToString(data) + "] " + Snapshot(p));
            if (sub == 1) { if (data.Length == 0) p.ConfirmNpcRest(); return; }
            byte[] deposits, withdrawals;
            // Native sender 0x2d0f96: 2 = hotel slots, 3 = team slots,
            // 4 = team count + slots + hotel count + slots (exchange).
            if (sub == 2) { deposits = new byte[0]; withdrawals = data; }
            else if (sub == 3) { deposits = data; withdrawals = new byte[0]; }
            else if (sub == 4)
            {
                if (data.Length < 2 || data[0] > 4 || data.Length < data[0] + 2)
                { DebugSystem.Write("[AC31] sub4 shape reject len=" + data.Length + " b0=" + (data.Length > 0 ? data[0] : -1)); return; }
                int n = data[0];
                int m = data[n + 1];
                if (m > 10 || data.Length != n + m + 2)
                { DebugSystem.Write("[AC31] sub4 count reject n=" + n + " m=" + m + " len=" + data.Length); return; }
                deposits = data.Skip(1).Take(n).ToArray();
                withdrawals = data.Skip(n + 2).ToArray();
            }
            else { DebugSystem.Write("[AC31] ignored sub=" + sub); return; } // 31:1 is a rest confirmation, never a hotel-open request.
            if (deposits.Length + withdrawals.Length == 0 || deposits.Length > 4 || withdrawals.Length > 10 ||
                deposits.Distinct().Count() != deposits.Length || withdrawals.Distinct().Count() != withdrawals.Length ||
                deposits.Any(s => s < 1 || s > 4) || withdrawals.Any(s => s < 1 || s > 10) ||
                Game.Battle.PvEBattleManager.IsInBattle(p))
            {
                DebugSystem.Write("[AC31] gate reject dep=[" + string.Join(",", deposits) + "] wd=[" + string.Join(",", withdrawals) +
                    "] inBattle=" + Game.Battle.PvEBattleManager.IsInBattle(p));
                return;
            }

            var outgoing = deposits.Select(p.GetClientPet).ToArray();
            if (outgoing.Any(pet => pet == null || pet.PetID == 0) || p.HotelPets == null ||
                withdrawals.Any(s => !p.HotelPets.ContainsKey(s) || p.HotelPets[s] == null))
            {
                DebugSystem.Write("[AC31] resolve reject dep=[" +
                    string.Join(",", deposits.Select((s, i) => s + "->" + (outgoing[i] == null ? "NULL" : outgoing[i].PetName))) + "] wd=[" +
                    string.Join(",", withdrawals.Select(s => s + "->" + (p.HotelPets != null && p.HotelPets.ContainsKey(s) && p.HotelPets[s] != null ? p.HotelPets[s].PetName : "MISSING"))) +
                    "] " + Snapshot(p));
                return;
            }
            var incoming = withdrawals.Select(s => p.HotelPets[s]).ToArray();
            var team = new Dictionary<byte, Player.PlayerPetData>(p.PlayerPets);
            var hotel = new Dictionary<byte, Player.PlayerPetData>(p.HotelPets);
            foreach (var pet in outgoing) team.Remove(pet.Slot);
            foreach (byte slot in withdrawals) hotel.Remove(slot);
            if (team.Count + incoming.Length > 4 || hotel.Count + outgoing.Length > 10)
            {
                DebugSystem.Write("[AC31] capacity reject team=" + team.Count + "+" + incoming.Length + " hotel=" + hotel.Count + "+" + outgoing.Length);
                p.SendSystemMessage(" Not enough free pet slots.");
                return;
            }
            var finalTeam = team.Values.Concat(incoming).ToArray();
            for (int i = 0; i < finalTeam.Length; i++)
                for (int j = 0; j < i; j++)
                    if (Player.IsSamePetOrCompanion(finalTeam[i].PetID, finalTeam[j].PetID))
                    {
                        DebugSystem.Write("[AC31] duplicate reject " + finalTeam[i].PetName + " vs " + finalTeam[j].PetName);
                        p.SendSystemMessage(" You already have this pet in your team.");
                        return;
                    }

            // Validate the whole selection before moving any pet. Exchange also works
            // when both lists are full; records retain all equipment and progression.
            foreach (byte slot in withdrawals) p.Send(Tools.FromFormat("bbb", 31, 4, slot));
            foreach (var pet in outgoing)
            {
                if (pet.IsRide) p.UnridePet();
                if (pet.IsBattle || Player.IsSamePetOrCompanion(p.ActivePetID, pet.PetID))
                {
                    p.ActivePetID = 0;
                    p.Send(Tools.FromFormat("bb", 19, 2));
                    p.CurMap?.Broadcast(Tools.FromFormat("bbd", 19, 7, p.CharID), "Ex", p.CharID);
                }
                byte slot = 1;
                while (hotel.ContainsKey(slot)) slot++;
                // Client copies the team record before AC15:2 deletes it.
                p.Send(Tools.FromFormat("bbbb", 31, 3, slot, pet.ClientSlot));
                p.Send(Tools.FromFormat("bbdb", 15, 2, p.CharID, pet.ClientSlot));
                DebugSystem.Write("[AC31] deposit " + pet.PetName + " teamCS=" + pet.ClientSlot + " -> hotelSlot=" + slot);
                pet.Slot = slot; pet.ClientSlot = 0; pet.IsBattle = false; pet.IsRide = false;
                hotel[slot] = pet;
            }
            p.PlayerPets = team;
            p.HotelPets = hotel;
            foreach (var pet in incoming)
            {
                byte slot = 1;
                while (team.ContainsKey(slot)) slot++;
                pet.Slot = slot; pet.IsBattle = false; pet.IsRide = false;
                pet.ClientSlot = 0;
                team[slot] = pet;
                // Incremental sync: deposits left holes on both sides, so the
                // first-free allocations here mirror the client's AddPetByID.
                // A bulk roster restore would desync those slot identities.
                if (p.RegisterClientPet(pet))
                {
                    DebugSystem.Write("[AC31] withdraw " + pet.PetName + " hotelSlot -> teamSlot=" + slot + " CS=" + pet.ClientSlot);
                    pet.NormalizeExpForLevel();
                    pet.NormalizeClientStats(inventory: p.Inv);
                    p.Send(QuestManager.CreatePetPacket(p, pet.PetID, pet.Slot, pet.HP, pet.MaxHP, pet.SP, pet.MaxSP,
                        pet.Amity, pet.Level, pet.Str, pet.Con, pet.Int, pet.Wis, pet.Agi, pet.Exp, pet.Reborn, pet.Job));
                    QuestManager.SendPetProgression(p, pet);
                    SendPacket namePacket = QuestManager.CreatePetNamePacket(p, pet);
                    if (namePacket != null) p.Send(namePacket);
                }
                else
                {
                    DebugSystem.Write("[AC31] withdraw " + pet.PetName + " RegisterClientPet FAILED (team full or duplicate)");
                }
            }
            // The client releases its per-transaction input lock only when a
            // VALID 31:6 record arrives after the request. Earlier eras sent
            // malformed records (name outside the 64-byte fixed part) or none
            // at all — both left the hotel window dead after one operation.
            p.SendPetHotelList();
            // The rest flow terminates its NPC-service session with 31:1,0
            // (Player.ConfirmNpcRest). The hotel transaction shares that
            // session machinery — without a terminal 31:1,0 the client's
            // service-busy flag never clears and all further AC31 sends
            // are silently dropped until relogin.
            p.Send(Tools.FromFormat("bbb", 31, 1, 0));
            p.SaveCharacterData();
            DebugSystem.Write("[AC31] done " + Snapshot(p));
        }
    }
}
