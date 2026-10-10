using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using DataBase;
using Game.Code;

namespace Server.API
{
    /// <summary>
    /// Simple HTTP server for handling web registration requests
    /// </summary>
    public class RegistrationServer
    {
        private HttpListener _listener;
        private Thread _listenerThread;
        private bool _isRunning;
        private readonly int _port;
        private readonly UserDataBase _userDb;

        public RegistrationServer(int port, UserDataBase userDb)
        {
            _port = port;
            _userDb = userDb;
        }

        public void Start()
        {
            if (_isRunning) return;

            _listener = new HttpListener();

            // Try http://+:port first (allows external access, requires admin)
            // Fall back to localhost if admin rights not available
            bool useExternalBinding = true;
            try
            {
                var testListener = new HttpListener();
                testListener.Prefixes.Add($"http://+:{_port}/");
                testListener.Start();
                testListener.Stop();
            }
            catch
            {
                useExternalBinding = false;
            }

            _listener.Prefixes.Add(useExternalBinding ? $"http://+:{_port}/" : $"http://localhost:{_port}/");

            try
            {
                _listener.Start();
                _isRunning = true;
                _listenerThread = new Thread(Listen);
                _listenerThread.IsBackground = true;
                _listenerThread.Start();
                DebugSystem.Write(useExternalBinding
                    ? $"[Registration] Started on http://*:{_port}/ (external access enabled)"
                    : $"[Registration] Started on http://localhost:{_port}/ (run as admin for external access)");
            }
            catch (Exception ex)
            {
                DebugSystem.Write($"Failed to start registration server: {ex.Message}");
            }
        }

        public void Stop()
        {
            _isRunning = false;
            _listener?.Stop();
        }

        private void Listen()
        {
            while (_isRunning)
            {
                try
                {
                    var context = _listener.GetContext();
                    ThreadPool.QueueUserWorkItem(o => HandleRequest(context));
                }
                catch (HttpListenerException)
                {
                    // Listener was stopped
                    break;
                }
            }
        }

        private void HandleRequest(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;

            // Enable CORS
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            response.Headers.Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

            if (request.HttpMethod == "OPTIONS")
            {
                response.StatusCode = 200;
                response.Close();
                return;
            }

            string responseString = "";
            response.ContentType = "application/json";

            try
            {
                string path = request.Url.AbsolutePath.ToLowerInvariant();

                if (path == "/register" && request.HttpMethod == "POST")
                {
                    responseString = HandleRegister(request);
                }
                else if (path == "/register" || path == "/register.html")
                {
                    response.ContentType = "text/html";
                    responseString = GetRegistrationPage();
                }
                else if (path == "/manage/create" && request.HttpMethod == "POST")
                {
                    responseString = HandleCreateChar(request);
                }
                else if (path == "/manage/points" && request.HttpMethod == "POST")
                {
                    responseString = HandlePoints(request);
                }
                else if (path == "/manage/edit" && request.HttpMethod == "POST")
                {
                    responseString = HandleEditChar(request);
                }
                else if (path == "/manage/chars")
                {
                    responseString = HandleListChars(request);
                }
                else if (path == "/manage" || path == "/manage.html")
                {
                    response.ContentType = "text/html; charset=utf-8";
                    responseString = GetManagePage();
                }
                else if (path.StartsWith("/api/buy"))
                {
                    response.ContentType = "application/json";
                    responseString = HandleApiBuy(request);
                }
                else if (path.StartsWith("/api/catalog"))
                {
                    response.ContentType = "application/json";
                    responseString = HandleApiCatalog();
                }
                else
                {
                    response.ContentType = "text/html; charset=utf-8";
                    responseString = GetItemMallPage();
                }
            }
            catch (Exception ex)
            {
                response.StatusCode = 500;
                responseString = $"{{\"success\":false,\"message\":\"{ex.Message}\"}}";
            }

            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.Close();
        }

        private string HandleApiCatalog()
        {
            var catalog = Game.PlayerRelated.ItemMallManager.GetCatalog();
            var jsonBuilder = new StringBuilder();
            jsonBuilder.Append("[");
            for (int i = 0; i < catalog.Count; i++)
            {
                var it = catalog[i];
                jsonBuilder.Append($"{{\"id\":{it.ItemID},\"name\":\"{it.ItemName}\",\"category\":\"{it.Category}\",\"cost\":{it.PointCost},\"count\":{it.Count}}}");
                if (i < catalog.Count - 1) jsonBuilder.Append(",");
            }
            jsonBuilder.Append("]");
            return jsonBuilder.ToString();
        }

        private string HandleApiBuy(HttpListenerRequest request)
        {
            string itemIdStr = request.QueryString["item"];
            string userStr = request.QueryString["user"];

            if (ushort.TryParse(itemIdStr, out ushort itemId) && !string.IsNullOrWhiteSpace(userStr))
            {
                var online = cGlobal.gCharacterDataBase?.GetOnlinePlayers();
                Game.Player target = null;
                if (online != null && online.Count > 0)
                {
                    target = online.FirstOrDefault(p => p.CharName.Equals(userStr, StringComparison.OrdinalIgnoreCase) || (p.UserAccount != null && p.UserAccount.UserName.Equals(userStr, StringComparison.OrdinalIgnoreCase)));
                }

                if (target != null)
                {
                    bool ok = Game.PlayerRelated.ItemMallManager.PurchaseItem(target, itemId, 1);
                    return $"{{\"success\":{(ok ? "true" : "false")},\"points\":{Game.PlayerRelated.ItemMallManager.GetUserPoints(target)}}}";
                }
            }

            return "{\"success\":false,\"error\":\"Player not found or not online\"}";
        }

        private string GetItemMallPage()
        {
            var catalog = Game.PlayerRelated.ItemMallManager.GetCatalog();
            var online = cGlobal.gCharacterDataBase?.GetOnlinePlayers();
            Game.Player player = (online != null && online.Count > 0) ? online.FirstOrDefault() : null;

            int currentPoints = player != null ? Game.PlayerRelated.ItemMallManager.GetUserPoints(player) : 0;
            string charName = player != null ? player.CharName : "Player";

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang='en'>");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset='UTF-8'>");
            sb.AppendLine("<title>Wonderland Online - Item Mall</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }");
            sb.AppendLine("  body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #f8fafc; padding: 20px; }");
            sb.AppendLine("  .header { display: flex; justify-content: space-between; align-items: center; background: rgba(30, 41, 59, 0.85); padding: 18px 24px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 24px; }");
            sb.AppendLine("  .title { font-size: 22px; font-weight: 700; color: #38bdf8; }");
            sb.AppendLine("  .balance-badge { background: linear-gradient(135deg, #f59e0b, #d97706); padding: 8px 18px; border-radius: 30px; font-weight: 700; font-size: 15px; color: #fff; }");
            sb.AppendLine("  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; }");
            sb.AppendLine("  .card { background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 16px; display: flex; flex-direction: column; justify-content: space-between; }");
            sb.AppendLine("  .card-category { font-size: 11px; text-transform: uppercase; color: #38bdf8; font-weight: 700; margin-bottom: 6px; }");
            sb.AppendLine("  .card-name { font-size: 15px; font-weight: 600; color: #f1f5f9; margin-bottom: 12px; }");
            sb.AppendLine("  .card-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; }");
            sb.AppendLine("  .card-price { font-size: 16px; font-weight: 700; color: #fbbf24; }");
            sb.AppendLine("  .buy-btn { background: #2563eb; color: #fff; border: none; padding: 8px 14px; border-radius: 6px; font-weight: 600; cursor: pointer; }");
            sb.AppendLine("  .buy-btn:hover { background: #1d4ed8; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("  <div class='header'>");
            sb.AppendLine("    <div class='title'> Wonderland Online Item Mall</div>");
            sb.AppendLine($"    <div class='balance-badge'> {charName}: <span id='user-pts'>{currentPoints}</span> IM Points</div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class='grid'>");

            foreach (var item in catalog)
            {
                sb.AppendLine("    <div class='card'>");
                sb.AppendLine("      <div>");
                sb.AppendLine($"        <div class='card-category'>{item.Category} (x{item.Count})</div>");
                sb.AppendLine($"        <div class='card-name'>{item.ItemName}</div>");
                sb.AppendLine("      </div>");
                sb.AppendLine("      <div class='card-footer'>");
                sb.AppendLine($"        <div class='card-price'>{item.PointCost} Pts</div>");
                sb.AppendLine($"        <button class='buy-btn' onclick='buyItem({item.ItemID}, \"{item.ItemName}\", {item.PointCost})'>Buy Now</button>");
                sb.AppendLine("      </div>");
                sb.AppendLine("    </div>");
            }

            sb.AppendLine("  </div>");
            sb.AppendLine("<script>");
            sb.AppendLine("  function buyItem(id, name, cost) {");
            sb.AppendLine("    if(!confirm('Purchase ' + name + ' for ' + cost + ' IM Points?')) return;");
            sb.AppendLine($"    fetch('/api/buy?item=' + id + '&user={charName}')");
            sb.AppendLine("      .then(r => r.json())");
            sb.AppendLine("      .then(d => {");
            sb.AppendLine("        if(d.success) {");
            sb.AppendLine("          alert('Purchase successful! Item delivered directly to your inventory in-game.');");
            sb.AppendLine("          document.getElementById('user-pts').innerText = d.points;");
            sb.AppendLine("        } else {");
            sb.AppendLine("          alert('Purchase failed: ' + (d.error || 'Insufficient IM Points!'));");
            sb.AppendLine("        }");
            sb.AppendLine("      })");
            sb.AppendLine("      .catch(e => alert('Network error: ' + e));");
            sb.AppendLine("  }");
            sb.AppendLine("</script>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return sb.ToString();
        }

        #region Character Management (web tool)

        private static readonly Encoding WireText = Encoding.GetEncoding(950);

        private static string Json(bool success, string message)
        {
            return $"{{\"success\":{(success ? "true" : "false")},\"message\":\"{EscapeJson(message)}\"}}";
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ') sb.Append(string.Format("\\u{0:x4}", (int)c));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        private static Dictionary<string, string> ParseFormBody(HttpListenerRequest request)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                foreach (var pair in body.Split('&'))
                {
                    if (string.IsNullOrEmpty(pair)) continue;
                    var parts = pair.Split(new[] { '=' }, 2);
                    if (parts.Length == 2)
                        result[Uri.UnescapeDataString(parts[0])] = Uri.UnescapeDataString(parts[1]).Replace('+', ' ');
                }
            }
            return result;
        }

        private static bool TryGetFormLong(Dictionary<string, string> form, string key, out long value)
        {
            value = 0;
            string s;
            if (!form.TryGetValue(key, out s)) return false;
            s = s.Trim();
            if (s.Length == 0) return false;
            return long.TryParse(s, out value);
        }

        private bool ValidateAccount(Dictionary<string, string> form, out uint dbid, out string[] userdata, out string error)
        {
            dbid = 0;
            userdata = null;
            error = null;

            string username = form.ContainsKey("username") ? form["username"].Trim().ToLower() : "";
            string password = form.ContainsKey("password") ? form["password"] : "";

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                error = "请输入账号和密码";
                return false;
            }
            if (!cGlobal.gUserDataBase.GetUserData(username, password, out dbid, out userdata) || dbid == 0)
            {
                error = "账号或密码错误";
                return false;
            }
            return true;
        }

        private static bool TryGetAccount(uint dbid, out uint charID1, out uint charID2)
        {
            charID1 = dbid + 10000;
            charID2 = dbid + 10000 + 4500000;
            return dbid != 0;
        }

        private string HandleCreateChar(HttpListenerRequest request)
        {
            var form = ParseFormBody(request);
            var db = cGlobal.gCharacterDataBase;

            uint dbid; string[] userdata; string error;
            if (!ValidateAccount(form, out dbid, out userdata, out error))
                return Json(false, error);
            if (db == null || db.ItemDat == null)
                return Json(false, "服务端数据未就绪（Item.dat 未加载）");

            string charName = form.ContainsKey("charname") ? form["charname"].Trim() : "";

            byte[] nameBytes;
            try { nameBytes = WireText.GetBytes(charName); }
            catch { nameBytes = null; }
            if (string.IsNullOrEmpty(charName) || nameBytes == null || nameBytes.Length < 4 || nameBytes.Length > 14)
                return Json(false, "角色名长度需为 4~14 字节（一个汉字算 2 字节）");

            if (!db.LockName(dbid, charName))
                return Json(false, "角色名已被占用或不可用");
            db.unLockName(charName); // once written, the DB row becomes authoritative

            uint charID1, charID2;
            TryGetAccount(dbid, out charID1, out charID2);
            bool slot1Used = db.GetCharacterData(charID1) != null;
            bool slot2Used = db.GetCharacterData(charID2) != null;
            if (slot1Used && slot2Used)
                return Json(false, "该账号的两个角色位都已占用，请先删除一个角色");
            byte slot = (byte)(slot1Used ? 2 : 1);

            long bodyVal, headVal, hairVal, skinVal, clothVal, eyeVal, elementVal;
            long strVal, conVal, intVal, wisVal, agiVal;
            TryGetFormLong(form, "body", out bodyVal); TryGetFormLong(form, "head", out headVal);
            TryGetFormLong(form, "haircolor", out hairVal); TryGetFormLong(form, "skincolor", out skinVal);
            TryGetFormLong(form, "clothingcolor", out clothVal); TryGetFormLong(form, "eyecolor", out eyeVal);
            TryGetFormLong(form, "element", out elementVal);
            TryGetFormLong(form, "str", out strVal); TryGetFormLong(form, "con", out conVal);
            TryGetFormLong(form, "int", out intVal); TryGetFormLong(form, "wis", out wisVal); TryGetFormLong(form, "agi", out agiVal);

            if (bodyVal < 1 || bodyVal > 4) return Json(false, "无效的体型");
            if (elementVal < 1 || elementVal > 4) return Json(false, "无效的属性系");

            var player = new Game.Player(db.ItemDat);
            player.UserAcc.DataBaseID = dbid;
            player.UserAcc.UserName = userdata[0];
            player.UserAcc.Cipher = userdata[1];
            player.UserAcc.IM = 0;
            int imParsed;
            if (userdata.Length > 2 && int.TryParse(userdata[2], out imParsed)) player.UserAcc.IM = imParsed;
            player.Slot = slot;
            player.CharName = charName;
            player.NickName = "";
            player.Eqs.Body = (Game.BodyStyle)bodyVal;
            player.Eqs.Head = (byte)Math.Max(0, Math.Min(headVal, 15));
            player.HairColor = (ushort)Math.Max(0, Math.Min(hairVal, 65535));
            player.SkinColor = (ushort)Math.Max(0, Math.Min(skinVal, 65535));
            player.ClothingColor = (ushort)Math.Max(0, Math.Min(clothVal, 65535));
            player.EyeColor = (ushort)Math.Max(0, Math.Min(eyeVal, 65535));
            player.Eqs.Element = (Game.Affinity)elementVal;
            player.Eqs.Str = (ushort)Math.Max(0, Math.Min(strVal, 30));
            player.Eqs.Con = (ushort)Math.Max(0, Math.Min(conVal, 30));
            player.Eqs.Int = (ushort)Math.Max(0, Math.Min(intVal, 30));
            player.Eqs.Wis = (ushort)Math.Max(0, Math.Min(wisVal, 30));
            player.Eqs.Agi = (ushort)Math.Max(0, Math.Min(agiVal, 30));

            // Same pipeline as the in-game creator (AC09)
            player.SetBeginnerOutfit();
            player.Eqs.ApplyCharacterBaseStats();
            player.FillHP(); player.FillSP();
            player.Settings.ChannelCode = (ChannelCodeType)31;
            player.Settings.TRADABLE = true;
            player.Settings.PKABLE = false;
            player.Settings.JOINABLE = true;
            player.Eqs.TotalExp = 6;
            player.LoginMap = 10017;
            player.CurX = 1042;
            player.CurY = 1075;
            player.SetGold(0);
            player.Started_Quests.Add(new Game.Quest() { QID = 1 });
            Game.PlayerRelated.StarterPackManager.DeliverToPlayer(player, sendData: false);

            if (!db.WriteNewPlayer(player.CharID, player))
                return Json(false, "写入数据库失败，请查看服务端日志");

            DebugSystem.Write($"[WebManage] Created character '{charName}' (charID={player.CharID}) for account '{userdata[0]}' via web tool");
            return Json(true, "角色「" + charName + "」创建成功（角色位 " + slot + "）。重新登录游戏即可在选角界面看到");
        }

        private string HandlePoints(HttpListenerRequest request)
        {
            var form = ParseFormBody(request);

            uint dbid; string[] userdata; string error;
            if (!ValidateAccount(form, out dbid, out userdata, out error))
                return Json(false, error);

            long amount;
            if (!TryGetFormLong(form, "amount", out amount) || amount == 0)
                return Json(false, "请输入有效的点数变动值（正数充值，负数扣除）");

            var online = (cGlobal.gCharacterDataBase?.GetOnlinePlayers() ?? new List<Game.Player>())
                .FirstOrDefault(p => p.UserAcc != null && p.UserAcc.DataBaseID == dbid);

            int current = online != null
                ? Game.PlayerRelated.ItemMallManager.GetUserPoints(online)
                : _userDb.GetIMPoints(dbid);
            int updated = Math.Max(0, current + (int)Math.Max(-2000000000, Math.Min(amount, 2000000000)));

            if (!_userDb.SetIMPoints(dbid, updated))
                return Json(false, "数据库更新失败");

            if (online != null)
            {
                online.UserAcc.IM = updated;
                Game.PlayerRelated.ItemMallManager.SendPointBalance(online);
            }

            DebugSystem.Write($"[WebManage] IM points for account '{userdata[0]}': {current} -> {updated} ({(online != null ? "online, synced" : "offline")})");
            return Json(true, $"点数更新成功：{current:N0} → {updated:N0}" + (online != null ? "（角色在线，已实时同步）" : "（角色离线，登录后生效）"));
        }

        private string HandleListChars(HttpListenerRequest request)
        {
            string username = (request.QueryString["user"] ?? "").Trim().ToLower();
            string password = request.QueryString["pass"] ?? "";

            uint dbid; string[] userdata;
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) ||
                !cGlobal.gUserDataBase.GetUserData(username, password, out dbid, out userdata) || dbid == 0)
                return Json(false, "账号或密码错误");

            var db = cGlobal.gCharacterDataBase;
            var online = db?.GetOnlinePlayers() ?? new List<Game.Player>();
            var onlineAcc = online.FirstOrDefault(p => p.UserAcc != null && p.UserAcc.DataBaseID == dbid);
            int points = onlineAcc != null
                ? Game.PlayerRelated.ItemMallManager.GetUserPoints(onlineAcc)
                : _userDb.GetIMPoints(dbid);

            var sb = new StringBuilder();
            sb.Append("{\"success\":true,\"points\":").Append(points).Append(",\"characters\":[");

            int written = 0;
            for (int slot = 1; slot <= 2; slot++)
            {
                uint charID = (slot == 1) ? dbid + 10000 : dbid + 10000 + 4500000;
                var ch = db.GetCharacterData(charID);
                if (ch == null) continue;

                bool isOnline = online.Any(p => p.CharID == charID);
                if (written > 0) sb.Append(",");
                sb.Append("{\"charid\":").Append(charID)
                  .Append(",\"slot\":").Append(slot)
                  .Append(",\"name\":\"").Append(EscapeJson(ch.CharName)).Append("\"")
                  .Append(",\"level\":").Append(ch.Level)
                  .Append(",\"exp\":").Append(ch.TotalExp)
                  .Append(",\"gold\":").Append(ch.Gold)
                  .Append(",\"element\":").Append((byte)ch.Element)
                  .Append(",\"str\":").Append(ch.baseStr)
                  .Append(",\"con\":").Append(ch.baseCon)
                  .Append(",\"int\":").Append(ch.baseInt)
                  .Append(",\"wis\":").Append(ch.baseWis)
                  .Append(",\"agi\":").Append(ch.baseAgi)
                  .Append(",\"skillpoints\":").Append(ch.SkillPoints)
                  .Append(",\"online\":").Append(isOnline ? "true" : "false")
                  .Append("}");
                written++;
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private string HandleEditChar(HttpListenerRequest request)
        {
            var form = ParseFormBody(request);
            var db = cGlobal.gCharacterDataBase;

            uint dbid; string[] userdata; string error;
            if (!ValidateAccount(form, out dbid, out userdata, out error))
                return Json(false, error);

            long charIdIn;
            if (!TryGetFormLong(form, "charid", out charIdIn))
                return Json(false, "缺少角色 ID");
            uint charID = (uint)charIdIn;

            uint charID1, charID2;
            TryGetAccount(dbid, out charID1, out charID2);
            if (charID != charID1 && charID != charID2)
                return Json(false, "该角色不属于此账号");

            var onlinePlayers = db.GetOnlinePlayers();
            if (onlinePlayers.Any(p => p.CharID == charID))
                return Json(false, "该角色当前在线，请先退出游戏（登出到选角界面）再修改");

            var ch = db.GetCharacterData(charID);
            if (ch == null)
                return Json(false, "角色不存在");

            var changed = new List<string>();

            #region characters table fields
            var sets = new List<string>();
            var parms = new List<RCLibrary.Core.DbParam>();

            string newName = form.ContainsKey("newname") ? form["newname"].Trim() : "";
            if (!string.IsNullOrEmpty(newName) && newName != ch.CharName)
            {
                byte[] nb;
                try { nb = WireText.GetBytes(newName); }
                catch { nb = null; }
                if (nb == null || nb.Length < 4 || nb.Length > 14)
                    return Json(false, "新角色名长度需为 4~14 字节（一个汉字算 2 字节）");
                if (!db.LockName(dbid, newName))
                    return Json(false, "新角色名已被占用或不可用");
                db.unLockName(newName);

                sets.Add("name = @name");
                sets.Add("name_clean = @nc");
                parms.Add(new RCLibrary.Core.DbParam("@name", newName));
                parms.Add(new RCLibrary.Core.DbParam("@nc", newName.ToLower()));
                changed.Add("改名为「" + newName + "」");
            }

            long goldVal, elementVal;
            if (TryGetFormLong(form, "gold", out goldVal))
            {
                sets.Add("gold = " + Math.Max(0, Math.Min(goldVal, 2000000000)));
                changed.Add("金币 " + Math.Max(0, Math.Min(goldVal, 2000000000)).ToString("N0"));
            }
            if (TryGetFormLong(form, "element", out elementVal))
            {
                if (elementVal < 0 || elementVal > 5) return Json(false, "无效的属性系");
                sets.Add("element = " + elementVal);
                changed.Add("属性系");
            }

            if (sets.Count > 0)
            {
                db.ExecuteNonQuery("UPDATE characters SET " + string.Join(", ", sets) + " WHERE charID = '" + charID + "'", parms.ToArray());
            }
            #endregion

            #region stats rows (upsert like WritePlayer)
            var statUpdates = new List<KeyValuePair<int, long>>();

            long levelVal, expVal;
            if (TryGetFormLong(form, "level", out levelVal))
            {
                if (levelVal < 1 || levelVal > 199) return Json(false, "等级需在 1~199 之间");
                long expTotal = 0;
                for (int l = 1; l < levelVal; l++) expTotal += ch.CalcMaxExp(0, l);
                statUpdates.Add(new KeyValuePair<int, long>(36, expTotal + 5)); // ~6 exp into the target level, same as a fresh character
                changed.Add("等级 " + levelVal);
            }
            else if (TryGetFormLong(form, "exp", out expVal))
            {
                statUpdates.Add(new KeyValuePair<int, long>(36, Math.Max(0, expVal)));
                changed.Add("总经验 " + expVal.ToString("N0"));
            }

            long v;
            if (TryGetFormLong(form, "str", out v)) statUpdates.Add(new KeyValuePair<int, long>(28, ClampStat(v)));
            if (TryGetFormLong(form, "con", out v)) statUpdates.Add(new KeyValuePair<int, long>(29, ClampStat(v)));
            if (TryGetFormLong(form, "agi", out v)) statUpdates.Add(new KeyValuePair<int, long>(30, ClampStat(v)));
            if (TryGetFormLong(form, "int", out v)) statUpdates.Add(new KeyValuePair<int, long>(27, ClampStat(v)));
            if (TryGetFormLong(form, "wis", out v)) statUpdates.Add(new KeyValuePair<int, long>(33, ClampStat(v)));
            if (TryGetFormLong(form, "skillpoints", out v)) statUpdates.Add(new KeyValuePair<int, long>(38, Math.Max(0, Math.Min(v, 65535))));
            if (statUpdates.Count(kv => kv.Key != 36) > 0) changed.Add("基础属性/技能点");

            foreach (var kv in statUpdates)
            {
                var existing = db.GetDataTable("SELECT * FROM stats WHERE charID = '" + charID + "' AND statID = '" + kv.Key + "'");
                if (existing != null && existing.Rows.Count > 0)
                    db.ExecuteNonQuery("UPDATE stats SET StatusUp = '" + kv.Value + "' WHERE charID = '" + charID + "' AND statID = '" + kv.Key + "'");
                else
                    db.ExecuteNonQuery("INSERT INTO stats (statIdx,charID,statID,StatusUp,potential) VALUES ('0','" + charID + "','" + kv.Key + "','" + kv.Value + "','0')");
            }
            #endregion

            if (changed.Count == 0)
                return Json(false, "没有需要修改的内容");

            db.EvictCache(charID);
            DebugSystem.Write($"[WebManage] Edited character charID={charID} via web tool: {string.Join(", ", changed)}");
            return Json(true, "修改完成（" + string.Join("、", changed) + "）。重新登录游戏后生效");
        }

        private static long ClampStat(long v)
        {
            return Math.Max(1, Math.Min(v, 65535));
        }

        #endregion

        private string HandleRegister(HttpListenerRequest request)
        {
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();

                // Parse form data or JSON
                string username = "", password = "", email = "";

                if (request.ContentType?.Contains("application/x-www-form-urlencoded") == true)
                {
                    // Manual query string parsing
                    var pairs = body.Split('&');
                    foreach (var pair in pairs)
                    {
                        var parts = pair.Split(new[] { '=' }, 2);
                        if (parts.Length == 2)
                        {
                            var key = Uri.UnescapeDataString(parts[0]);
                            var value = Uri.UnescapeDataString(parts[1]);
                            if (key == "username") username = value;
                            else if (key == "password") password = value;
                            else if (key == "email") email = value;
                        }
                    }
                }
                else
                {
                    // Simple JSON parsing
                    username = ExtractJsonValue(body, "username");
                    password = ExtractJsonValue(body, "password");
                    email = ExtractJsonValue(body, "email");
                }

                // Validate input
                if (string.IsNullOrWhiteSpace(username) || username.Length < 3)
                {
                    return "{\"success\":false,\"message\":\"Username must be at least 3 characters\"}";
                }
                if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
                {
                    return "{\"success\":false,\"message\":\"Password must be at least 4 characters\"}";
                }
                if (string.IsNullOrWhiteSpace(email) || !email.Contains("@"))
                {
                    return "{\"success\":false,\"message\":\"Please enter a valid email\"}";
                }

                // Register user
                string errorMessage;
                bool success = _userDb.RegisterUser(username, password, email, out errorMessage);

                if (success)
                {
                    return "{\"success\":true,\"message\":\"Registration successful! You can now login.\"}";
                }
                else
                {
                    return $"{{\"success\":false,\"message\":\"{errorMessage}\"}}";
                }
            }
        }

        private string ExtractJsonValue(string json, string key)
        {
            try
            {
                int keyIndex = json.IndexOf($"\"{key}\"");
                if (keyIndex < 0) return "";
                int colonIndex = json.IndexOf(":", keyIndex);
                int valueStart = json.IndexOf("\"", colonIndex) + 1;
                int valueEnd = json.IndexOf("\"", valueStart);
                return json.Substring(valueStart, valueEnd - valueStart);
            }
            catch
            {
                return "";
            }
        }

        private string GetManagePage()
        {
            return @"<!DOCTYPE html>
<html lang='zh-CN'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>漂流幻境 · 角色管理</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; min-height: 100vh; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 30px 15px; color: #e8e8f0; }
.wrap { max-width: 760px; margin: 0 auto; }
h1 { text-align: center; font-size: 1.6rem; margin-bottom: 6px; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.sub { text-align: center; color: rgba(255,255,255,0.45); font-size: 0.8rem; margin-bottom: 24px; }
.tabs { display: flex; gap: 8px; margin-bottom: 20px; }
.tabs button { flex: 1; padding: 12px; border: 1px solid rgba(255,255,255,0.12); border-radius: 10px; background: rgba(255,255,255,0.04); color: rgba(255,255,255,0.6); font-size: 0.95rem; cursor: pointer; transition: all .2s; }
.tabs button.active { background: linear-gradient(90deg, #2563eb, #38bdf8); color: #fff; border-color: transparent; font-weight: 600; }
.tab { display: none; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 26px; }
.tab.active { display: block; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 18px; }
.grid .full { grid-column: 1 / -1; }
label { display: block; color: rgba(255,255,255,0.7); font-size: 0.8rem; margin-bottom: 5px; }
input, select { width: 100%; padding: 10px 12px; border: 1px solid rgba(255,255,255,0.12); border-radius: 8px; background: rgba(0,0,0,0.3); color: #fff; font-size: 0.9rem; }
input:focus, select:focus { outline: none; border-color: #38bdf8; }
.hint { color: rgba(255,255,255,0.35); font-size: 0.72rem; margin-top: 4px; }
.btn { padding: 12px 24px; border: none; border-radius: 8px; background: linear-gradient(90deg, #e94560, #ff6b6b); color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; margin-top: 16px; }
.btn:hover { filter: brightness(1.1); }
.btn.blue { background: linear-gradient(90deg, #2563eb, #38bdf8); }
.btn.sm { padding: 6px 12px; font-size: 0.8rem; margin-top: 0; }
.quick { display: flex; gap: 8px; margin-top: 8px; }
.quick button { flex: 1; padding: 7px; border: 1px solid rgba(56,189,248,0.4); border-radius: 6px; background: rgba(56,189,248,0.08); color: #38bdf8; cursor: pointer; font-size: 0.8rem; }
.msg { margin-top: 14px; padding: 11px 14px; border-radius: 8px; font-size: 0.85rem; display: none; }
.msg.ok { background: rgba(46,213,115,0.15); color: #2ed573; border: 1px solid rgba(46,213,115,0.3); }
.msg.err { background: rgba(255,71,87,0.15); color: #ff4757; border: 1px solid rgba(255,71,87,0.3); }
.card { background: rgba(0,0,0,0.25); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 18px; margin-top: 16px; }
.card h3 { font-size: 1rem; margin-bottom: 12px; color: #38bdf8; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.7rem; margin-left: 8px; vertical-align: middle; }
.badge.on { background: rgba(46,213,115,0.2); color: #2ed573; }
.badge.off { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.4); }
.statline { color: rgba(255,255,255,0.5); font-size: 0.75rem; margin-bottom: 14px; }
</style>
</head>
<body>
<div class='wrap'>
<h1>漂流幻境 · 角色管理</h1>
<p class='sub'>本地服务管理工具 · 创建角色 / 商城点数 / 角色属性</p>
<div class='tabs'>
<button class='active' data-tab='create'>创建角色</button>
<button data-tab='points'>商城点数</button>
<button data-tab='edit'>角色属性</button>
</div>

<div id='tab-create' class='tab active'>
<form id='createForm'>
<div class='grid'>
<div><label>游戏账号</label><input name='username' required></div>
<div><label>密码</label><input name='password' type='password' required></div>
<div class='full'><label>角色名（支持中文，4~14 字节，一个汉字 2 字节）</label><input name='charname' maxlength='14' required></div>
<div><label>体型</label>
<select name='body' id='bodySel'>
<option value='1'>小体型 · 男</option>
<option value='2'>小体型 · 女</option>
<option value='3' selected>大体型 · 男</option>
<option value='4'>大体型 · 女</option>
</select></div>
<div><label>发型</label><select name='head' id='headSel'></select></div>
<div><label>属性系</label>
<select name='element'>
<option value='1'>地</option>
<option value='2' selected>水</option>
<option value='3'>火</option>
<option value='4'>风</option>
</select></div>
<div><label>发色</label><input type='number' name='haircolor' value='0' min='0' max='15'></div>
<div><label>肤色</label><input type='number' name='skincolor' value='0' min='0' max='15'></div>
<div><label>衣色</label><input type='number' name='clothingcolor' value='0' min='0' max='15'></div>
<div><label>瞳色</label><input type='number' name='eyecolor' value='0' min='0' max='15'></div>
<div><label>力量 STR</label><input type='number' name='str' value='5' min='0' max='30'></div>
<div><label>体质 CON</label><input type='number' name='con' value='5' min='0' max='30'></div>
<div><label>智力 INT</label><input type='number' name='int' value='5' min='0' max='30'></div>
<div><label>智慧 WIS</label><input type='number' name='wis' value='5' min='0' max='30'></div>
<div><label>敏捷 AGI</label><input type='number' name='agi' value='5' min='0' max='30'></div>
<div class='full'><p class='hint'>创建流程与游戏内建角色完全一致：出生在沉船(10017)、带初始装备和新手包、初始任务。创建后重新登录游戏即可看到。</p></div>
</div>
<button class='btn' type='submit'>创建角色</button>
</form>
<div id='createMsg' class='msg'></div>
</div>

<div id='tab-points' class='tab'>
<form id='pointsForm'>
<div class='grid'>
<div><label>游戏账号</label><input name='username' required></div>
<div><label>密码</label><input name='password' type='password' required></div>
<div class='full'><label>点数变动（正数充值，负数扣除）</label><input type='number' name='amount' id='amountInput' value='1000' required>
<div class='quick'>
<button type='button' onclick='setAmt(100)'>+100</button>
<button type='button' onclick='setAmt(500)'>+500</button>
<button type='button' onclick='setAmt(1000)'>+1000</button>
<button type='button' onclick='setAmt(10000)'>+10000</button>
<button type='button' onclick='setAmt(-100)'>-100</button>
</div></div>
</div>
<button class='btn blue' type='submit'>提交</button>
</form>
<div id='pointsMsg' class='msg'></div>
</div>

<div id='tab-edit' class='tab'>
<form id='loadForm'>
<div class='grid'>
<div><label>游戏账号</label><input name='username' required></div>
<div><label>密码</label><input name='password' type='password' required></div>
</div>
<button class='btn blue' type='submit'>加载角色</button>
</form>
<div id='editMsg' class='msg'></div>
<div id='charList'></div>
</div>
</div>

<script>
var heads = {
1: [['0','罗可']],
2: [['0','妮娜'],['1','贝蒂']],
3: [['0','丹尼尔'],['1','席德'],['2','莫尔'],['3','铁男']],
4: [['0','艾丽丝'],['1','莉可'],['2','凡妮莎'],['3','布瑞拉'],['4','杰西卡'],['5','小卷'],['6','玛丽亚'],['7','卡琳']]
};
var elemNames = ['无','地','水','火','风'];
function populateHeads(){
var b = document.getElementById('bodySel').value;
var sel = document.getElementById('headSel');
sel.innerHTML = '';
heads[b].forEach(function(h){ var o=document.createElement('option'); o.value=h[0]; o.textContent=h[1]; sel.appendChild(o); });
}
populateHeads();
document.getElementById('bodySel').addEventListener('change', populateHeads);

document.querySelectorAll('.tabs button').forEach(function(b){
b.addEventListener('click', function(){
document.querySelectorAll('.tabs button').forEach(function(x){ x.classList.remove('active'); });
document.querySelectorAll('.tab').forEach(function(x){ x.classList.remove('active'); });
b.classList.add('active');
document.getElementById('tab-'+b.dataset.tab).classList.add('active');
});
});

function show(id, ok, text){
var el = document.getElementById(id);
el.textContent = text;
el.className = 'msg ' + (ok ? 'ok' : 'err');
el.style.display = 'block';
}
function postForm(url, data){
return fetch(url, { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: data })
.then(function(r){ return r.json(); });
}
function encodeForm(vals){
return vals.map(function(kv){ return encodeURIComponent(kv[0]) + '=' + encodeURIComponent(kv[1]); }).join('&');
}

document.getElementById('createForm').addEventListener('submit', function(e){
e.preventDefault();
var f = e.target;
var vals = ['username','password','charname','body','head','element','haircolor','skincolor','clothingcolor','eyecolor','str','con','int','wis','agi']
.map(function(n){ return [n, f.elements[n].value]; });
show('createMsg', true, '正在创建…');
postForm('/manage/create', encodeForm(vals)).then(function(d){
show('createMsg', d.success, d.message);
if(d.success) f.elements['charname'].value = '';
});
});

function setAmt(v){ document.getElementById('amountInput').value = v; }
document.getElementById('pointsForm').addEventListener('submit', function(e){
e.preventDefault();
var f = e.target;
show('pointsMsg', true, '正在提交…');
postForm('/manage/points', encodeForm([['username', f.elements['username'].value],['password', f.elements['password'].value],['amount', f.elements['amount'].value]]))
.then(function(d){ show('pointsMsg', d.success, d.message); });
});

document.getElementById('loadForm').addEventListener('submit', function(e){
e.preventDefault();
var f = e.target;
var user = f.elements['username'].value, pass = f.elements['password'].value;
document.getElementById('charList').innerHTML = '';
show('editMsg', true, '正在加载…');
fetch('/manage/chars?user=' + encodeURIComponent(user) + '&pass=' + encodeURIComponent(pass))
.then(function(r){ return r.json(); })
.then(function(d){
if(!d.success){ show('editMsg', false, d.message); return; }
show('editMsg', true, '商城点数：' + d.points.toLocaleString() + ' 点');
if(d.characters.length === 0){
document.getElementById('charList').innerHTML = '<div class=\'card\'><p class=\'statline\'>该账号还没有角色，请先到「创建角色」页创建。</p></div>';
return;
}
d.characters.forEach(function(c){ renderCard(c); });
});
});

function renderCard(c){
var div = document.createElement('div');
div.className = 'card';
var onlineBadge = c.online ? '<span class=\'badge on\'>在线</span>' : '<span class=\'badge off\'>离线</span>';
var levelOpts = '<option value=\'\'>不修改</option>';
for(var i = 1; i <= 199; i++){
levelOpts += '<option value=\'' + i + '\'' + (i === c.level ? ' selected' : '') + '>' + i + ' 级</option>';
}
var elemOpts = '';
for(var j = 0; j <= 4; j++){
elemOpts += '<option value=\'' + j + '\'' + (j === c.element ? ' selected' : '') + '>' + elemNames[j] + '</option>';
}
div.innerHTML = '<h3>' + c.name + ' · 角色位 ' + c.slot + onlineBadge + '</h3>' +
'<p class=\'statline\'>charID ' + c.charid + ' · 等级 ' + c.level + ' · 总经验 ' + c.exp.toLocaleString() + ' · 金币 ' + c.gold.toLocaleString() + ' · 技能点 ' + c.skillpoints + ' · STR ' + c.str + ' / CON ' + c.con + ' / INT ' + c.int + ' / WIS ' + c.wis + ' / AGI ' + c.agi + '</p>' +
'<div class=\'grid\'>' +
'<div><label>金币</label><input type=\'number\' name=\'gold\' value=\'' + c.gold + '\' min=\'0\'></div>' +
'<div><label>等级（会重算总经验）</label><select name=\'level\'>' + levelOpts + '</select></div>' +
'<div><label>力量 STR</label><input type=\'number\' name=\'str\' value=\'' + c.str + '\' min=\'1\'></div>' +
'<div><label>体质 CON</label><input type=\'number\' name=\'con\' value=\'' + c.con + '\' min=\'1\'></div>' +
'<div><label>智力 INT</label><input type=\'number\' name=\'int\' value=\'' + c.int + '\' min=\'1\'></div>' +
'<div><label>智慧 WIS</label><input type=\'number\' name=\'wis\' value=\'' + c.wis + '\' min=\'1\'></div>' +
'<div><label>敏捷 AGI</label><input type=\'number\' name=\'agi\' value=\'' + c.agi + '\' min=\'1\'></div>' +
'<div><label>技能点</label><input type=\'number\' name=\'skillpoints\' value=\'' + c.skillpoints + '\' min=\'0\'></div>' +
'<div><label>属性系</label><select name=\'element\'>' + elemOpts + '</select></div>' +
'<div><label>改名为（留空 = 不改）</label><input name=\'newname\' maxlength=\'14\' placeholder=\'支持中文\'></div>' +
'</div>' +
'<button class=\'btn sm\' type=\'button\'>保存修改</button>';
var orig = {
gold: String(c.gold), level: c.level === 0 ? '' : String(c.level), str: String(c.str), con: String(c.con),
int: String(c.int), wis: String(c.wis), agi: String(c.agi), skillpoints: String(c.skillpoints),
element: String(c.element), newname: ''
};
div.querySelector('button').addEventListener('click', function(){
var vals = [];
div.querySelectorAll('[name]').forEach(function(inp){
var n = inp.name, v = inp.value;
if(v !== orig[n]) vals.push([n, v]);
});
if(vals.length === 0){ alert('没有修改任何内容'); return; }
vals.unshift(['charid', c.charid]);
var lf = document.getElementById('loadForm');
vals.unshift(['username', lf.elements['username'].value]);
vals.unshift(['password', lf.elements['password'].value]);
postForm('/manage/edit', encodeForm(vals)).then(function(d){ alert(d.message); if(d.success) document.getElementById('loadForm').dispatchEvent(new Event('submit')); });
});
document.getElementById('charList').appendChild(div);
}
</script>
</body>
</html>";
        }

        private string GetRegistrationPage()
        {
            return @"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Wonderland - Register</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            color: #fff;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2rem;
            background: linear-gradient(90deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            color: rgba(255, 255, 255, 0.6);
            text-align: center;
            margin-bottom: 30px;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.05);
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        input:focus {
            outline: none;
            border-color: #e94560;
            background: rgba(255, 255, 255, 0.1);
        }
        input::placeholder {
            color: rgba(255, 255, 255, 0.3);
        }
        button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(90deg, #e94560, #ff6b6b);
            color: #fff;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(233, 69, 96, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .message {
            padding: 12px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: center;
            font-size: 0.9rem;
            display: none;
        }
        .message.success {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
            border: 1px solid rgba(46, 213, 115, 0.3);
        }
        .message.error {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
            font-size: 3rem;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='logo'></div>
        <h1>Wonderland</h1>
        <p class='subtitle'>Create your account</p>
        
        <form id='registerForm'>
            <div class='form-group'>
                <label for='username'>Username</label>
                <input type='text' id='username' name='username' placeholder='Enter username' required minlength='3'>
            </div>
            <div class='form-group'>
                <label for='email'>Email</label>
                <input type='email' id='email' name='email' placeholder='Enter email' required>
            </div>
            <div class='form-group'>
                <label for='password'>Password</label>
                <input type='password' id='password' name='password' placeholder='Enter password' required minlength='4'>
            </div>
            <div class='form-group'>
                <label for='confirmPassword'>Confirm Password</label>
                <input type='password' id='confirmPassword' placeholder='Confirm password' required>
            </div>
            <button type='submit'>Register</button>
        </form>
        
        <div id='message' class='message'></div>
    </div>

    <script>
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const messageDiv = document.getElementById('message');
            
            if (password !== confirmPassword) {
                messageDiv.textContent = 'Passwords do not match';
                messageDiv.className = 'message error';
                messageDiv.style.display = 'block';
                return;
            }
            
            const data = {
                username: document.getElementById('username').value,
                email: document.getElementById('email').value,
                password: password
            };
            
            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                messageDiv.textContent = result.message;
                messageDiv.className = 'message ' + (result.success ? 'success' : 'error');
                messageDiv.style.display = 'block';
                
                if (result.success) {
                    document.getElementById('registerForm').reset();
                }
            }
            catch (error) {
                messageDiv.textContent = 'Connection error. Please try again.';
                messageDiv.className = 'message error';
                messageDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>";
        }
    }
}
