const express = require("express");
const TelegramBot = require("node-telegram-bot-api");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));
app.use("/panel", express.static(path.join(__dirname, "public"), { index: "admin.html" }));

const {
  BOT_TOKEN,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  CODE_SECRET,
  OWNER_TELEGRAM_ID
} = process.env;

if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !CODE_SECRET) {
  throw new Error("Не заданы секретные настройки сервера");
}

const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

const rateBuckets = new Map();
function rateLimit({ windowMs, max, key }) {
  return (req, res, next) => {
    const now = Date.now();
    const bucketKey = key(req);
    let bucket = rateBuckets.get(bucketKey);
    if (!bucket || now - bucket.startedAt >= windowMs) {
      bucket = { startedAt: now, count: 0 };
      rateBuckets.set(bucketKey, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((windowMs - (now - bucket.startedAt)) / 1000));
      res.set("Retry-After", String(retryAfter));
      return res.status(429).json({ error: "Слишком много запросов. Попробуй позже." });
    }
    if (rateBuckets.size > 5000) {
      for (const [storedKey, value] of rateBuckets) {
        if (now - value.startedAt >= windowMs) rateBuckets.delete(storedKey);
      }
    }
    next();
  };
}

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  key: req => "auth:" + (req.ip || req.socket.remoteAddress || "unknown")
});

const hash = value => crypto.createHmac("sha256", CODE_SECRET).update(value).digest("hex");
const randomCode = () => String(crypto.randomInt(100000, 1000000));
const randomNumber = () => "+7" + String(crypto.randomInt(10000000, 100000000));
const safeHashEqual = (left, right) => {
  if (typeof left !== "string" || typeof right !== "string" ||
      !/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
};

async function createAccount(msg) {
  const telegramId = String(msg.from.id);
  const { data: existing, error: lookupError } = await db
    .from("accounts").select("id, virtual_number")
    .eq("telegram_user_id", telegramId).maybeSingle();
  if (lookupError) throw lookupError;
  if (existing) return { existing: true, ...existing };

  for (let i = 0; i < 5; i++) {
    const number = randomNumber();
    const code = randomCode();
    const { data, error } = await db.from("accounts").insert({
      virtual_number: number,
      telegram_user_id: telegramId,
      login_code_hash: hash(code),
      code_expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      failed_login_attempts: 0,
      username: msg.from.username || "Новый пользователь"
    }).select("id, virtual_number").single();

    if (!error) {
      if (OWNER_TELEGRAM_ID && telegramId === String(OWNER_TELEGRAM_ID)) {
        const { error: roleError } = await db.from("account_admins")
          .upsert({ account_id: data.id, role: "owner" });
        if (roleError) throw roleError;
        await db.from("admin_logs").insert({
          actor_account_id: data.id,
          action: "owner_bootstrapped",
          target_account_id: data.id,
          metadata: { source: "verified_telegram_bot" }
        });
      }
      return { ...data, code };
    }
    if (error.code !== "23505") throw error;
  }
  throw new Error("Не удалось создать уникальный номер");
}

async function getSession(token) {
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const { data: session, error } = await db.from("sessions")
    .select("id, account_id, expires_at")
    .eq("token_hash", hash(token))
    .is("revoked_at", null)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (error || !session) return null;

  const { data: account, error: accountError } = await db.from("accounts")
    .select("id, virtual_number, username, stars, is_deleted")
    .eq("id", session.account_id)
    .eq("is_deleted", false)
    .maybeSingle();
  if (accountError || !account) return null;
  return { session, account };
}

async function requireUser(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    const auth = await getSession(token);
    if (!auth) return res.status(401).json({ error: "Нет действующей авторизации" });
    req.auth = auth;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const { data: admin, error } = await db.from("account_admins")
      .select("role").eq("account_id", req.auth.account.id).maybeSingle();
    if (error) throw error;
    if (!admin) return res.status(403).json({ error: "Доступ только для администраторов" });
    req.auth.role = admin.role;
    next();
  } catch (error) {
    console.error("Admin authorization error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
}

bot.onText(/^\/start$/, msg => {
  bot.sendMessage(msg.chat.id,
    "Добро пожаловать в АИОГРАМ!\n\nДля создания аккаунта отправь /new");
});

bot.onText(/^\/new$/, async msg => {
  try {
    const account = await createAccount(msg);
    if (account.existing) {
      return bot.sendMessage(msg.chat.id,
        "У тебя уже есть аккаунт АИОГРАМ. Номер: " + account.virtual_number);
    }
    await bot.sendMessage(msg.chat.id,
      "ТВОЙ НОВЫЙ АИОГРАМ АККАУНТ\n\n" +
      "Номер: " + account.virtual_number + "\n" +
      "Код входа: " + account.code + "\n\n" +
      "Код действует 10 минут и используется один раз. Не пересылай его другим.");
  } catch (error) {
    console.error("Account creation error:", error);
    bot.sendMessage(msg.chat.id, "Ошибка создания аккаунта. Попробуй позже.");
  }
});

app.get("/", (req, res) => res.send("АИОГРАМ работает"));
app.get("/health", (req, res) => res.json({ status: "online", name: "АИОГРАМ" }));

app.post("/auth/verify", authRateLimit, async (req, res) => {
  try {
    const { number, code } = req.body || {};
    if (typeof number !== "string" || typeof code !== "string" ||
        !/^\+7\d{8}$/.test(number) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Неверные данные" });
    }

    const { data: account, error } = await db.from("accounts")
      .select("id, virtual_number, username, login_code_hash, code_expires_at, failed_login_attempts")
      .eq("virtual_number", number).eq("is_deleted", false).maybeSingle();

    if (error || !account || !account.login_code_hash ||
        !account.code_expires_at || new Date(account.code_expires_at).getTime() <= Date.now() ||
        account.failed_login_attempts >= 5) {
      return res.status(401).json({ error: "Неверный номер, код или срок действия кода истёк" });
    }

    if (!safeHashEqual(hash(code), account.login_code_hash)) {
      await db.from("accounts")
        .update({ failed_login_attempts: account.failed_login_attempts + 1 })
        .eq("id", account.id)
        .eq("login_code_hash", account.login_code_hash);
      return res.status(401).json({ error: "Неверный номер или код" });
    }

    const { data: consumed, error: consumeError } = await db.from("accounts")
      .update({ login_code_hash: null, code_expires_at: null })
      .eq("id", account.id)
      .eq("login_code_hash", account.login_code_hash)
      .gt("code_expires_at", new Date().toISOString())
      .lt("failed_login_attempts", 5)
      .select("id").maybeSingle();

    if (consumeError) throw consumeError;
    if (!consumed) return res.status(401).json({ error: "Код уже использован или истёк" });

    const token = crypto.randomBytes(32).toString("hex");
    const { error: sessionError } = await db.from("sessions").insert({
      account_id: account.id,
      token_hash: hash(token),
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
    if (sessionError) throw sessionError;

    res.json({ success: true, token, account: {
      number: account.virtual_number, username: account.username
    }});
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/auth/me", requireUser, (req, res) => {
  const { account } = req.auth;
  res.json({ success: true, account: {
    number: account.virtual_number, username: account.username, stars: account.stars
  }});
});

app.post("/auth/logout", requireUser, async (req, res) => {
  try {
    const { error } = await db.from("sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", req.auth.session.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Админ API: сведения об аккаунтах и управлении доступом.
// Содержимое личных переписок этим API не раскрывается.
app.get("/admin/me", requireUser, requireAdmin, (req, res) => {
  res.json({ success: true, role: req.auth.role, account: {
    number: req.auth.account.virtual_number, username: req.auth.account.username
  }});
});

app.get("/admin/overview", requireUser, requireAdmin, async (req, res) => {
  try {
    const [accounts, sessions] = await Promise.all([
      db.from("accounts").select("id", { count: "exact", head: true }).eq("is_deleted", false),
      db.from("sessions").select("id", { count: "exact", head: true })
        .is("revoked_at", null).gt("expires_at", new Date().toISOString())
    ]);
    if (accounts.error) throw accounts.error;
    if (sessions.error) throw sessions.error;
    res.json({ success: true, accounts: accounts.count || 0, active_sessions: sessions.count || 0 });
  } catch (error) {
    console.error("Admin overview error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/admin/accounts", requireUser, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 50);
    const { data, error } = await db.from("accounts")
      .select("id, virtual_number, username, stars, is_deleted, created_at")
      .order("created_at", { ascending: false }).limit(limit);
    if (error) throw error;
    res.json({ success: true, accounts: data });
  } catch (error) {
    console.error("Admin accounts error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/admin/accounts/:id/disable", requireUser, requireAdmin, async (req, res) => {
  try {
    if (req.auth.role === "moderator") {
      return res.status(403).json({ error: "Недостаточно прав" });
    }
    const targetId = req.params.id;
    const { data: targetRole, error: roleError } = await db.from("account_admins")
      .select("role").eq("account_id", targetId).maybeSingle();
    if (roleError) throw roleError;
    if (targetRole?.role === "owner") {
      return res.status(403).json({ error: "Нельзя отключить владельца" });
    }
    const { error } = await db.from("accounts")
      .update({ is_deleted: true }).eq("id", targetId).eq("is_deleted", false);
    if (error) throw error;
    await db.from("sessions").update({ revoked_at: new Date().toISOString() })
      .eq("account_id", targetId).is("revoked_at", null);
    await db.from("admin_logs").insert({
      actor_account_id: req.auth.account.id,
      action: "account_disabled",
      target_account_id: targetId,
      metadata: { role: req.auth.role }
    });
    res.json({ success: true });
  } catch (error) {
    console.error("Admin disable error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("АИОГРАМ server started on port " + PORT));
