const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));
app.use("/panel", express.static(path.join(__dirname, "public"), { index: "admin.html" }));

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  CODE_SECRET,
  OWNER_EMAIL
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !CODE_SECRET) {
  throw new Error("Не заданы секретные настройки сервера");
}

const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

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

const hash = value => crypto.createHmac("sha256", CODE_SECRET).update(value).digest("hex");
const randomNumber = () => "+7" + String(crypto.randomInt(10000000, 100000000));

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
    .select("id, virtual_number, username, email, stars, is_deleted")
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

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));
app.get("/health", (req, res) => res.json({ status: "online", name: "АИОГРАМ" }));

const emailAuthRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  key: req => "email-auth:" + (req.ip || req.socket.remoteAddress || "unknown")
});

function createAuthClient() {
  return createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
  });
}

app.post("/auth/email/request", emailAuthRateLimit, async (req, res) => {
  try {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    if (email.length > 254 || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Введи корректный email" });
    }
    const authClient = createAuthClient();
    const { error } = await authClient.auth.signInWithOtp({
      email,
      options: { shouldCreateUser: true }
    });
    if (error) {
      console.error("Email OTP request error:", error.message);
      return res.status(400).json({ error: "Не удалось отправить код. Проверь email и попробуй позже." });
    }
    res.json({ success: true, message: "Код отправлен на почту" });
  } catch (error) {
    console.error("Email OTP request failed:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/auth/email/verify", emailAuthRateLimit, async (req, res) => {
  try {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const code = typeof req.body?.code === "string" ? req.body.code.trim() : "";
    if (email.length > 254 || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) || !/^\\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Проверь email и шестизначный код" });
    }

    const authClient = createAuthClient();
    const { data: verified, error: verifyError } = await authClient.auth.verifyOtp({
      email,
      token: code,
      type: "email"
    });
    if (verifyError || !verified?.user?.id || !verified.user.email) {
      return res.status(401).json({ error: "Неверный или просроченный код" });
    }

    const authUserId = verified.user.id;
    const verifiedEmail = verified.user.email.toLowerCase();
    let { data: account, error: lookupError } = await db.from("accounts")
      .select("id, virtual_number, username, email, stars, is_deleted")
      .eq("auth_user_id", authUserId).maybeSingle();
    if (lookupError) throw lookupError;

    if (!account) {
      for (let attempt = 0; attempt < 5; attempt++) {
        const number = randomNumber();
        const { data: created, error: createError } = await db.from("accounts").insert({
          auth_user_id: authUserId,
          email: verifiedEmail,
          virtual_number: number,
          username: verifiedEmail.split("@")[0].slice(0, 32) || "Новый пользователь"
        }).select("id, virtual_number, username, email, stars, is_deleted").single();

        if (!createError) {
          account = created;
          break;
        }
        if (createError.code === "23505") {
          const existing = await db.from("accounts").select("id, virtual_number, username, email, stars, is_deleted")
            .eq("auth_user_id", authUserId).maybeSingle();
          if (existing.error) throw existing.error;
          if (existing.data) { account = existing.data; break; }
          continue;
        }
        throw createError;
      }
      if (!account) throw new Error("Не удалось создать уникальный номер аккаунта");

    }

    if (OWNER_EMAIL && verifiedEmail === String(OWNER_EMAIL).trim().toLowerCase()) {
      const { error: roleError } = await db.from("account_admins")
        .upsert({ account_id: account.id, role: "owner" });
      if (roleError) throw roleError;
      await db.from("admin_logs").insert({
        actor_account_id: account.id,
        action: "owner_bootstrapped",
        target_account_id: account.id,
        metadata: { source: "verified_email_otp" }
      });
    }

    if (account.is_deleted) {
      return res.status(403).json({ error: "Этот аккаунт отключён" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const { error: sessionError } = await db.from("sessions").insert({
      account_id: account.id,
      token_hash: hash(token),
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
    if (sessionError) throw sessionError;

    res.json({ success: true, token, account: {
      number: account.virtual_number, username: account.username, email: account.email
    }});
  } catch (error) {
    console.error("Email login error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/auth/me", requireUser, (req, res) => {
  const { account } = req.auth;
  res.json({ success: true, account: {
    number: account.virtual_number, username: account.username, email: account.email, stars: account.stars
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
      .select("id, virtual_number, username, email, stars, is_deleted, created_at")
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
