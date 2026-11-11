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
  SUPABASE_ANON_KEY,
  SUPABASE_PUBLISHABLE_KEY,
  CODE_SECRET,
  OWNER_EMAIL
} = process.env;

const AUTH_PUBLIC_KEY = SUPABASE_PUBLISHABLE_KEY || SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !AUTH_PUBLIC_KEY || !CODE_SECRET) {
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
    .select("id, auth_user_id, virtual_number, username, email, stars, is_deleted")
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

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("/register", (req, res) => res.redirect("/"));
app.get("/health", (req, res) => res.json({ status: "online", name: "АИОГРАМ" }));

const emailAuthRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  key: req => "email-auth:" + (req.ip || req.socket.remoteAddress || "unknown")
});

function createAuthClient() {
  return createClient(SUPABASE_URL, AUTH_PUBLIC_KEY, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
  });
}

app.post("/auth/email/request", emailAuthRateLimit, async (req, res) => {
  try {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
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
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(code)) {
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

    if (account.is_deleted) {
      return res.status(403).json({ error: "Этот аккаунт отключён" });
    }

    if (OWNER_EMAIL && verifiedEmail === String(OWNER_EMAIL).trim().toLowerCase()) {
      const { data: currentRole, error: currentRoleError } = await db.from("account_admins")
        .select("role").eq("account_id", account.id).maybeSingle();
      if (currentRoleError) throw currentRoleError;
      if (currentRole?.role !== "owner") {
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


// API переписок АИОГРАМ. Все запросы проверяют участника чата на сервере.
function requireChatIdentity(req, res, next) {
  if (!req.auth.account.auth_user_id) {
    return res.status(403).json({ error: "Для аккаунта не привязана учётная запись Auth" });
  }
  req.userId = req.auth.account.auth_user_id;
  next();
}

const chatRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  key: req => "chat-api:" + (req.auth?.account?.id || req.ip || "unknown")
});

app.get("/api/users/search", requireUser, requireChatIdentity, chatRateLimit, async (req, res) => {
  try {
    const number = typeof req.query.number === "string" ? req.query.number.trim() : "";
    if (!/^\+7\d{8}$/.test(number)) {
      return res.status(400).json({ error: "Укажи полный номер АИОГРАМ, например +712345678" });
    }
    const { data, error } = await db.from("accounts")
      .select("auth_user_id, virtual_number, username")
      .eq("virtual_number", number)
      .eq("is_deleted", false)
      .not("auth_user_id", "is", null)
      .maybeSingle();
    if (error) throw error;
    if (!data || data.auth_user_id === req.userId) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    res.json({ success: true, user: { number: data.virtual_number, username: data.username } });
  } catch (error) {
    console.error("User search error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/api/chats", requireUser, requireChatIdentity, chatRateLimit, async (req, res) => {
  try {
    const { data: memberships, error: membershipError } = await db.from("chat_members")
      .select("chat_id, joined_at").eq("user_id", req.userId);
    if (membershipError) throw membershipError;
    const chatIds = (memberships || []).map(row => row.chat_id);
    if (!chatIds.length) return res.json({ success: true, chats: [] });

    const [{ data: chats, error: chatsError }, { data: members, error: membersError }, { data: messages, error: messagesError }] = await Promise.all([
      db.from("chats").select("id, title, is_group, created_at").in("id", chatIds).order("created_at", { ascending: false }),
      db.from("chat_members").select("chat_id, user_id").in("chat_id", chatIds),
      db.from("messages").select("id, chat_id, sender_id, content, created_at").in("chat_id", chatIds).order("created_at", { ascending: false }).limit(200)
    ]);
    if (chatsError) throw chatsError;
    if (membersError) throw membersError;
    if (messagesError) throw messagesError;

    const userIds = [...new Set((members || []).map(row => row.user_id))];
    const { data: accounts, error: accountsError } = await db.from("accounts")
      .select("auth_user_id, virtual_number, username").in("auth_user_id", userIds);
    if (accountsError) throw accountsError;
    const accountById = new Map((accounts || []).map(row => [row.auth_user_id, row]));
    const latestByChat = new Map();
    for (const message of messages || []) {
      if (!latestByChat.has(message.chat_id)) latestByChat.set(message.chat_id, message);
    }
    const membersByChat = new Map();
    for (const member of members || []) {
      if (!membersByChat.has(member.chat_id)) membersByChat.set(member.chat_id, []);
      const account = accountById.get(member.user_id);
      if (account) membersByChat.get(member.chat_id).push({
        number: account.virtual_number, username: account.username, is_self: member.user_id === req.userId
      });
    }
    res.json({
      success: true,
      chats: (chats || []).map(chat => ({
        id: chat.id, title: chat.title, is_group: !!chat.is_group,
        members: membersByChat.get(chat.id) || [],
        last_message: latestByChat.get(chat.id) || null
      }))
    });
  } catch (error) {
    console.error("Chat list error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/chats/direct", requireUser, requireChatIdentity, chatRateLimit, async (req, res) => {
  try {
    const number = typeof req.body?.number === "string" ? req.body.number.trim() : "";
    if (!/^\+7\d{8}$/.test(number)) return res.status(400).json({ error: "Неверный номер пользователя" });
    const { data: target, error: targetError } = await db.from("accounts")
      .select("id, auth_user_id, virtual_number, username")
      .eq("virtual_number", number).eq("is_deleted", false)
      .not("auth_user_id", "is", null).maybeSingle();
    if (targetError) throw targetError;
    if (!target || target.auth_user_id === req.userId) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const { data: mine, error: mineError } = await db.from("chat_members")
      .select("chat_id").eq("user_id", req.userId);
    if (mineError) throw mineError;
    const mineIds = (mine || []).map(row => row.chat_id);
    if (mineIds.length) {
      const { data: shared, error: sharedError } = await db.from("chat_members")
        .select("chat_id").eq("user_id", target.auth_user_id).in("chat_id", mineIds);
      if (sharedError) throw sharedError;
      const candidateIds = (shared || []).map(row => row.chat_id);
      if (candidateIds.length) {
        const { data: candidateChats, error: candidateError } = await db.from("chats")
          .select("id, is_group").in("id", candidateIds).eq("is_group", false);
        if (candidateError) throw candidateError;
        if (candidateChats?.length) {
          const existingId = candidateChats[0].id;
          return res.json({ success: true, chat_id: existingId, existing: true });
        }
      }
    }

    const { data: chat, error: createError } = await db.from("chats")
      .insert({ is_group: false, created_by: req.userId })
      .select("id").single();
    if (createError) throw createError;
    const { error: membersError } = await db.from("chat_members").insert([
      { chat_id: chat.id, user_id: req.userId },
      { chat_id: chat.id, user_id: target.auth_user_id }
    ]);
    if (membersError) {
      await db.from("chats").delete().eq("id", chat.id);
      throw membersError;
    }
    res.status(201).json({ success: true, chat_id: chat.id, existing: false });
  } catch (error) {
    console.error("Create direct chat error:", error);
    res.status(500).json({ error: "Не удалось создать чат" });
  }
});

app.get("/api/chats/:id/messages", requireUser, requireChatIdentity, chatRateLimit, async (req, res) => {
  try {
    const { data: membership, error: membershipError } = await db.from("chat_members")
      .select("chat_id").eq("chat_id", req.params.id).eq("user_id", req.userId).maybeSingle();
    if (membershipError) throw membershipError;
    if (!membership) return res.status(404).json({ error: "Чат не найден" });
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
    const { data, error } = await db.from("messages")
      .select("id, chat_id, sender_id, content, created_at")
      .eq("chat_id", req.params.id).order("created_at", { ascending: false }).limit(limit);
    if (error) throw error;
    res.json({ success: true, messages: (data || []).reverse().map(message => ({
      id: message.id, sender_id: message.sender_id, content: message.content,
      created_at: message.created_at, is_self: message.sender_id === req.userId
    })) });
  } catch (error) {
    console.error("Message list error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/chats/:id/messages", requireUser, requireChatIdentity, chatRateLimit, async (req, res) => {
  try {
    const content = typeof req.body?.content === "string" ? req.body.content.trim() : "";
    if (!content || content.length > 4000) {
      return res.status(400).json({ error: "Сообщение должно содержать от 1 до 4000 символов" });
    }
    const { data: membership, error: membershipError } = await db.from("chat_members")
      .select("chat_id").eq("chat_id", req.params.id).eq("user_id", req.userId).maybeSingle();
    if (membershipError) throw membershipError;
    if (!membership) return res.status(404).json({ error: "Чат не найден" });

    const { data: message, error } = await db.from("messages").insert({
      chat_id: req.params.id, sender_id: req.userId, content
    }).select("id, sender_id, content, created_at").single();
    if (error) throw error;
    res.status(201).json({ success: true, message: {
      id: message.id, sender_id: message.sender_id, content: message.content,
      created_at: message.created_at, is_self: true
    }});
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ error: "Не удалось отправить сообщение" });
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
