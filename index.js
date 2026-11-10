
const express = require("express");
const TelegramBot = require("node-telegram-bot-api");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));

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
const safeHashEqual = (left, right) => {
  if (typeof left !== "string" || typeof right !== "string" ||
      !/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
};

const {
  BOT_TOKEN,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  CODE_SECRET
} = process.env;

if (!BOT_TOKEN || !SUPABASE_URL ||
    !SUPABASE_SERVICE_ROLE_KEY || !CODE_SECRET) {
  throw new Error("Не заданы секретные настройки сервера");
}

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

const hash = value =>
  crypto.createHmac("sha256", CODE_SECRET)
    .update(value).digest("hex");

const randomCode = () =>
  String(crypto.randomInt(100000, 1000000));

const randomNumber = () =>
  "+7" + String(crypto.randomInt(10000000, 100000000));

async function createAccount() {
  for (let i = 0; i < 5; i++) {
    const number = randomNumber();
    const code = randomCode();

    const { data, error } = await db
      .from("accounts")
      .insert({
        virtual_number: number,
        login_code_hash: hash(code),
        username: "Новый пользователь"
      })
      .select("id, virtual_number")
      .single();

    if (!error) {
      return { ...data, code };
    }

    if (error.code !== "23505") {
      throw error;
    }
  }

  throw new Error("Не удалось создать уникальный номер");
}

bot.onText(/^\/start$/, async msg => {
  bot.sendMessage(
    msg.chat.id,
    "Добро пожаловать в AIO GRAM!\n\n" +
    "Для создания нового аккаунта отправь /new"
  );
});

bot.onText(/^\/new$/, async msg => {
  try {
    const account = await createAccount();

    await bot.sendMessage(
      msg.chat.id,
      "ТВОЙ НОВЫЙ AIO GRAM АККАУНТ\n\n" +
      "Номер: " + account.virtual_number + "\n" +
      "Код входа: " + account.code + "\n\n" +
      "Сохрани эти данные. Код одноразовый."
    );
  } catch (error) {
    console.error("Account creation error:", error);
    bot.sendMessage(msg.chat.id, "Ошибка создания аккаунта. Попробуй позже.");
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "AIO GRAM server online" });
});

app.post("/auth/verify", authRateLimit, async (req, res) => {
  try {
    const { number, code } = req.body || {};

    if (
      typeof number !== "string" ||
      typeof code !== "string" ||
      !/^\+7\d{8}$/.test(number) ||
      !/^\d{6}$/.test(code)
    ) {
      return res.status(400).json({ error: "Неверные данные" });
    }

    const { data: account, error } = await db
      .from("accounts")
      .select("id, virtual_number, username, login_code_hash")
      .eq("virtual_number", number)
      .eq("is_deleted", false)
      .maybeSingle();

    if (error || !account || !account.login_code_hash ||
        !safeHashEqual(hash(code), account.login_code_hash)) {
      return res.status(401).json({ error: "Неверный номер или код" });
    }

    const token = crypto.randomBytes(32).toString("hex");

    const { error: updateError } = await db
      .from("accounts")
      .update({ login_code_hash: null })
      .eq("id", account.id)
      .eq("login_code_hash", account.login_code_hash);

    if (updateError) {
      throw updateError;
    }

    const { error: sessionError } = await db
      .from("sessions")
      .insert({
        account_id: account.id,
        token_hash: hash(token),
        expires_at: new Date(
          Date.now() + 30 * 24 * 60 * 60 * 1000
        ).toISOString()
      });

    if (sessionError) {
      throw sessionError;
    }

    res.json({
      success: true,
      token,
      account: {
        number: account.virtual_number,
        username: account.username
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/auth/logout", async (req, res) => {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(401).json({ error: "Нет авторизации" });
    }
    const { error } = await db.from("sessions").delete().eq("token_hash", hash(token));
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.get("/auth/me", async (req, res) => {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer /, "");

    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(401).json({ error: "Нет авторизации" });
    }

    const { data: session, error } = await db
      .from("sessions")
      .select("account_id, expires_at")
      .eq("token_hash", hash(token))
      .gt("expires_at", new Date().toISOString())
      .maybeSingle();

    if (error || !session) {
      return res.status(401).json({ error: "Сессия истекла" });
    }

    const { data: account } = await db
      .from("accounts")
      .select("virtual_number, username, stars")
      .eq("id", session.account_id)
      .eq("is_deleted", false)
      .maybeSingle();

    if (!account) {
      return res.status(401).json({ error: "Аккаунт недоступен" });
    }

    res.json({ success: true, account });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("AIO GRAM server started on port " + PORT);
});
