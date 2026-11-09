const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json({ limit: "32kb" }));

const { SUPABASE_URL, SUPABASE_ANON_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error("Set SUPABASE_URL and SUPABASE_ANON_KEY in the server environment");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

function userClient(token) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: `Bearer ${token}` } }
  });
}

async function requireUser(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Требуется вход" });

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: "Сессия недействительна" });

  req.user = data.user;
  req.db = userClient(token);
  next();
}

app.get("/health", (_req, res) => {
  res.json({ service: "AIOGRAM", status: "online" });
});

app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string" ||
        typeof username !== "string" || !/^[a-zA-Z0-9_]{3,24}$/.test(username) ||
        password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Укажи email, пароль от 8 символов и логин 3–24 символа (латиница, цифры, _)"
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email: email.trim().toLowerCase(),
      password,
      options: { data: { username } }
    });

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json({
      success: true,
      confirmationRequired: !data.session,
      message: data.session ? "Аккаунт создан" : "Проверь почту для подтверждения",
      token: data.session?.access_token || null,
      user: data.user ? { id: data.user.id, email: data.user.email } : null
    });
  } catch (error) {
    console.error("register:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Укажи email и пароль" });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim().toLowerCase(),
      password
    });
    if (error) return res.status(401).json({ error: "Неверный email или пароль" });

    res.json({
      success: true,
      token: data.session.access_token,
      user: { id: data.user.id, email: data.user.email }
    });
  } catch (error) {
    console.error("login:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.get("/me", requireUser, async (req, res) => {
  const { data, error } = await req.db
    .from("profiles")
    .select("id, username, display_name, created_at")
    .eq("id", req.user.id)
    .maybeSingle();

  if (error) return res.status(400).json({ error: error.message });
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      profile: data
    }
  });
});

app.patch("/me", requireUser, async (req, res) => {
  const { display_name } = req.body || {};
  if (typeof display_name !== "string" || display_name.trim().length < 1 ||
      display_name.trim().length > 40) {
    return res.status(400).json({ error: "Имя должно содержать от 1 до 40 символов" });
  }

  const { data, error } = await req.db
    .from("profiles")
    .update({ display_name: display_name.trim() })
    .eq("id", req.user.id)
    .select("id, username, display_name, created_at")
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true, profile: data });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`AIOGRAM independent API listening on ${PORT}`);
});
