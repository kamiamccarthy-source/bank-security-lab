
const express = require("express");
const crypto = require("crypto");
const { promisify } = require("util");

const app = express();
const scrypt = promisify(crypto.scrypt);

app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;

if (!SECRET || SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters");
}

// Temporary in-memory laboratory storage
const users = new Map();
const accounts = new Map();
const loginAttempts = new Map();

function createToken(userId) {
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + 900
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(token) {
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest();

  let received;
  try {
    received = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(received, expected)
  ) return null;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!data.sub || data.exp <= Date.now() / 1000) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64);

  return salt.toString("hex") + ":" + hash.toString("hex");
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");

  const hash = await scrypt(
    password,
    Buffer.from(saltHex, "hex"),
    64
  );

  const expected = Buffer.from(hashHex, "hex");

  return crypto.timingSafeEqual(hash, expected);
}

// Authentication middleware
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer (.+)$/);

  if (!match) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const session = verifyToken(match[1]);

  if (!session || !users.has(session.sub)) {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }

  req.userId = session.sub;
  next();
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "online", lab: "Bank Security Lab" });
});

// Customer registration
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      name.trim().length < 2 ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Invalid registration details"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if ([...users.values()].some(
      u => u.email === normalizedEmail
    )) {
      return res.status(409).json({
        error: "Account already registered"
      });
    }

    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    users.set(id, {
      id,
      name: name.trim(),
      email: normalizedEmail,
      passwordHash
    });

    const accountId = crypto.randomUUID();

    accounts.set(accountId, {
      id: accountId,
      userId: id,
      balance: 10000,
      currency: "NGN"
    });

    res.status(201).json({
      message: "Test customer created",
      customerId: id,
      accountId
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Customer login
app.post("/api/login", async (req, res) => {
  try {
    const ip = req.ip;
    const now = Date.now();

    const attempts = loginAttempts.get(ip) || [];
    const recent = attempts.filter(
      time => now - time < 60000
    );

    if (recent.length >= 5) {
      return res.status(429).json({
        error: "Too many login attempts. Try again later."
      });
    }

    recent.push(now);
    loginAttempts.set(ip, recent);

    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Invalid login details"
      });
    }

    const user = [...users.values()].find(
      u => u.email === email.trim().toLowerCase()
    );

    const valid = user
      ? await verifyPassword(password, user.passwordHash)
      : false;

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    loginAttempts.delete(ip);

    res.json({
      message: "Login successful",
      token: createToken(user.id),
      expiresIn: 900
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Current customer
app.get("/api/me", authenticate, (req, res) => {
  const user = users.get(req.userId);

  res.json({
    id: user.id,
    name: user.name,
    email: user.email
  });
});

// Protected account information
app.get("/api/accounts/:id", authenticate, (req, res) => {
  const account = accounts.get(req.params.id);

  if (!account || account.userId !== req.userId) {
    return res.status(403).json({
      error: "Access denied: account ownership required"
    });
  }

  res.json({
    accountId: account.id,
    balance: account.balance,
    currency: account.currency
  });
});

// Start server
app.listen(PORT, () => {
  console.log("Bank Security Lab running on port " + PORT);
});
