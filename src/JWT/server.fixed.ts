import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import "dotenv/config";

const app = express();
app.use(express.json());
app.use(cors());

const USERS = [
  { id: "u1", email: "user@test.com", password: "1234", role: "user" },
  { id: "a1", email: "admin@test.com", password: "admin1234", role: "admin" },
];

const JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET) throw new Error("Missing JWT_SECRET env var");

const ISSUER = process.env.ISSUER;
const AUDIENCE = process.env.AUDIENCE;

type JwtPayload = {
  sub: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
};

function signAccessToken(userId: string) {
  return jwt.sign({ sub: userId, iss: ISSUER, aud: AUDIENCE }, JWT_SECRET, {
    expiresIn: "15m",
    algorithm: "HS256",
  });
}

function auth(req: any, res: any, next: any) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing Bearer token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
    }) as JwtPayload;

    req.userId = decoded.sub;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const user = USERS.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const accessToken = signAccessToken(user.id);
  res.json({ token: accessToken });
});

// ADMIN — authorization based on server-side user role (not token role)
app.get("/admin", auth, (req: any, res) => {
  const user = USERS.find((u) => u.id === req.userId);
  if (!user) return res.status(401).json({ error: "User not found" });

  if (user.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  return res.json({ secret: "Admin data protected ✅" });
});

app.listen(3000, () =>
  console.log("JWT server running on http://localhost:3000"),
);
