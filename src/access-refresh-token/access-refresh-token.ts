import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import jwt, { JwtPayload } from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

// standard JWT claims we use throughout the demo
const ISSUER = process.env.ISSUER as string;
const AUDIENCE = process.env.AUDIENCE as string;

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);

type User = {
  id: string;
  email: string;
  password: string;
  role: "user" | "admin";
};

const USERS: User[] = [
  { id: "u1", email: "user@test.com", password: "1234", role: "user" },
];

const refreshTokensByUserId = new Map<string, Set<string>>(); // demo store

function signAccessToken(user: User) {
  return jwt.sign(
    { sub: user.id, iss: ISSUER, aud: AUDIENCE, algorithm: "HS256" },
    ACCESS_TOKEN_SECRET,
    {
      expiresIn: "1m",
    },
  );
}

function signRefreshToken(user: User) {
  // refresh tokens are only ever consumed by the auth server, so
  // audience isn't particularly meaningful here. we still add the
  // issuer claim for consistency and to make verification stricter.
  return jwt.sign(
    { sub: user.id, typ: "refresh", iss: ISSUER },
    REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" },
  );
}

function saveRefreshToken(userId: string, token: string) {
  const set = refreshTokensByUserId.get(userId) ?? new Set<string>();
  set.add(token);
  refreshTokensByUserId.set(userId, set);
}

function revokeRefreshToken(userId: string, token: string) {
  const set = refreshTokensByUserId.get(userId);
  if (!set) return;
  set.delete(token);
  if (set.size === 0) refreshTokensByUserId.delete(userId);
}

function isRefreshTokenActive(userId: string, token: string) {
  const set = refreshTokensByUserId.get(userId);
  return !!set?.has(token);
}

type AuthedRequest = Request & {
  user?: { id: string; role: "user" | "admin" };
};
// Access-token middleware
function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing access token" });

  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET, {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
    }) as JwtPayload;

    req.user = {
      id: String(payload.sub),
      role: USERS.find((u) => u.id === payload.sub)?.role ?? "user",
    };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }
}

// LOGIN
app.post("/auth/login", (req: Request, res: Response) => {
  const { email, password } = req.body as { email: string; password: string };

  const user = USERS.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  saveRefreshToken(user.id, refreshToken);

  // Mobile-friendly: return both in JSON
  return res.json({ accessToken, refreshToken });
});

// REFRESH (with rotation)
app.post("/auth/refresh", (req: Request, res: Response) => {
  console.log("[*] Refresh token request received");
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken)
    return res.status(401).json({ error: "Missing refresh token" });

  let payload: JwtPayload;
  try {
    payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, {
      issuer: ISSUER /* audience optional */,
    }) as JwtPayload;
  } catch {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }

  const userId = String(payload.sub);

  if (!isRefreshTokenActive(userId, refreshToken)) {
    return res.status(401).json({ error: "Refresh token revoked" });
  }

  const user = USERS.find((u) => u.id === userId);
  if (!user) return res.status(401).json({ error: "User not found" });

  // rotate refresh token
  revokeRefreshToken(userId, refreshToken);
  const newAccessToken = signAccessToken(user);
  const newRefreshToken = signRefreshToken(user);
  saveRefreshToken(userId, newRefreshToken);

  console.log("[*] Refresh token rotated");

  return res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
});

// LOGOUT (revoke)
app.post("/auth/logout", (req: Request, res: Response) => {
  console.log("[*] Logout request received");
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken) return res.json({ ok: true });

  try {
    const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, {
      issuer: ISSUER,
    }) as JwtPayload;
    revokeRefreshToken(String(payload.sub), refreshToken);
  } catch {
    // ignore
  }

  return res.json({ ok: true });
});

// Protected route
app.get("/me", requireAuth, (req: AuthedRequest, res: Response) => {
  console.log("[*] Authenticated user");
  return res.json({
    message: "Protected route success ✅",
    user: req.user,
  });
});

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => console.log(`API running on http://localhost:${port}`));
