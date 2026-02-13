import express, { Request, Response, NextFunction } from "express";

const app = express();
app.use(express.json());

/**
 * "Fake DB" in memory
 * - Each profile belongs to a userId
 */
type Profile = {
  userId: string;
  fullName: string;
  email: string;
  secretNotes: string;
};

const profiles: Record<string, Profile> = {
  u1: {
    userId: "u1",
    fullName: "Alice Doe",
    email: "alice@example.com",
    secretNotes: "Alice private notes: salary=120k",
  },
  u2: {
    userId: "u2",
    fullName: "Bob Smith",
    email: "bob@example.com",
    secretNotes: "Bob private notes: medical=confidential",
  },
};

/**
 * Super simple "auth"
 * Client sends: Authorization: Bearer u1
 * We treat u1/u2 as the logged-in user id.
 */
type AuthedRequest = Request & { user?: { id: string } };

function auth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Missing Authorization: Bearer <userId>" });
  }
  const userId = header.slice("Bearer ".length).trim();
  if (!profiles[userId]) {
    return res.status(401).json({ error: "Invalid token (use u1 or u2)" });
  }
  req.user = { id: userId };
  next();
}

// Health check
app.get("/", (_req, res) => res.send("IDOR demo server (FIXED) running"));

app.get("/profiles/:userId", auth, (req: AuthedRequest, res: Response) => {
  const { userId } = req.params;
  const myId = req.user!.id;

  if (userId !== myId) {
    return res
      .status(403)
      .json({ error: "Forbidden: cannot access other profiles" });
  }
  const profile = profiles[userId];
  if (!profile) return res.status(404).json({ error: "Not found" });

  return res.json({
    requestedBy: req.user!.id,
    profile,
  });
});

app.get("/me/profile", auth, (req: AuthedRequest, res: Response) => {
  const myId = req.user!.id;
  const profile = profiles[myId];
  if (!profile) return res.status(404).json({ error: "Not found" });

  return res.json({
    requestedBy: req.user!.id,
    profile,
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ FIXED server running on http://localhost:${PORT}`);
  console.log(
    `Try: curl -H "Authorization: Bearer u1" http://localhost:${PORT}/profiles/u2  (should 403)`,
  );
});
