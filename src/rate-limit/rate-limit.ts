import rateLimit, { RateLimitRequestHandler } from "express-rate-limit";
import express, { Request, Response } from "express";

export const loginLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts
  message: {
    error: "Too many login attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const app = express();

app.use(express.json());
type User = {
  id: string;
  email: string;
  password: string;
  role: "user" | "admin";
};

const USERS: User[] = [
  { id: "u1", email: "user@test.com", password: "1234", role: "user" },
];

app.post("/auth/login", loginLimiter, (req: Request, res: Response) => {
  const { email, password } = req.body;

  console.log(
    `[${new Date().toISOString()}] Login attempt for email: ${email}`,
  );
  const user = USERS.find((u) => u.email === email && u.password === password);

  // Fake login logic for demo
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  console.log("Login successful");

  return res.json({ message: "Login successful" });
});

app.listen(4000, () => {
  console.log("Server running on port 4000");
});
