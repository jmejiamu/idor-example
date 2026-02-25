import express from "express";
import bcrypt from "bcrypt";
const app = express();

app.use(express.json());

const SALT_ROUNDS = 12;

type User = {
  id: string;
  email: string;
  password: string;
};

const USERS: User[] = [];

app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const exists = USERS.find((u) => u.email === email);
  if (exists) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, SALT_ROUNDS);

  USERS.push({ id: Date.now().toString(), email, password: hashed });

  console.log("[*] - Register User", USERS);

  return res.status(201).json({ message: "User registered successfully" });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const user = USERS.find((u) => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

  console.log("[*] - Login User", user);

  return res.json({ message: "Login successful" });
});

app.listen(4000, () => {
  console.log("Server running on port 4000");
});
