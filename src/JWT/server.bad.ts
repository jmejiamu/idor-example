import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

const USERS = [
  { id: "u1", email: "user@test.com", password: "1234", role: "user" },
];

const SECRET = "secret123";

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = USERS.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET);

  res.json({ token });
});

app.get("/admin", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET) as any;

    if (decoded.role === "admin") {
      return res.json({ secret: "Admin data exposed 🚨" });
    }

    res.status(403).json({ error: "Not admin" });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.listen(3000, () => {
  console.log("Bad JWT server running on http://localhost:3000");
  console.log(
    '[*] Run test: curl -X POST http://localhost:3000/login -H \'Content-Type: application/json\' -d \'{"email":"user@test.com","password":"1234"}\'',
  );
});
