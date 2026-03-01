# IDOR Example Server

> **Note:** This repository is designed as a demo for common security pitfalls and fixes. It is not intended for production use.

## 📁 Project Structure

```
src/
  ├─ access-refresh-token/
  ├─ idor-example/
  ├─ JWT/
  ├─ password-hashing/
  ├─ rate-limit/
  └─ validation-auth/
```

Each folder contains a small Express/TypeScript server demonstrating a particular concept:

- **idor-example** – insecure direct object reference example (bad vs fixed)
- **JWT** – JWT auth flows with vulnerable and corrected implementations
- **access-refresh-token** – Access token and refresh token management
- **rate-limit** – Example of using `express-rate-limit` to defend against brute-force
- **password-hashing** – Hashing passwords with `bcrypt`
- **validation-auth** – Validating incoming requests with `zod` and Express

## 🚀 Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```
2. Choose a demo to run and start in development mode. For example:
   ```bash
   npm run dev:bad            # IDOR vulnerable server
   npm run dev:fixed          # IDOR fixed server
   npm run dev:jwt-bad        # JWT insecure version
   npm run dev:jwt-fixed      # JWT secure version
   npm run dev:access-refresh-tokens
   npm run dev:rate-limit
   npm run dev:password-hashing
   npm run dev:validation
   ```
3. Open your browser or use curl/postman to hit `http://localhost:3000` (or the port defined in `.env`).

> ⚠️ The demo servers listen on port 3000 by default. You can override by creating a `.env` file with `PORT=your_port`.

## 🛠️ Scripts

- `npm start` – run the compiled JavaScript from `dist/` (when built)
- `npm run dev:*` – start various handlers with `nodemon` and `ts-node`

## 💡 Purpose

This repository is aimed at developers learning about web security. Each example pairs a vulnerable implementation with a fixed version so you can compare and understand the issue.

Feel free to copy snippets for your own demos or workshops!

> **Bonus:** A companion React Native application demonstrating secure practices can be found here:
> https://github.com/jmejiamu/securing-rn-app

---

_Created for demonstration only._
