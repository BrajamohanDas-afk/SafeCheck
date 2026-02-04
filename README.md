# SafeCheck

A browser-based, zero-install file safety checker. Drop a file, get a verdict — Safe, Suspicious, or Dangerous. No account needed, no downloads required.

SafeCheck does not just scan files. It **interprets** the results. When VirusTotal flags something as `HackTool` or `Crack`, SafeCheck tells you whether that is a normal, expected flag or an actual threat — in plain English.

![SafeCheck Banner](https://i.imgur.com/placeholder.png)

---

## What It Does

| Feature | How It Works |
|---|---|
| **Source URL Checker** | Paste the URL you downloaded from. Instantly checks against a database of verified legitimate and known fake sites. |
| **VirusTotal Scan** | Upload a file (under 32MB). SafeCheck scans it through 70+ antivirus engines and interprets the result using a weighted scoring engine — not raw flag counts. |
| **SHA-256 Hash Verification** | Paste a known-good hash. The tool computes the hash of your file locally in the browser — nothing is uploaded for this step. Match or mismatch, instant answer. |
| **Torrent Metadata Parser** | Drop a `.torrent` file. See the full file list, sizes, and folder structure before you download anything. Advisory anomaly flags highlight anything unusual. |

---

## Tech Stack

- **React** + **TypeScript**
- **Vite** — build and dev server
- **Tailwind CSS** — styling
- **shadcn/ui** — component library
- **Web Crypto API** (`crypto.subtle`) — local SHA-256 hashing, runs entirely in your browser
- **VirusTotal API v3** — file scanning backend (via a server-side proxy to keep the API key hidden)

---

## Getting Started Locally

Make sure you have **Node.js** (18+) and **npm** installed.

```bash
# 1. Clone the repo
git clone https://github.com/BrajamohanDas-afk/SafeCheck.git
cd SafeCheck

# 2. Install dependencies
npm install

# 3. Set up your environment variable
# Create a .env file in the root with your VirusTotal API key:
# VIRUSTOTAL_API_KEY=your_key_here

# 4. Start the dev server
npm run dev
```

The app will be running at `http://localhost:5173`.

For local development with serverless functions:
```bash
# Install Vercel CLI
npm i -g vercel

# In another terminal, start the Vercel dev server (runs /api routes)
vercel dev
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Yes | Your VirusTotal API key (server-side only, never exposed to browser). Get a free one at [virustotal.com](https://www.virustotal.com/gui/join-us). Free tier gives 500 file scans/day. |

> **Note:** The API key is kept on the server and proxied through Vercel Serverless Functions (`/api/scan` and `/api/check-hash`). The client never sees it.

---

## Project Structure

```
SafeCheck/
├── public/                 # Static files (favicon, etc.)
├── src/
│   ├── components/         # React components (UI blocks)
│   ├── lib/                # Utility functions (hashing, scoring logic, site DB)
│   ├── pages/              # Page-level components
│   ├── App.tsx             # Root component
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles (Tailwind directives)
├── .env                    # Environment variables (gitignored)
├── package.json            # Dependencies and scripts
├── tailwind.config.ts      # Tailwind configuration
├── tsconfig.json           # TypeScript root config
├── vite.config.ts          # Vite configuration
└── README.md               # This file
```

---

## Available Scripts

| Command | What It Does |
|---|---|
| `npm run dev` | Starts the local development server with hot reload |
| `npm run build` | Compiles the app for production into `/dist` |
| `npm run preview` | Previews the production build locally |
| `npm run lint` | Runs ESLint across the project |

---

## Deploying to Vercel

This is the recommended deployment target. It is free and takes under 2 minutes.

1. Push your code to GitHub (you already have this).
2. Go to [vercel.com](https://vercel.com) and click **New Project**.
3. Import your `SafeCheck` repository.
4. Under **Environment Variables**, add `VIRUSTOTAL_API_KEY` with your VirusTotal key.
5. Click **Deploy**.

Vercel will auto-detect Vite and handle the build for you. Every push to `main` will auto-deploy.

The Vercel Serverless Functions in `/api/scan.ts` and `/api/check-hash.ts` will automatically be deployed and your API key will be secure server-side.

---

## How the Verdict Engine Works

SafeCheck does not treat all antivirus engines equally and does not treat all flag types equally.

**Engine tiers** — Engines are ranked by reputation. A flag from Kaspersky or Bitdefender (Tier 1, 3 points) carries more weight than a flag from a lesser-known engine (Tier 3, 1 point).

**Flag categories** — Each flag is categorized. Generic flags like `HackTool` or `Crack` score 0 points — they are expected and normal. Suspicious flags like `Adware` or `Bundler` score at half weight. Dangerous flags like `Ransomware`, `Trojan.Stealer`, or `Miner` score at full weight.

**Final verdict thresholds:**

| Score | Verdict |
|---|---|
| 0–4 | ✅ Safe |
| 5–9 | ⚠️ Suspicious |
| 10+ | 🚨 Dangerous |

Every verdict card includes an expandable "Why this verdict?" section that shows exactly which engines flagged what and how the score was calculated.

---

## Disclaimer

SafeCheck cannot guarantee a file is safe. It provides a risk assessment based on available data. Always exercise caution with downloaded files. This tool is for informational purposes only.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Roadmap

| Phase | What Is Coming |
|---|---|
| MVP (now) | URL checker, VirusTotal scan + weighted verdict, hash verification, torrent parser |
| v1.1 | Missing file / quarantine detector, community site reporting, UI polish |
| v2.0 | Chrome + Firefox browser extension — real-time warnings on known fake sites |
| v3.0 | Desktop companion app for process monitoring and live miner detection |