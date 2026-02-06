# SafeCheck

A browser-based, zero-install file safety checker. Drop a file, get a verdict — Safe, Suspicious, or Dangerous. No account needed, no downloads required.

SafeCheck does not just scan files. It **interprets** the results. When VirusTotal flags something as `HackTool` or `Crack`, SafeCheck tells you whether that is a normal, expected flag or an actual threat — in plain English.

![SafeCheck Banner](./SafeCheck%20Banner.png)

> **Note:** This started as a learning project to understand file hashing, API integration, and weighted scoring algorithms. I'm sharing it in case it helps someone else who's new to downloading files safely. If you already know how to check hashes and interpret VirusTotal results, you probably don't need this — but the code might still be useful as a reference.

---

## What It Does

| Feature | How It Works |
|---|---|
| **Source URL Checker** | Paste the URL you downloaded from. Instantly checks against a database of verified legitimate and known fake sites. |
| **VirusTotal Scan** | Upload a file (under 32MB). SafeCheck scans it through 70+ antivirus engines and interprets the result using a weighted scoring engine — not raw flag counts. |
| **SHA-256 Hash Verification** | Paste a known-good hash. The tool computes the hash of your file locally in the browser — nothing is uploaded for this step. Match or mismatch, instant answer. |
| **Torrent Metadata Parser** | Drop a `.torrent` file. See the full file list, sizes, and folder structure before you download anything. Advisory anomaly flags highlight anything unusual. |

---

## Privacy & Trust

**TL;DR:** Most operations run entirely in your browser. File uploads go to VirusTotal's official API via a proxy. Nothing is stored.

### What Runs in Your Browser (Client-Side)
- **SHA-256 hash computation** — Uses the browser's native `crypto.subtle` API. Your file never leaves your device for this.
- **Torrent file parsing** — The `.torrent` file is parsed locally using the `parse-torrent` library. Nothing is uploaded.
- **Source URL checking** — Checks against a local database. No network request.

### What Goes to the Server
- **VirusTotal file scanning** — When you upload a file for scanning, it is sent to a backend proxy server (your own if self-hosting, or the hosted version). The server forwards it to VirusTotal's official API at `https://www.virustotal.com/api/v3/files` and returns the result. The file is not stored anywhere — it goes straight to VirusTotal and the response comes straight back to you.
- **Hash lookup** — When checking if a file hash already exists in VirusTotal's database, the hash (not the file) is sent to the backend proxy, which queries VirusTotal's hash lookup endpoint. This does not count against your scan quota and no file is uploaded.

### Why a Backend Proxy?
The VirusTotal API key must be kept secret. If it were in the frontend code, anyone could steal it and abuse it. The proxy exists solely to hide the API key. You can audit the code yourself in `/server/src/index.ts` (or `/api/scan.ts` and `/api/check-hash.ts` if using Vercel).

### Open Source = Full Transparency
The entire codebase is public. You can read every line of code and see exactly what data is sent where. If you don't trust the hosted version, you can run your own instance (see below).

---

## Self-Hosting (Run Your Own Instance)

If you don't trust the hosted version or want full control, you can run SafeCheck entirely on your own machine or server.

### Option 1: Run Locally (Frontend + Backend)

**Step 1:** Clone the repo and install dependencies

```bash
git clone https://github.com/BrajamohanDas-afk/SafeCheck.git
cd SafeCheck
npm install
```

**Step 2:** Set up the backend

```bash
cd server
npm install
```

Create `server/.env`:

```
PORT=3001
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
```

Get a free VirusTotal API key at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us).

**Step 3:** Run both frontend and backend

Terminal 1 (backend):
```bash
cd server
npm run dev
```

Terminal 2 (frontend):
```bash
cd ..
npm run dev
```

The frontend will be at `http://localhost:5173` and will call your local backend at `http://localhost:3001`.

### Option 2: Deploy to Your Own Server

You can deploy the backend to any service:

- **Render.com** (free tier, auto-deploys from GitHub)
- **Railway.app** (free tier, very easy setup)
- **Fly.io** (free tier for small apps)
- **Your own VPS** (DigitalOcean, Linode, etc.)

Instructions for each platform are in the [deployment guide](https://github.com/BrajamohanDas-afk/SafeCheck/wiki/Deployment) (TODO: add this wiki page).

### Option 3: Use Vercel Serverless Functions

If you prefer serverless instead of a traditional backend:

1. Deploy the frontend to Vercel
2. The `/api` folder contains Vercel Serverless Functions that act as the proxy
3. Add `VIRUSTOTAL_API_KEY` to your Vercel environment variables
4. Deploy and you're done

Full instructions in [Getting Started](#getting-started-locally).

---

## Tech Stack

- **React** + **TypeScript**
- **Vite** — build and dev server
- **Tailwind CSS** — styling
- **shadcn/ui** — component library
- **Web Crypto API** (`crypto.subtle`) — local SHA-256 hashing, runs entirely in your browser
- **Express.js** — backend server (or Vercel Serverless Functions if you prefer)
- **VirusTotal API v3** — file scanning backend (proxied server-side)

---

## Getting Started Locally

Make sure you have **Node.js** (18+) and **npm** installed.

### Quick Start (Frontend Only, No Backend)

If you just want to see the UI and test the hash verification / torrent parsing features (which run client-side):

```bash
# 1. Clone the repo
git clone https://github.com/BrajamohanDas-afk/SafeCheck.git
cd SafeCheck

# 2. Install dependencies
npm install

# 3. Start the frontend dev server
npm run dev
```

The app will be running at `http://localhost:5173`. The VirusTotal scan feature won't work without the backend, but everything else will.

### Full Setup (Frontend + Backend)

To enable the VirusTotal scanning feature, you need to run the backend as well.

**Step 1:** Install frontend dependencies

```bash
npm install
```

**Step 2:** Set up and run the backend

```bash
cd server
npm install
```

Create `server/.env`:

```
PORT=3001
VIRUSTOTAL_API_KEY=your_key_here
```

Start the backend:

```bash
npm run dev
```

**Step 3:** In a new terminal, start the frontend

```bash
cd ..
npm run dev
```

Now the frontend at `http://localhost:5173` will call your backend at `http://localhost:3001` for VirusTotal scans.

---

## Environment Variables

### Frontend (root `.env`)
Not required for basic functionality. The frontend doesn't need any API keys.

### Backend (`server/.env`)

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Port for the backend server. Defaults to `3001`. |
| `VIRUSTOTAL_API_KEY` | Yes | Your VirusTotal API key. Get a free one at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us). Free tier gives 500 file scans/day. |

---

## Testing with Postman

You can test the backend API endpoints using Postman. Here's how:

### 1. Health Check
Test if the backend is running.

```
GET http://localhost:3001/health
```

**Expected Response:**
```json
{
  "status": "The server is running",
  "timeStamp": "2026-02-06T10:30:45.123Z",
  "vtKeyLoaded": true
}
```

---

### 2. Check File Hash
Check if a file hash already exists in VirusTotal's database (without uploading).

```
GET http://localhost:3001/api/check-hash?hash=<SHA256_HASH>
```

**Example:**
```
GET http://localhost:3001/api/check-hash?hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Headers:**
- None required

**Expected Response:**
```json
{
  "data": {
    "type": "file",
    "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "attributes": {
      "last_analysis_stats": {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 65,
        "timeout": 5
      }
    }
  }
}
```

---

### 3. Scan a File
Upload a file to VirusTotal for scanning.

```
POST http://localhost:3001/api/scan
```

**Headers:**
- None required (Content-Type will be auto-set)

**Body:**
- Select `form-data`
- Key: `file`
- Type: `File` (dropdown)
- Value: Select your file

**Example in Postman:**
1. Method: `POST`
2. URL: `http://localhost:3001/api/scan`
3. Body → `form-data`
4. Key: `file`, Type: `File`, Value: `[Select your file]`
5. Click **Send**

**Expected Response (200 OK):**
```json
{
  "data": {
    "type": "analysis",
    "id": "YjIwZmE3YTkxNTFjNDBjNDRhMzc2ODA1M2MzZWE1ODc6MTc3MDMzOTMwOQ==",
    "links": {
      "self": "https://www.virustotal.com/api/v3/analyses/YjIwZmE3YTkxNTFjNDBjNDRhMzc2ODA1M2MzZWE1ODc6MTc3MDMzOTMwOQ=="
    }
  }
}
```

The `data.id` is the analysis ID. Use it to fetch detailed results.

---

### 4. Get Analysis Results
Fetch the detailed scanning results from VirusTotal.

```
GET https://www.virustotal.com/api/v3/analyses/<ANALYSIS_ID>
```

**Headers:**
- Key: `x-apikey`
- Value: `Your VirusTotal API Key`

**Example in Postman:**
1. Method: `GET`
2. URL: `https://www.virustotal.com/api/v3/analyses/YjIwZmE3YTkxNTFjNDBjNDRhMzc2ODA1M2MzZWE1ODc6MTc3MDMzOTMwOQ==`
3. Headers → Add:
   - Key: `x-apikey`
   - Value: Your API key from `server/.env`
4. Click **Send**

**Expected Response:**
```json
{
  "data": {
    "type": "analysis",
    "id": "YjIwZmE3YTkxNTFjNDBjNDRhMzc2ODA1M2MzZWE1ODc6MTc3MDMzOTMwOQ==",
    "attributes": {
      "status": "completed",
      "stats": {
        "malicious": 2,
        "suspicious": 1,
        "undetected": 65,
        "timeout": 2
      },
      "results": {
        "Avast": {
          "category": "malware",
          "engine_name": "Avast",
          "result": "Win32:PUP-gen"
        }
      }
    }
  }
}
```

---

### Troubleshooting Postman Requests

| Error | Solution |
|---|---|
| `401 Unauthorized` on analysis endpoint | Make sure the `x-apikey` header is set correctly in the **Headers** tab, not Query Parameters |
| `404 Not Found` on check-hash | The hash might not exist in VirusTotal's database. Try with a known file hash. |
| `Failed to connect` | Make sure the backend is running (`npm run dev` in the `server/` folder) |
| `Missing or invalid hash parameter` | Add `?hash=<SHA256_HASH>` to the URL (Query Parameters) |

> **Important:** The API key should NEVER be prefixed with `VITE_`. That would expose it to the browser. Keep it server-side only.

---

## Project Structure

```
SafeCheck/
├── server/                 # Backend server (Express.js)
│   ├── src/
│   │   └── index.ts        # Main server file with /api/scan and /api/check-hash routes
│   ├── .env                # Backend environment variables (VIRUSTOTAL_API_KEY)
│   ├── package.json
│   └── tsconfig.json
│
├── src/                    # Frontend React code
│   ├── components/         # React components (UI blocks)
│   ├── lib/                # Utility functions (hashing, scoring logic, site DB)
│   ├── pages/              # Page-level components
│   ├── App.tsx             # Root component
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles (Tailwind directives)
│
├── public/                 # Static files (favicon, etc.)
├── package.json            # Frontend dependencies and scripts
├── tailwind.config.ts      # Tailwind configuration
├── tsconfig.json           # TypeScript root config
├── vite.config.ts          # Vite configuration (includes proxy to backend)
└── README.md               # This file
```

---

## Available Scripts

### Frontend

| Command | What It Does |
|---|---|
| `npm run dev` | Starts the local development server with hot reload |
| `npm run build` | Compiles the app for production into `/dist` |
| `npm run preview` | Previews the production build locally |
| `npm run lint` | Runs ESLint across the project |

### Backend (from `server/` folder)

| Command | What It Does |
|---|---|
| `npm run dev` | Starts the backend server with hot reload (using `nodemon` + `ts-node`) |
| `npm run build` | Compiles TypeScript to JavaScript in `/dist` |
| `npm start` | Runs the compiled JavaScript (for production) |

---

## Deploying to Vercel (Alternative to Self-Hosting)

This is the easiest deployment option if you don't want to manage a server.

1. Push your code to GitHub.
2. Go to [vercel.com](https://vercel.com) and click **New Project**.
3. Import your `SafeCheck` repository.
4. Under **Environment Variables**, add `VIRUSTOTAL_API_KEY` with your VirusTotal key.
5. Click **Deploy**.

Vercel will auto-detect Vite and handle the build. The Vercel Serverless Functions in `/api/scan.ts` and `/api/check-hash.ts` will automatically be deployed and your API key will be secure server-side.

> **Note:** If using Vercel, you don't need the `server/` folder. The `/api` folder replaces it.

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

The tool does not replace common sense. If you download from a trusted source and the only flags are generic crack signatures, you're probably fine. If you download from a sketchy site and see Ransomware flags, delete it. Use your judgment.

---

## Contributing

This is a learning project, but contributions are welcome. If you find a bug or want to add a feature:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please keep the code clean and well-commented. This project is meant to be readable for other learners.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

You are free to use, modify, and distribute this code. If you build something cool with it, let me know — I'd love to see it.

---

## Roadmap

| Phase | What Is Coming |
|---|---|
| **MVP (now)** | URL checker, VirusTotal scan + weighted verdict, hash verification, torrent parser |
| **v1.1** | Missing file / quarantine detector, community site reporting, UI polish |
| **v2.0** | Chrome + Firefox browser extension — real-time warnings on known fake sites |
| **v3.0** | Desktop companion app for process monitoring and live miner detection |

---

## Acknowledgments

- **VirusTotal** for providing the free API that makes this possible
- The communities at r/Piracy, r/CrackSupport, and r/PiratedGames for the inspiration and feedback
- Everyone who helped test and improve this tool

---



Built by [Brajamohan Das](https://github.com/BrajamohanDas-afk)