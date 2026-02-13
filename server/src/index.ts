import dotenv from "dotenv";
import { createApp } from "./app";

dotenv.config();

const port = Number(process.env.PORT || 3001);
const vtApiKey = process.env.VIRUSTOTAL_API_KEY;

if (!vtApiKey) {
  console.error({ error: "VIRUSTOTAL_API_KEY is not set in the environment" });
  process.exit(1);
}

const app = createApp({ vtApiKey });

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`VirusTotal API key loaded: ${vtApiKey.substring(0, 8)}...`);
});
