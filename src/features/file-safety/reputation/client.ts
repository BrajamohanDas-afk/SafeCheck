import type { SmartDownloadReputationResult } from "../types";

async function parseErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const payload = (await response.json()) as { error?: string };
    if (payload?.error) return payload.error;
  } catch {
    // ignore parsing error
  }

  return fallback;
}

export async function scoreDownloadReputation(input: string): Promise<SmartDownloadReputationResult> {
  const response = await fetch(`/api/reputation-score?input=${encodeURIComponent(input)}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const message = await parseErrorMessage(response, "Failed to score download reputation.");
    throw new Error(message);
  }

  return (await response.json()) as SmartDownloadReputationResult;
}

