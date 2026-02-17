import type { VirusTotalFileResult } from "../types";

const SCAN_POLL_INTERVAL_MS = 7000;
const SCAN_POLL_TIMEOUT_MS = 10 * 60 * 1000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function parseErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const payload = (await response.json()) as { error?: string };
    if (payload?.error) return payload.error;
  } catch {
    // ignore JSON parse issues and use fallback
  }

  return fallback;
}

/**
 * Check if a file hash already exists in VirusTotal's cache.
 */
export async function checkHashCache(
  hash: string
): Promise<VirusTotalFileResult | null> {
  const response = await fetch(`/api/check-hash?hash=${encodeURIComponent(hash)}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to check hash");
  }

  return (await response.json()) as VirusTotalFileResult | null;
}

/**
 * Upload a file via backend proxy and return the final file report.
 * Backend handles VT upload + polling analysis completion.
 */
export async function uploadFileToScan(file: File): Promise<VirusTotalFileResult> {
  const formData = new FormData();
  formData.append("file", file);

  const uploadResponse = await fetch("/api/scan", {
    method: "POST",
    body: formData,
    cache: "no-store",
  });

  if (!uploadResponse.ok) {
    const message = await parseErrorMessage(uploadResponse, "Failed to upload file for scan");
    throw new Error(message);
  }

  const uploadPayload = (await uploadResponse.json()) as { analysisId?: string };
  const analysisId = uploadPayload.analysisId;

  if (!analysisId) {
    throw new Error("Scan upload succeeded but no analysis id was returned.");
  }

  const deadline = Date.now() + SCAN_POLL_TIMEOUT_MS;

  while (Date.now() < deadline) {
    await sleep(SCAN_POLL_INTERVAL_MS);

    const pollResponse = await fetch(`/api/scan?analysisId=${encodeURIComponent(analysisId)}`, {
      cache: "no-store",
    });

    if (pollResponse.status === 202) {
      continue;
    }

    if (!pollResponse.ok) {
      const message = await parseErrorMessage(pollResponse, "Failed while waiting for scan result");
      throw new Error(message);
    }

    const payload = (await pollResponse.json()) as {
      status?: string;
      report?: VirusTotalFileResult;
    };

    if (payload.status === "completed" && payload.report) {
      return payload.report;
    }
  }

  throw new Error(
    `VirusTotal scan is still processing after ${Math.round(
      SCAN_POLL_TIMEOUT_MS / 1000
    )}s. Please retry in a bit.`
  );
}
