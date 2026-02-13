import type { VirusTotalFileResult } from "../types";

/**
 * Check if a file hash already exists in VirusTotal's cache.
 */
export async function checkHashCache(
  hash: string
): Promise<VirusTotalFileResult | null> {
  const response = await fetch(`/api/check-hash?hash=${encodeURIComponent(hash)}`);

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to check hash");
  }

  return response.json();
}

/**
 * Upload a file via backend proxy and return the final file report.
 * Backend handles VT upload + polling analysis completion.
 */
export async function uploadFileToScan(file: File): Promise<VirusTotalFileResult> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/api/scan", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to scan file");
  }

  return response.json();
}
