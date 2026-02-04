/**
 * VirusTotal API client for the frontend
 * All requests are proxied through serverless functions for API key security
 */

export interface VirusTotalFileResult {
  data: {
    id: string;
    type: string;
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
      };
      last_analysis_results: Record<
        string,
        {
          category: string;
          engine_name: string;
          result: string;
        }
      >;
      meaningful_name?: string;
      sha256: string;
      size: number;
      type_tag: string;
    };
    links?: {
      self: string;
    };
  };
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Check if a file hash has been cached in VirusTotal
 * This endpoint doesn't consume the file scan quota
 * @param hash SHA-256 hash of the file
 * @returns Cached scan result if found, null if not in cache
 */
export async function checkHashCache(
  hash: string
): Promise<VirusTotalFileResult | null> {
  try {
    const response = await fetch(`/api/check-hash?hash=${encodeURIComponent(hash)}`);

    if (response.status === 404) {
      return null; // File not in cache
    }

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to check hash");
    }

    return await response.json();
  } catch (error) {
    console.error("Error checking hash cache:", error);
    throw error;
  }
}

/**
 * Upload a file to VirusTotal for scanning
 * @param file The file to scan
 * @returns Scan submission response with analysis ID
 */
export async function uploadFileToScan(
  file: File
): Promise<VirusTotalFileResult> {
  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch("/api/scan", {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to upload file");
    }

    return await response.json();
  } catch (error) {
    console.error("Error uploading file:", error);
    throw error;
  }
}

/**
 * Performs cache-first flow:
 * 1. First checks if file hash exists in VirusTotal cache (doesn't consume quota)
 * 2. If not cached, uploads file for scanning (consumes quota)
 * @param file The file to scan
 * @param fileHash SHA-256 hash of the file
 * @returns Scan result from cache or upload
 */
export async function scanFileWithCacheFallback(
  file: File,
  fileHash: string
): Promise<VirusTotalFileResult> {
  try {
    // First, check if file is already cached
    const cachedResult = await checkHashCache(fileHash);

    if (cachedResult) {
      return cachedResult;
    }

    // If not cached, upload for scanning
    return await uploadFileToScan(file);
  } catch (error) {
    console.error("Error in cache-first scan flow:", error);
    throw error;
  }
}
