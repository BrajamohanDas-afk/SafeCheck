import type { HashCompareResult } from "../types";

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;

function normalize(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, "");
}

export function compareKnownHash(
  expectedHashInput: string,
  actualFileHash: string | null
): HashCompareResult {
  const normalizedInput = normalize(expectedHashInput);

  if (!normalizedInput) {
    return {
      status: "idle",
      normalizedInput,
      message: "Paste a known-good SHA-256 hash to compare.",
    };
  }

  if (!SHA256_HEX_REGEX.test(normalizedInput)) {
    return {
      status: "invalid",
      normalizedInput,
      message: "Hash must be a 64-character SHA-256 hex string.",
    };
  }

  if (!actualFileHash) {
    return {
      status: "waiting-file-hash",
      normalizedInput,
      message: "Upload a file first so SafeCheck can compute its SHA-256 hash.",
    };
  }

  if (normalizedInput === actualFileHash.toLowerCase()) {
    return {
      status: "match",
      normalizedInput,
      message: "Hash match: this file is byte-for-byte identical to the expected file.",
    };
  }

  return {
    status: "mismatch",
    normalizedInput,
    message: "Hash mismatch: file differs from the expected hash. Treat as tampered.",
  };
}
