import type { MissingFileDetectionResult } from "../types";

const LIKELY_QUARANTINE_PATTERNS = [
  /steam_api64\.dll$/i,
  /steam_api\.dll$/i,
  /emp\.dll$/i,
  /codex64\.dll$/i,
  /crack.*\.dll$/i,
  /patch.*\.exe$/i,
];

function normalizeFileList(raw: string): string[] {
  const parts = raw
    .split(/\r?\n|,/g)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => item.replace(/\\/g, "/").replace(/^\.?\//, "").toLowerCase());

  return Array.from(new Set(parts));
}

function matchesLikelyQuarantine(filePath: string): boolean {
  const name = filePath.split("/").pop() ?? filePath;
  return LIKELY_QUARANTINE_PATTERNS.some((pattern) => pattern.test(name));
}

export function detectMissingFiles(
  expectedRaw: string,
  actualRaw: string
): MissingFileDetectionResult {
  const expected = normalizeFileList(expectedRaw);
  const actual = new Set(normalizeFileList(actualRaw));

  const missingFiles = expected.filter((item) => !actual.has(item));
  const likelyQuarantined = missingFiles.filter(matchesLikelyQuarantine);
  const expectedSet = new Set(expected);
  const unexpectedFiles = normalizeFileList(actualRaw).filter((item) => !expectedSet.has(item));

  return {
    expectedCount: expected.length,
    actualCount: actual.size,
    missingFiles,
    unexpectedFiles,
    likelyQuarantined,
  };
}
