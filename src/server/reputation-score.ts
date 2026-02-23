import { checkSource } from "@/server/source-db";
import type {
  ReputationReason,
  SmartDownloadReputationResult,
  SourceVerdict,
} from "@/features/file-safety/types";

const MAX_REDIRECTS = 6;
const REQUEST_TIMEOUT_MS = 8_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const EXECUTABLE_EXTENSIONS = new Set([
  "exe",
  "msi",
  "dll",
  "bat",
  "cmd",
  "ps1",
  "scr",
  "com",
  "jar",
  "vbs",
]);

const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "bz2", "xz"]);
const VIDEO_EXTENSIONS = new Set(["mp4", "mkv", "avi", "mov", "webm"]);
const DOC_EXTENSIONS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"]);
const BAIT_EXTENSIONS = new Set(["pdf", "doc", "docx", "txt", "jpg", "jpeg", "png", "mp4", "xls", "xlsx"]);

interface UrlInspectionResult {
  finalUrl: string;
  redirectDepth: number;
  tlsStatus: "https" | "http" | "downgraded" | "unknown";
  mimeType: string | null;
  metadataFetchStatus: "ok" | "error";
}

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Please enter a URL to score.");
  }

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withProtocol);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http/https URLs are supported.");
  }

  return parsed.toString();
}

function toDomain(value: string): string {
  const parsed = new URL(value);
  return parsed.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
}

function getFilenameFromUrl(value: string): string | null {
  const parsed = new URL(value);
  const segments = parsed.pathname.split("/").filter(Boolean);
  if (segments.length === 0) return null;

  const candidate = decodeURIComponent(segments[segments.length - 1]).trim();
  return candidate || null;
}

function getExtension(filename: string | null): string | null {
  if (!filename) return null;
  const parts = filename.split(".");
  if (parts.length < 2) return null;
  return parts[parts.length - 1].toLowerCase();
}

function isSuspiciousDoubleExtension(filename: string | null): boolean {
  if (!filename) return false;

  const parts = filename.toLowerCase().split(".").filter(Boolean);
  if (parts.length < 3) return false;

  const penultimate = parts[parts.length - 2];
  const last = parts[parts.length - 1];

  return BAIT_EXTENSIONS.has(penultimate) && EXECUTABLE_EXTENSIONS.has(last);
}

function createTimeoutSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

async function requestUrlMetadata(url: string): Promise<Response> {
  const common: RequestInit = {
    redirect: "manual",
    cache: "no-store",
    signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
    headers: {
      "user-agent": "SafeCheck/1.0",
    },
  };

  const headResponse = await fetch(url, {
    ...common,
    method: "HEAD",
  });

  if (headResponse.status === 405 || headResponse.status === 501) {
    return fetch(url, {
      ...common,
      method: "GET",
    });
  }

  return headResponse;
}

function resolveTlsStatus(initialUrl: string, finalUrl: string, sawDowngrade: boolean): UrlInspectionResult["tlsStatus"] {
  if (sawDowngrade) return "downgraded";

  const initialProtocol = new URL(initialUrl).protocol;
  const finalProtocol = new URL(finalUrl).protocol;

  if (initialProtocol === "https:" && finalProtocol === "https:") return "https";
  if (finalProtocol === "http:") return "http";
  return "unknown";
}

async function inspectUrl(inputUrl: string): Promise<UrlInspectionResult> {
  let currentUrl = inputUrl;
  let redirectDepth = 0;
  let sawDowngrade = false;

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
      const response = await requestUrlMetadata(currentUrl);
      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.get("location");
        if (!location) {
          return {
            finalUrl: currentUrl,
            redirectDepth,
            tlsStatus: resolveTlsStatus(inputUrl, currentUrl, sawDowngrade),
            mimeType: null,
            metadataFetchStatus: "error",
          };
        }

        const nextUrl = new URL(location, currentUrl).toString();
        const nextProtocol = new URL(nextUrl).protocol;
        if (nextProtocol === "http:") {
          sawDowngrade = true;
        }

        currentUrl = nextUrl;
        redirectDepth += 1;
        continue;
      }

      return {
        finalUrl: currentUrl,
        redirectDepth,
        tlsStatus: resolveTlsStatus(inputUrl, currentUrl, sawDowngrade),
        mimeType: response.headers.get("content-type"),
        metadataFetchStatus: "ok",
      };
    }
  } catch {
    return {
      finalUrl: currentUrl,
      redirectDepth,
      tlsStatus: "unknown",
      mimeType: null,
      metadataFetchStatus: "error",
    };
  }

  return {
    finalUrl: currentUrl,
    redirectDepth,
    tlsStatus: resolveTlsStatus(inputUrl, currentUrl, sawDowngrade),
    mimeType: null,
    metadataFetchStatus: "error",
  };
}

function isMimeMismatch(extension: string | null, mimeType: string | null): boolean {
  if (!extension || !mimeType) return false;
  const normalizedMime = mimeType.toLowerCase();

  if (EXECUTABLE_EXTENSIONS.has(extension)) {
    return normalizedMime.startsWith("text/html") || normalizedMime.startsWith("text/plain");
  }

  if (ARCHIVE_EXTENSIONS.has(extension)) {
    return !(normalizedMime.includes("zip") || normalizedMime.includes("compressed") || normalizedMime.includes("octet-stream"));
  }

  if (VIDEO_EXTENSIONS.has(extension)) {
    return !normalizedMime.startsWith("video/");
  }

  if (DOC_EXTENSIONS.has(extension)) {
    return normalizedMime.startsWith("application/x-msdownload");
  }

  return false;
}

function addReason(
  reasons: ReputationReason[],
  id: string,
  label: string,
  points: number,
  detail: string
): number {
  if (points <= 0) return 0;
  reasons.push({ id, label, points, detail });
  return points;
}

function levelFromScore(score: number): SmartDownloadReputationResult["level"] {
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function reasonForSourceVerdict(verdict: SourceVerdict): { label: string; points: number; detail: string } | null {
  if (verdict === "known-fake") {
    return {
      label: "Known bad source",
      points: 45,
      detail: "The domain is already marked as known fake in your trust database.",
    };
  }

  if (verdict === "unknown") {
    return {
      label: "Unknown source trust",
      points: 12,
      detail: "No trusted source status is available yet for this domain.",
    };
  }

  return null;
}

export async function analyzeDownloadReputation(input: string): Promise<SmartDownloadReputationResult> {
  const normalizedUrl = normalizeUrl(input);
  const domain = toDomain(normalizedUrl);

  const [source, urlInspection] = await Promise.all([checkSource(normalizedUrl), inspectUrl(normalizedUrl)]);

  const filename = getFilenameFromUrl(urlInspection.finalUrl);
  const extension = getExtension(filename);
  const mimeMismatch = isMimeMismatch(extension, urlInspection.mimeType);

  const reasons: ReputationReason[] = [];
  let score = 0;

  const sourceReason = reasonForSourceVerdict(source.verdict);
  if (sourceReason) {
    score += addReason(reasons, "source-verdict", sourceReason.label, sourceReason.points, sourceReason.detail);
  }

  if (source.reports > 0) {
    const reportPoints = Math.min(15, source.reports * 3);
    score += addReason(
      reasons,
      "community-reports",
      "Community reports",
      reportPoints,
      `${source.reports} reports were submitted for this domain.`
    );
  }

  if (source.threatTypes.length > 0) {
    score += addReason(
      reasons,
      "threat-intel-hit",
      "Threat intelligence hit",
      40,
      `External feed matched: ${source.threatTypes.join(", ")}.`
    );
  }

  if (urlInspection.tlsStatus === "http") {
    score += addReason(
      reasons,
      "http-transport",
      "Insecure transport",
      18,
      "The URL resolves over HTTP instead of HTTPS."
    );
  } else if (urlInspection.tlsStatus === "downgraded") {
    score += addReason(
      reasons,
      "https-downgrade",
      "HTTPS downgrade redirect",
      22,
      "The redirect chain downgraded from HTTPS to HTTP."
    );
  }

  if (urlInspection.redirectDepth >= 3) {
    const redirectPoints = urlInspection.redirectDepth >= 5 ? 15 : 8;
    score += addReason(
      reasons,
      "redirect-depth",
      "Deep redirect chain",
      redirectPoints,
      `The URL redirected ${urlInspection.redirectDepth} times before resolving.`
    );
  }

  if (isSuspiciousDoubleExtension(filename)) {
    score += addReason(
      reasons,
      "double-extension",
      "Suspicious filename pattern",
      18,
      `Detected a double-extension pattern in "${filename}".`
    );
  }

  if (mimeMismatch) {
    score += addReason(
      reasons,
      "mime-mismatch",
      "MIME/extension mismatch",
      15,
      `File extension "${extension}" conflicts with content type "${urlInspection.mimeType}".`
    );
  }

  if (urlInspection.metadataFetchStatus === "error") {
    score += addReason(
      reasons,
      "metadata-unavailable",
      "Incomplete URL metadata",
      6,
      "Could not reliably fetch remote metadata (TLS/redirect/content-type checks are partial)."
    );
  }

  score = Math.min(100, score);
  reasons.sort((a, b) => b.points - a.points);

  return {
    inputUrl: input.trim(),
    normalizedUrl,
    domain,
    score,
    level: levelFromScore(score),
    reasons,
    signals: {
      sourceVerdict: source.verdict,
      sourceConfidence: source.confidence,
      reports: source.reports,
      threatTypes: source.threatTypes,
      intelProvider: source.intelProvider,
      tlsStatus: urlInspection.tlsStatus,
      redirectDepth: urlInspection.redirectDepth,
      finalUrl: urlInspection.finalUrl,
      mimeType: urlInspection.mimeType,
      mimeMismatch,
      filename,
      domainAgeStatus: "not-available",
      popularityStatus: "not-available",
      metadataFetchStatus: urlInspection.metadataFetchStatus,
    },
  };
}

