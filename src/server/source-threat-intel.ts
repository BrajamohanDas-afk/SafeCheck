type GoogleThreatMatch = {
  threatType?: string;
};

type GoogleThreatMatchesResponse = {
  matches?: GoogleThreatMatch[];
};

export interface SourceThreatIntelResult {
  provider: "google-safe-browsing";
  status: "match" | "not_found";
  threatTypes: string[];
  note: string;
}

const GOOGLE_SAFE_BROWSING_ENDPOINT =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const SAFE_BROWSING_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

function toThreatTypes(payload: GoogleThreatMatchesResponse): string[] {
  if (!Array.isArray(payload.matches)) return [];

  return Array.from(
    new Set(
      payload.matches
        .map((match) => (typeof match?.threatType === "string" ? match.threatType : null))
        .filter((value): value is string => Boolean(value))
    )
  );
}

function createTimeoutSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

export async function checkGoogleSafeBrowsing(
  inputUrl: string
): Promise<SourceThreatIntelResult | null> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return null;
  }

  let response: Response;
  try {
    response = await fetch(`${GOOGLE_SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client: {
          clientId: "safecheck",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: SAFE_BROWSING_THREAT_TYPES,
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: inputUrl }],
        },
      }),
      cache: "no-store",
      signal: createTimeoutSignal(10_000),
    });
  } catch (error) {
    throw new Error(
      `Google Safe Browsing check failed: ${
        error instanceof Error ? error.message : "network error"
      }`
    );
  }

  if (!response.ok) {
    let message = `Google Safe Browsing request failed (${response.status})`;
    try {
      const payload = (await response.json()) as {
        error?: { message?: string };
      };
      if (typeof payload?.error?.message === "string") {
        message = `Google Safe Browsing error: ${payload.error.message}`;
      }
    } catch {
      // Keep fallback message.
    }

    throw new Error(message);
  }

  const payload = (await response.json()) as GoogleThreatMatchesResponse;
  const threatTypes = toThreatTypes(payload);

  if (threatTypes.length > 0) {
    return {
      provider: "google-safe-browsing",
      status: "match",
      threatTypes,
      note: `Listed as unsafe by Google Safe Browsing (${threatTypes.join(", ")}).`,
    };
  }

  return {
    provider: "google-safe-browsing",
    status: "not_found",
    threatTypes: [],
    note: "Not found in Google Safe Browsing threat database.",
  };
}

