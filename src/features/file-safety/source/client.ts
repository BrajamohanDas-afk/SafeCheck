import type {
  SiteReportItem,
  SiteReportModerationInput,
  SiteReportModerationResult,
  SiteReportResponse,
  SourceCheckResult,
} from "../types";

async function parseErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const payload = (await response.json()) as { error?: string };
    if (payload?.error) return payload.error;
  } catch {
    // ignore parsing error
  }

  return fallback;
}

export async function checkSourceInput(input: string): Promise<SourceCheckResult> {
  const response = await fetch(`/api/source-check?input=${encodeURIComponent(input)}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const message = await parseErrorMessage(response, "Failed to check source.");
    throw new Error(message);
  }

  return (await response.json()) as SourceCheckResult;
}

export async function submitSourceReport(
  input: string,
  notes: string,
  createdBy: string
): Promise<SiteReportResponse> {
  const response = await fetch("/api/site-reports", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ input, notes, createdBy }),
  });

  if (!response.ok) {
    const message = await parseErrorMessage(response, "Failed to submit source report.");
    throw new Error(message);
  }

  return (await response.json()) as SiteReportResponse;
}

export async function loadPendingSiteReports(moderationToken: string): Promise<SiteReportItem[]> {
  const response = await fetch("/api/site-reports?limit=50", {
    headers: {
      "x-moderation-token": moderationToken,
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const message = await parseErrorMessage(response, "Failed to load pending reports.");
    throw new Error(message);
  }

  const payload = (await response.json()) as { reports?: SiteReportItem[] };
  return (payload.reports ?? []).filter(
    (item) => item.status === "pending" || item.status === "pending_review"
  );
}

export async function moderatePendingSiteReport(
  moderationToken: string,
  input: SiteReportModerationInput
): Promise<SiteReportModerationResult> {
  const response = await fetch("/api/site-reports", {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "x-moderation-token": moderationToken,
    },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    const message = await parseErrorMessage(response, "Failed to moderate report.");
    throw new Error(message);
  }

  return (await response.json()) as SiteReportModerationResult;
}
