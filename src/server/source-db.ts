import { getSupabaseAdminClient } from "@/lib/supabase/server";

export type SourceStatus = "legitimate" | "fake" | "unknown";
export type SourceConfidence = "high" | "medium" | "low";
export type SourceVerdict = "verified" | "known-fake" | "unknown";

interface SourceRecord {
  domain: string;
  status: SourceStatus;
  confidence: SourceConfidence;
  reports: number;
  addedDate: string;
  lastVerifiedAt: string;
  verifiedBy: string;
}

export interface SourceCheckResult {
  domain: string;
  matchedDomain: string | null;
  verdict: SourceVerdict;
  status: SourceStatus;
  confidence: SourceConfidence;
  reports: number;
  stale: boolean;
  note: string;
  backend: "supabase" | "seed";
}

export interface SiteReportResponse {
  id: string;
  domain: string;
  status: string;
  reportCountForDomain: number;
  autoFlaggedForReview: boolean;
}

export interface SiteReportModerationInput {
  reportId: string;
  decision: "approve" | "reject" | "needs_more_data";
  sourceStatus?: SourceStatus;
  confidence?: SourceConfidence;
  reviewNotes?: string;
  reviewedBy?: string;
}

export interface SiteReportModerationResult {
  reportId: string;
  domain: string;
  status: string;
  source?: SourceCheckResult;
}

export interface SiteReportItem {
  id: string;
  domain: string;
  notes: string;
  status: string;
  createdBy: string | null;
  createdAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNotes: string | null;
}

const STALE_DAYS = 90;
const AUTO_FLAG_THRESHOLD = 3;

const SEEDED_SOURCE_RECORDS: SourceRecord[] = [
  {
    domain: "github.com",
    status: "legitimate",
    confidence: "high",
    reports: 12,
    addedDate: "2026-02-03T00:00:00.000Z",
    lastVerifiedAt: "2026-02-03T00:00:00.000Z",
    verifiedBy: "admin",
  },
  {
    domain: "obsproject.com",
    status: "legitimate",
    confidence: "high",
    reports: 7,
    addedDate: "2026-02-03T00:00:00.000Z",
    lastVerifiedAt: "2026-02-03T00:00:00.000Z",
    verifiedBy: "admin",
  },
  {
    domain: "ubuntu.com",
    status: "legitimate",
    confidence: "high",
    reports: 6,
    addedDate: "2026-02-03T00:00:00.000Z",
    lastVerifiedAt: "2026-02-03T00:00:00.000Z",
    verifiedBy: "admin",
  },
  {
    domain: "safecheck-phishing.example",
    status: "fake",
    confidence: "high",
    reports: 9,
    addedDate: "2026-02-03T00:00:00.000Z",
    lastVerifiedAt: "2026-02-03T00:00:00.000Z",
    verifiedBy: "admin",
  },
];

const seedSources = new Map<string, SourceRecord>(
  SEEDED_SOURCE_RECORDS.map((record) => [record.domain, record])
);

const seedReports: SiteReportItem[] = [];
let seedReportCounter = 1;

function normalizeDomain(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const parsed = new URL(withProtocol);
    const host = parsed.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    if (!host || host.includes(" ")) return null;
    return host;
  } catch {
    return null;
  }
}

function getDomainCandidates(domain: string): string[] {
  const parts = domain.split(".").filter(Boolean);
  const candidates = [domain];

  if (parts.length > 2) {
    candidates.push(parts.slice(-2).join("."));
  }

  return Array.from(new Set(candidates));
}

function toIso(value: string | null | undefined, fallback: string): string {
  if (!value) return fallback;
  const asDate = new Date(value);
  if (Number.isNaN(asDate.getTime())) return fallback;
  return asDate.toISOString();
}

function isStale(lastVerifiedAt: string): boolean {
  const verifiedAt = new Date(lastVerifiedAt).getTime();
  if (Number.isNaN(verifiedAt)) return true;
  const staleThresholdMs = STALE_DAYS * 24 * 60 * 60 * 1000;
  return Date.now() - verifiedAt > staleThresholdMs;
}

function resolveVerdict(status: SourceStatus, confidence: SourceConfidence): SourceVerdict {
  if (confidence === "low") return "unknown";
  if (status === "legitimate") return "verified";
  if (status === "fake") return "known-fake";
  return "unknown";
}

function buildResult(
  record: SourceRecord | null,
  requestedDomain: string,
  matchedDomain: string | null,
  backend: "supabase" | "seed"
): SourceCheckResult {
  if (!record) {
    return {
      domain: requestedDomain,
      matchedDomain,
      verdict: "unknown",
      status: "unknown",
      confidence: "low",
      reports: 0,
      stale: false,
      note: "This source is unknown. Proceed with caution and run file checks.",
      backend,
    };
  }

  const stale = isStale(record.lastVerifiedAt);
  const effectiveConfidence = stale ? "low" : record.confidence;
  const verdict = resolveVerdict(record.status, effectiveConfidence);

  let note = "This source is unknown. Proceed with caution and run file checks.";
  if (verdict === "verified") {
    note = "This source is verified in the SafeCheck database.";
  } else if (verdict === "known-fake") {
    note = "This source matches a known fake domain. Do not open files from it.";
  } else if (stale) {
    note = "This source entry is stale (not verified recently). Treat as unknown.";
  }

  return {
    domain: requestedDomain,
    matchedDomain,
    verdict,
    status: record.status,
    confidence: effectiveConfidence,
    reports: record.reports,
    stale,
    note,
    backend,
  };
}

function mapSupabaseSourceRow(row: Record<string, unknown>): SourceRecord {
  const nowIso = new Date().toISOString();

  return {
    domain: String(row.domain ?? ""),
    status: (row.status as SourceStatus) ?? "unknown",
    confidence: (row.confidence as SourceConfidence) ?? "low",
    reports: Number(row.reports ?? 0),
    addedDate: toIso(row.added_date as string | null | undefined, nowIso),
    lastVerifiedAt: toIso(row.last_verified_at as string | null | undefined, nowIso),
    verifiedBy: String(row.verified_by ?? "community"),
  };
}

function getSeedMatch(domain: string): { match: SourceRecord | null; matchedDomain: string | null } {
  const candidates = getDomainCandidates(domain);
  for (const candidate of candidates) {
    const matched = seedSources.get(candidate);
    if (matched) {
      return { match: matched, matchedDomain: candidate };
    }
  }
  return { match: null, matchedDomain: null };
}

export async function checkSource(input: string): Promise<SourceCheckResult> {
  const domain = normalizeDomain(input);
  if (!domain) {
    throw new Error("Please enter a valid URL or domain.");
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    const { match, matchedDomain } = getSeedMatch(domain);
    return buildResult(match, domain, matchedDomain, "seed");
  }

  const candidates = getDomainCandidates(domain);
  const { data, error } = await supabase
    .from("site_sources")
    .select("domain,status,confidence,reports,added_date,last_verified_at,verified_by")
    .in("domain", candidates)
    .limit(10);

  if (error) {
    throw new Error(`Source DB check failed: ${error.message}`);
  }

  const rows = (data ?? []) as Record<string, unknown>[];
  const exactMatch = rows.find((row) => String(row.domain) === domain);
  const firstMatch = exactMatch ?? rows[0];

  if (!firstMatch) {
    return buildResult(null, domain, null, "supabase");
  }

  const record = mapSupabaseSourceRow(firstMatch);
  return buildResult(record, domain, record.domain, "supabase");
}

export async function submitSiteReport(
  input: string,
  notes: string,
  createdBy: string | null
): Promise<SiteReportResponse> {
  const domain = normalizeDomain(input);
  if (!domain) {
    throw new Error("Please enter a valid URL or domain before reporting.");
  }

  const cleanNotes = notes.trim();
  if (!cleanNotes) {
    throw new Error("Please add a short reason for the report.");
  }

  if (cleanNotes.length > 1000) {
    throw new Error("Report notes are too long. Keep it under 1000 characters.");
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    const reportId = `seed-${seedReportCounter++}`;
    const pendingForDomain = seedReports.filter(
      (item) => item.domain === domain && (item.status === "pending" || item.status === "pending_review")
    ).length;
    const autoFlaggedForReview = pendingForDomain + 1 >= AUTO_FLAG_THRESHOLD;

    const report: SiteReportItem = {
      id: reportId,
      domain,
      notes: cleanNotes,
      status: autoFlaggedForReview ? "pending_review" : "pending",
      createdBy,
      createdAt: new Date().toISOString(),
      reviewedBy: null,
      reviewedAt: null,
      reviewNotes: null,
    };

    seedReports.push(report);

    const existing = seedSources.get(domain);
    if (existing) {
      existing.reports += 1;
      seedSources.set(domain, existing);
    } else {
      seedSources.set(domain, {
        domain,
        status: "unknown",
        confidence: "low",
        reports: 1,
        addedDate: new Date().toISOString(),
        lastVerifiedAt: new Date().toISOString(),
        verifiedBy: "community",
      });
    }

    return {
      id: reportId,
      domain,
      status: report.status,
      reportCountForDomain: pendingForDomain + 1,
      autoFlaggedForReview,
    };
  }

  const now = new Date().toISOString();
  const { data: inserted, error: insertError } = await supabase
    .from("site_reports")
    .insert({
      domain,
      notes: cleanNotes,
      status: "pending",
      created_by: createdBy,
      created_at: now,
    })
    .select("id")
    .single();

  if (insertError || !inserted) {
    throw new Error(`Report submission failed: ${insertError?.message ?? "Unknown insert error"}`);
  }

  const { data: pendingData, error: pendingError } = await supabase
    .from("site_reports")
    .select("id")
    .eq("domain", domain)
    .in("status", ["pending", "pending_review"]);

  if (pendingError) {
    throw new Error(`Failed to read report count: ${pendingError.message}`);
  }

  const reportCountForDomain = pendingData?.length ?? 1;
  const autoFlaggedForReview = reportCountForDomain >= AUTO_FLAG_THRESHOLD;

  if (autoFlaggedForReview) {
    const { error: flagError } = await supabase
      .from("site_reports")
      .update({ status: "pending_review" })
      .eq("domain", domain)
      .in("status", ["pending", "pending_review"]);

    if (flagError) {
      throw new Error(`Failed to auto-flag report queue: ${flagError.message}`);
    }
  }

  const { data: existingSource } = await supabase
    .from("site_sources")
    .select("domain,reports")
    .eq("domain", domain)
    .maybeSingle();

  if (existingSource) {
    await supabase
      .from("site_sources")
      .update({ reports: Number(existingSource.reports ?? 0) + 1 })
      .eq("domain", domain);
  } else {
    await supabase.from("site_sources").insert({
      domain,
      status: "unknown",
      confidence: "low",
      reports: 1,
      verified_by: "community",
      added_date: now,
      last_verified_at: now,
    });
  }

  return {
    id: String(inserted.id),
    domain,
    status: autoFlaggedForReview ? "pending_review" : "pending",
    reportCountForDomain,
    autoFlaggedForReview,
  };
}

export async function listSiteReports(
  status: string | null,
  limit: number
): Promise<SiteReportItem[]> {
  const safeLimit = Math.max(1, Math.min(limit, 100));
  const supabase = getSupabaseAdminClient();

  if (!supabase) {
    return seedReports
      .filter((item) => (status ? item.status === status : true))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, safeLimit);
  }

  let query = supabase
    .from("site_reports")
    .select("id,domain,notes,status,created_by,created_at,reviewed_by,reviewed_at,review_notes")
    .order("created_at", { ascending: false })
    .limit(safeLimit);

  if (status) {
    query = query.eq("status", status);
  }

  const { data, error } = await query;
  if (error) {
    throw new Error(`Failed to list site reports: ${error.message}`);
  }

  const rows = (data ?? []) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: String(row.id),
    domain: String(row.domain),
    notes: String(row.notes ?? ""),
    status: String(row.status ?? "pending"),
    createdBy: (row.created_by as string | null) ?? null,
    createdAt: String(row.created_at ?? ""),
    reviewedBy: (row.reviewed_by as string | null) ?? null,
    reviewedAt: (row.reviewed_at as string | null) ?? null,
    reviewNotes: (row.review_notes as string | null) ?? null,
  }));
}

function isConfidence(value: string | undefined): value is SourceConfidence {
  return value === "high" || value === "medium" || value === "low";
}

function isSourceStatus(value: string | undefined): value is SourceStatus {
  return value === "legitimate" || value === "fake" || value === "unknown";
}

export async function moderateSiteReport(
  input: SiteReportModerationInput
): Promise<SiteReportModerationResult> {
  const supabase = getSupabaseAdminClient();
  const reviewedBy = input.reviewedBy?.trim() || "moderator";
  const reviewNotes = input.reviewNotes?.trim() || null;
  const now = new Date().toISOString();

  if (!input.reportId.trim()) {
    throw new Error("Missing report id.");
  }

  if (!["approve", "reject", "needs_more_data"].includes(input.decision)) {
    throw new Error("Invalid moderation decision.");
  }

  if (supabase) {
    const { data: report, error: readError } = await supabase
      .from("site_reports")
      .select("id,domain")
      .eq("id", input.reportId)
      .single();

    if (readError || !report) {
      throw new Error(`Unable to load report: ${readError?.message ?? "Report not found"}`);
    }

    const statusMap: Record<SiteReportModerationInput["decision"], string> = {
      approve: "approved",
      reject: "rejected",
      needs_more_data: "needs_more_data",
    };

    const finalStatus = statusMap[input.decision];

    const { error: updateError } = await supabase
      .from("site_reports")
      .update({
        status: finalStatus,
        reviewed_by: reviewedBy,
        reviewed_at: now,
        review_notes: reviewNotes,
      })
      .eq("id", input.reportId);

    if (updateError) {
      throw new Error(`Failed to update report status: ${updateError.message}`);
    }

    if (input.decision !== "approve") {
      return {
        reportId: input.reportId,
        domain: String(report.domain),
        status: finalStatus,
      };
    }

    const sourceStatus = isSourceStatus(input.sourceStatus) ? input.sourceStatus : "unknown";
    const confidence = isConfidence(input.confidence) ? input.confidence : "medium";

    const { data: domainReports } = await supabase.from("site_reports").select("id").eq("domain", report.domain);
    const reportCount = domainReports?.length ?? 1;

    const { error: upsertError } = await supabase.from("site_sources").upsert(
      {
        domain: report.domain,
        status: sourceStatus,
        confidence,
        reports: reportCount,
        verified_by: "admin",
        last_verified_at: now,
        added_date: now,
      },
      { onConflict: "domain" }
    );

    if (upsertError) {
      throw new Error(`Failed to upsert source record: ${upsertError.message}`);
    }

    const checked = await checkSource(String(report.domain));
    return {
      reportId: input.reportId,
      domain: String(report.domain),
      status: finalStatus,
      source: checked,
    };
  }

  const reportIndex = seedReports.findIndex((item) => item.id === input.reportId);
  if (reportIndex === -1) {
    throw new Error("Report not found.");
  }

  const report = seedReports[reportIndex];
  const statusMap: Record<SiteReportModerationInput["decision"], string> = {
    approve: "approved",
    reject: "rejected",
    needs_more_data: "needs_more_data",
  };
  const finalStatus = statusMap[input.decision];
  report.status = finalStatus;
  report.reviewedBy = reviewedBy;
  report.reviewedAt = now;
  report.reviewNotes = reviewNotes;
  seedReports[reportIndex] = report;

  if (input.decision !== "approve") {
    return {
      reportId: input.reportId,
      domain: report.domain,
      status: finalStatus,
    };
  }

  const sourceStatus = isSourceStatus(input.sourceStatus) ? input.sourceStatus : "unknown";
  const confidence = isConfidence(input.confidence) ? input.confidence : "medium";
  const existing = seedSources.get(report.domain);
  const reportCount = seedReports.filter((item) => item.domain === report.domain).length;

  seedSources.set(report.domain, {
    domain: report.domain,
    status: sourceStatus,
    confidence,
    reports: reportCount,
    addedDate: existing?.addedDate ?? now,
    lastVerifiedAt: now,
    verifiedBy: "admin",
  });

  const checked = await checkSource(report.domain);
  return {
    reportId: input.reportId,
    domain: report.domain,
    status: finalStatus,
    source: checked,
  };
}
