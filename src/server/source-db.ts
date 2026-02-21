import { getSupabaseAdminClient } from "@/lib/supabase/server";
import { checkGoogleSafeBrowsing, type SourceThreatIntelResult } from "@/server/source-threat-intel";

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
  categories: string[];
  threatTypes: string[];
  intelProvider: string | null;
}

export interface SiteReportResponse {
  id: string;
  domain: string;
  status: string;
  reportCountForDomain: number;
  autoFlaggedForReview: boolean;
  automatedDecision: "auto_fake_threat_intel" | "auto_fake_consensus" | "needs_more_data";
  moderationSummary: string;
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

function isMissingTableError(errorMessage: string, tableName: string): boolean {
  const lower = errorMessage.toLowerCase();
  const normalizedTable = tableName.toLowerCase();
  return (
    (lower.includes("could not find the table") && lower.includes(normalizedTable)) ||
    (lower.includes("schema cache") && lower.includes(normalizedTable)) ||
    lower.includes(`relation "public.${normalizedTable}" does not exist`)
  );
}

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

function normalizeLookupUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.toString();
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
  backend: "supabase" | "seed",
  noteOverride?: string,
  categories: string[] = [],
  threatTypes: string[] = [],
  intelProvider: string | null = null
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
      categories,
      threatTypes,
      intelProvider,
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

  if (noteOverride) {
    note = noteOverride;
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
    categories,
    threatTypes,
    intelProvider,
  };
}

function buildCategorySignals(
  status: SourceStatus,
  confidence: SourceConfidence,
  sourceIntel: SourceThreatIntelResult | null
): { categories: string[]; threatTypes: string[]; intelProvider: string | null } {
  const categories: string[] = [];
  const threatTypes = sourceIntel?.threatTypes ?? [];
  const intelProvider = sourceIntel?.provider ?? null;

  if (sourceIntel?.status === "match") {
    categories.push("Threat Intelligence / Reputation Checks");
  }

  if (
    sourceIntel?.status === "match" ||
    (status === "fake" && (confidence === "high" || confidence === "medium"))
  ) {
    categories.push("Web Risk Assessment");
  }

  return {
    categories,
    threatTypes,
    intelProvider,
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

function checkSourceWithSeedBackend(
  domain: string,
  sourceIntel: SourceThreatIntelResult | null
): SourceCheckResult {
  const now = new Date().toISOString();

  if (sourceIntel?.status === "match") {
    const existing = seedSources.get(domain);
    const seeded: SourceRecord = {
      domain,
      status: "fake",
      confidence: "high",
      reports: existing?.reports ?? 0,
      addedDate: existing?.addedDate ?? now,
      lastVerifiedAt: now,
      verifiedBy: sourceIntel.provider,
    };

    seedSources.set(domain, seeded);
    const signals = buildCategorySignals(seeded.status, seeded.confidence, sourceIntel);
    return buildResult(
      seeded,
      domain,
      domain,
      "seed",
      sourceIntel.note,
      signals.categories,
      signals.threatTypes,
      signals.intelProvider
    );
  }

  const { match, matchedDomain } = getSeedMatch(domain);
  if (match) {
    const override = match.status === "unknown" ? sourceIntel?.note : undefined;
    const signals = buildCategorySignals(match.status, match.confidence, sourceIntel);
    return buildResult(
      match,
      domain,
      matchedDomain,
      "seed",
      override,
      signals.categories,
      signals.threatTypes,
      signals.intelProvider
    );
  }

  const trackedUnknown: SourceRecord = {
    domain,
    status: "unknown",
    confidence: "low",
    reports: 0,
    addedDate: now,
    lastVerifiedAt: now,
    verifiedBy: sourceIntel?.provider ?? "auto-check",
  };

  seedSources.set(domain, trackedUnknown);
  const signals = buildCategorySignals(trackedUnknown.status, trackedUnknown.confidence, sourceIntel);
  return buildResult(
    trackedUnknown,
    domain,
    domain,
    "seed",
    sourceIntel?.note,
    signals.categories,
    signals.threatTypes,
    signals.intelProvider
  );
}

export async function checkSource(input: string): Promise<SourceCheckResult> {
  const domain = normalizeDomain(input);
  if (!domain) {
    throw new Error("Please enter a valid URL or domain.");
  }

  const lookupUrl = normalizeLookupUrl(input);
  if (!lookupUrl) {
    throw new Error("Please enter a valid URL or domain.");
  }

  const sourceIntel = await checkGoogleSafeBrowsing(lookupUrl);

  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    return checkSourceWithSeedBackend(domain, sourceIntel);
  }

  const candidates = getDomainCandidates(domain);
  const { data, error } = await supabase
    .from("site_sources")
    .select("domain,status,confidence,reports,added_date,last_verified_at,verified_by")
    .in("domain", candidates)
    .limit(10);

  if (error) {
    if (isMissingTableError(error.message, "site_sources")) {
      return checkSourceWithSeedBackend(domain, sourceIntel);
    }
    throw new Error(`Source DB check failed: ${error.message}`);
  }

  const rows = (data ?? []) as Record<string, unknown>[];
  const exactMatch = rows.find((row) => String(row.domain) === domain);
  const firstMatch = exactMatch ?? rows[0];

  if (sourceIntel?.status === "match") {
    const now = new Date().toISOString();
    const existing = exactMatch ? mapSupabaseSourceRow(exactMatch) : null;
    const reports = existing?.reports ?? 0;
    const addedDate = existing?.addedDate ?? now;

    const { error: upsertError } = await supabase.from("site_sources").upsert(
      {
        domain,
        status: "fake",
        confidence: "high",
        reports,
        verified_by: sourceIntel.provider,
        added_date: addedDate,
        last_verified_at: now,
        updated_at: now,
      },
      { onConflict: "domain" }
    );

    if (upsertError) {
      if (isMissingTableError(upsertError.message, "site_sources")) {
        return checkSourceWithSeedBackend(domain, sourceIntel);
      }
      throw new Error(`Source DB check failed: ${upsertError.message}`);
    }

    const trackedRecord: SourceRecord = {
      domain,
      status: "fake",
      confidence: "high",
      reports,
      addedDate,
      lastVerifiedAt: now,
      verifiedBy: sourceIntel.provider,
    };

    const signals = buildCategorySignals(trackedRecord.status, trackedRecord.confidence, sourceIntel);
    return buildResult(
      trackedRecord,
      domain,
      domain,
      "supabase",
      sourceIntel.note,
      signals.categories,
      signals.threatTypes,
      signals.intelProvider
    );
  }

  if (!firstMatch) {
    const now = new Date().toISOString();
    const trackedRecord: SourceRecord = {
      domain,
      status: "unknown",
      confidence: "low",
      reports: 0,
      addedDate: now,
      lastVerifiedAt: now,
      verifiedBy: sourceIntel?.provider ?? "auto-check",
    };

    const { error: upsertError } = await supabase.from("site_sources").upsert(
      {
        domain,
        status: "unknown",
        confidence: "low",
        reports: 0,
        verified_by: sourceIntel?.provider ?? "auto-check",
        added_date: now,
        last_verified_at: now,
        updated_at: now,
      },
      { onConflict: "domain", ignoreDuplicates: true }
    );

    if (upsertError) {
      if (isMissingTableError(upsertError.message, "site_sources")) {
        return checkSourceWithSeedBackend(domain, sourceIntel);
      }

      throw new Error(`Source DB check failed: ${upsertError.message}`);
    }

    const signals = buildCategorySignals(trackedRecord.status, trackedRecord.confidence, sourceIntel);
    return buildResult(
      trackedRecord,
      domain,
      domain,
      "supabase",
      sourceIntel?.note,
      signals.categories,
      signals.threatTypes,
      signals.intelProvider
    );
  }

  const record = mapSupabaseSourceRow(firstMatch);
  const noteOverride = record.status === "unknown" ? sourceIntel?.note : undefined;
  const signals = buildCategorySignals(record.status, record.confidence, sourceIntel);
  return buildResult(
    record,
    domain,
    record.domain,
    "supabase",
    noteOverride,
    signals.categories,
    signals.threatTypes,
    signals.intelProvider
  );
}

type AutomatedModerationDecision = "auto_fake_threat_intel" | "auto_fake_consensus" | "needs_more_data";

interface AutomatedModerationPlan {
  decision: AutomatedModerationDecision;
  reportStatus: "approved" | "needs_more_data";
  sourceStatus: SourceStatus;
  confidence: SourceConfidence;
  verifiedBy: string;
  reviewNotes: string;
}

function buildAutomatedModerationPlan(
  reportCountForDomain: number,
  sourceIntel: SourceThreatIntelResult | null
): AutomatedModerationPlan {
  if (sourceIntel?.status === "match") {
    return {
      decision: "auto_fake_threat_intel",
      reportStatus: "approved",
      sourceStatus: "fake",
      confidence: "high",
      verifiedBy: sourceIntel.provider,
      reviewNotes: `Auto-approved as fake via ${sourceIntel.provider} (${sourceIntel.threatTypes.join(", ")}).`,
    };
  }

  if (reportCountForDomain >= AUTO_FLAG_THRESHOLD) {
    return {
      decision: "auto_fake_consensus",
      reportStatus: "approved",
      sourceStatus: "fake",
      confidence: "medium",
      verifiedBy: "auto-consensus",
      reviewNotes: `Auto-approved as fake via community consensus threshold (${reportCountForDomain} reports).`,
    };
  }

  return {
    decision: "needs_more_data",
    reportStatus: "needs_more_data",
    sourceStatus: "unknown",
    confidence: "low",
    verifiedBy: sourceIntel?.provider ?? "auto-check",
    reviewNotes: `Insufficient evidence. Waiting for more reports (current: ${reportCountForDomain}).`,
  };
}

function buildAutomatedModerationSummary(plan: AutomatedModerationPlan): string {
  if (plan.decision === "auto_fake_threat_intel") {
    return "Auto-moderation marked this domain as fake using threat intelligence.";
  }

  if (plan.decision === "auto_fake_consensus") {
    return "Auto-moderation marked this domain as fake using community consensus.";
  }

  return "Report accepted. Domain stays unknown until more evidence is collected.";
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

  const lookupUrl = normalizeLookupUrl(input);
  if (!lookupUrl) {
    throw new Error("Please enter a valid URL or domain before reporting.");
  }

  const cleanNotes = notes.trim();
  if (!cleanNotes) {
    throw new Error("Please add a short reason for the report.");
  }

  if (cleanNotes.length > 1000) {
    throw new Error("Report notes are too long. Keep it under 1000 characters.");
  }

  let sourceIntel: SourceThreatIntelResult | null = null;
  try {
    sourceIntel = await checkGoogleSafeBrowsing(lookupUrl);
  } catch (error) {
    console.warn("Threat intel check failed during report submission:", error);
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    const now = new Date().toISOString();
    const reportId = `seed-${seedReportCounter++}`;
    const existingReportsForDomain = seedReports.filter((item) => item.domain === domain).length;
    const reportCountForDomain = existingReportsForDomain + 1;
    const plan = buildAutomatedModerationPlan(reportCountForDomain, sourceIntel);

    const report: SiteReportItem = {
      id: reportId,
      domain,
      notes: cleanNotes,
      status: plan.reportStatus,
      createdBy,
      createdAt: now,
      reviewedBy: "auto-bot",
      reviewedAt: now,
      reviewNotes: plan.reviewNotes,
    };

    seedReports.push(report);

    const existing = seedSources.get(domain);
    const nextReports = (existing?.reports ?? 0) + 1;
    const nextStatus =
      plan.sourceStatus === "fake" ? "fake" : ((existing?.status ?? "unknown") as SourceStatus);
    const nextConfidence =
      plan.sourceStatus === "fake" ? plan.confidence : ((existing?.confidence ?? "low") as SourceConfidence);
    const verifiedBy =
      plan.sourceStatus === "fake"
        ? plan.verifiedBy
        : sourceIntel?.provider ?? existing?.verifiedBy ?? "auto-check";

    seedSources.set(domain, {
      domain,
      status: nextStatus,
      confidence: nextConfidence,
      reports: nextReports,
      addedDate: existing?.addedDate ?? now,
      lastVerifiedAt: now,
      verifiedBy,
    });

    const moderationSummary = buildAutomatedModerationSummary(plan);

    return {
      id: reportId,
      domain,
      status: report.status,
      reportCountForDomain,
      autoFlaggedForReview: plan.decision !== "needs_more_data",
      automatedDecision: plan.decision,
      moderationSummary,
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
      updated_at: now,
    })
    .select("id")
    .single();

  if (insertError || !inserted) {
    throw new Error(`Report submission failed: ${insertError?.message ?? "Unknown insert error"}`);
  }

  const { data: reportCountRows, error: reportCountError } = await supabase
    .from("site_reports")
    .select("id")
    .eq("domain", domain);

  if (reportCountError) {
    throw new Error(`Failed to read report count: ${reportCountError.message}`);
  }

  const reportCountForDomain = reportCountRows?.length ?? 1;
  const plan = buildAutomatedModerationPlan(reportCountForDomain, sourceIntel);
  const moderationSummary = buildAutomatedModerationSummary(plan);

  const { error: reportUpdateError } = await supabase
    .from("site_reports")
    .update({
      status: plan.reportStatus,
      reviewed_by: "auto-bot",
      reviewed_at: now,
      review_notes: plan.reviewNotes,
      updated_at: now,
    })
    .eq("id", inserted.id);

  if (reportUpdateError) {
    throw new Error(`Failed to apply automated moderation: ${reportUpdateError.message}`);
  }

  const { data: existingSource, error: existingSourceError } = await supabase
    .from("site_sources")
    .select("domain,status,confidence,reports,added_date,verified_by")
    .eq("domain", domain)
    .maybeSingle();

  if (existingSourceError) {
    throw new Error(`Failed to load source record: ${existingSourceError.message}`);
  }

  if (plan.sourceStatus === "fake") {
    const addedDate = toIso(
      (existingSource as Record<string, unknown> | null)?.added_date as string | null | undefined,
      now
    );
    const { error: sourceUpsertError } = await supabase.from("site_sources").upsert(
      {
        domain,
        status: "fake",
        confidence: plan.confidence,
        reports: reportCountForDomain,
        verified_by: plan.verifiedBy,
        added_date: addedDate,
        last_verified_at: now,
        updated_at: now,
      },
      { onConflict: "domain" }
    );

    if (sourceUpsertError) {
      throw new Error(`Failed to update source after auto-moderation: ${sourceUpsertError.message}`);
    }
  } else {
    if (existingSource) {
      const { error: sourceUpdateError } = await supabase
        .from("site_sources")
        .update({
          reports: reportCountForDomain,
          updated_at: now,
        })
        .eq("domain", domain);

      if (sourceUpdateError) {
        throw new Error(`Failed to update source report count: ${sourceUpdateError.message}`);
      }
    } else {
      const { error: sourceInsertError } = await supabase.from("site_sources").insert({
        domain,
        status: "unknown",
        confidence: "low",
        reports: reportCountForDomain,
        verified_by: sourceIntel?.provider ?? "auto-check",
        added_date: now,
        last_verified_at: now,
        updated_at: now,
      });

      if (sourceInsertError) {
        throw new Error(`Failed to create source record: ${sourceInsertError.message}`);
      }
    }
  }

  return {
    id: String(inserted.id),
    domain,
    status: plan.reportStatus,
    reportCountForDomain,
    autoFlaggedForReview: plan.decision !== "needs_more_data",
    automatedDecision: plan.decision,
    moderationSummary,
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
