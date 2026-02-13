import { scoreVirusTotalResult } from "@/features/file-safety/verdict/scoring";
import type { VirusTotalFileResult } from "@/features/file-safety/types";
import { getSupabaseAdminClient } from "@/lib/supabase/server";

function isVirusTotalFileResult(value: unknown): value is VirusTotalFileResult {
  if (!value || typeof value !== "object") return false;
  const record = value as { data?: { attributes?: { sha256?: unknown } } };
  return typeof record.data?.attributes?.sha256 === "string";
}

export async function persistScanHistoryIfConfigured(payload: unknown): Promise<void> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) return;
  if (!isVirusTotalFileResult(payload)) return;

  const score = scoreVirusTotalResult(payload);
  const stats = payload.data.attributes.last_analysis_stats;

  const { error } = await supabase.from("scan_history").insert({
    sha256: payload.data.attributes.sha256,
    verdict: score.verdict,
    total_score: score.totalScore,
    malicious_count: stats.malicious,
    suspicious_count: stats.suspicious,
    harmless_count: stats.harmless,
    undetected_count: stats.undetected,
    source: "virustotal",
    created_at: new Date().toISOString(),
  });

  if (error) {
    console.error("Supabase scan_history insert failed:", error.message);
  }
}
