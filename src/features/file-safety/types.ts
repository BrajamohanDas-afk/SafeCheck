export type ScanStatus =
  | "idle"
  | "hashing"
  | "checking-cache"
  | "uploading"
  | "complete"
  | "error";

export type Verdict = "safe" | "suspicious" | "dangerous";

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
          result: string | null;
        }
      >;
      meaningful_name?: string;
      sha256: string;
      size: number;
      type_tag?: string;
    };
    links?: {
      self?: string;
    };
  };
  error?: {
    code: string;
    message: string;
  };
}

export type EngineTier = "tier1" | "tier2" | "tier3";
export type RiskCategory = "generic" | "suspicious" | "dangerous";

export interface ScoreContributor {
  engine: string;
  tier: EngineTier;
  result: string;
  riskCategory: RiskCategory;
  points: number;
  reason: string;
}

export interface VerdictScoreBreakdown {
  verdict: Verdict;
  totalScore: number;
  topContributors: ScoreContributor[];
  ignoredGenericFlags: ScoreContributor[];
}

export interface HashCompareResult {
  status: "idle" | "invalid" | "waiting-file-hash" | "match" | "mismatch";
  normalizedInput: string;
  message: string;
}

export interface TorrentFileEntry {
  path: string;
  size: number;
  extension: string;
}

export interface TorrentAnomaly {
  id: string;
  label: string;
  details: string;
}

export interface TorrentAnalysisResult {
  source: "torrent-file" | "magnet-link";
  name: string;
  infoHash?: string;
  trackerCount: number;
  totalSize: number;
  files: TorrentFileEntry[];
  anomalies: TorrentAnomaly[];
}

export type SourceStatus = "legitimate" | "fake" | "unknown";
export type SourceConfidence = "high" | "medium" | "low";
export type SourceVerdict = "verified" | "known-fake" | "unknown";

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

export interface MissingFileDetectionResult {
  expectedCount: number;
  actualCount: number;
  missingFiles: string[];
  unexpectedFiles: string[];
  likelyQuarantined: string[];
}
