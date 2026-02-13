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
