import type {
  EngineTier,
  RiskCategory,
  ScoreContributor,
  Verdict,
  VerdictScoreBreakdown,
  VirusTotalFileResult,
} from "../types";

const TIER_1_ENGINES = new Set([
  "kaspersky",
  "bitdefender",
  "avast",
  "norton",
  "sophos",
  "malwarebytes",
  "eset",
]);

const TIER_2_ENGINES = new Set([
  "trend micro",
  "f-secure",
  "panda",
  "webroot",
  "totaldefense",
  "mcafee",
]);

const GENERIC_KEYWORDS = ["hacktool", "crack", "keygen", "potentiallyunwanted", "hacked"];
const SUSPICIOUS_KEYWORDS = ["adware", "bundler", "dropper", "pup", "grayware"];
const DANGEROUS_KEYWORDS = [
  "ransomware",
  "trojan.stealer",
  "trojan",
  "stealer",
  "miner",
  "worm",
  "backdoor",
  "rat",
  "exploit",
];

const TIER_WEIGHT: Record<EngineTier, number> = {
  tier1: 3,
  tier2: 2,
  tier3: 1,
};

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

function getEngineTier(engineName: string): EngineTier {
  const engine = normalize(engineName);
  if (TIER_1_ENGINES.has(engine)) return "tier1";
  if (TIER_2_ENGINES.has(engine)) return "tier2";
  return "tier3";
}

function detectRiskCategory(result: string, vtCategory: string): RiskCategory {
  const normalizedResult = normalize(result);

  if (GENERIC_KEYWORDS.some((keyword) => normalizedResult.includes(keyword))) {
    return "generic";
  }

  if (DANGEROUS_KEYWORDS.some((keyword) => normalizedResult.includes(keyword))) {
    return "dangerous";
  }

  if (SUSPICIOUS_KEYWORDS.some((keyword) => normalizedResult.includes(keyword))) {
    return "suspicious";
  }

  const normalizedCategory = normalize(vtCategory);
  if (normalizedCategory === "malicious") return "dangerous";
  if (normalizedCategory === "suspicious") return "suspicious";
  return "generic";
}

function calculatePoints(tier: EngineTier, riskCategory: RiskCategory): number {
  const baseWeight = TIER_WEIGHT[tier];

  if (riskCategory === "dangerous") return baseWeight;
  if (riskCategory === "suspicious") return baseWeight * 0.5;
  return 0;
}

function getVerdictFromScore(totalScore: number): Verdict {
  if (totalScore >= 10) return "dangerous";
  if (totalScore >= 5) return "suspicious";
  return "safe";
}

function createReason(tier: EngineTier, riskCategory: RiskCategory): string {
  if (riskCategory === "dangerous") {
    return `${tier.toUpperCase()} engine raised a dangerous classification`;
  }

  if (riskCategory === "suspicious") {
    return `${tier.toUpperCase()} engine raised a suspicious classification`;
  }

  return "Generic crack-related classification ignored";
}

export function scoreVirusTotalResult(
  result: VirusTotalFileResult
): VerdictScoreBreakdown {
  const rawResults = result.data.attributes.last_analysis_results ?? {};
  const contributingFlags: ScoreContributor[] = [];
  const ignoredGenericFlags: ScoreContributor[] = [];

  Object.values(rawResults).forEach((engineResult) => {
    if (!engineResult?.result) return;

    const tier = getEngineTier(engineResult.engine_name);
    const riskCategory = detectRiskCategory(engineResult.result, engineResult.category ?? "");
    const points = calculatePoints(tier, riskCategory);

    const contributor: ScoreContributor = {
      engine: engineResult.engine_name,
      tier,
      result: engineResult.result,
      riskCategory,
      points,
      reason: createReason(tier, riskCategory),
    };

    if (points > 0) {
      contributingFlags.push(contributor);
      return;
    }

    ignoredGenericFlags.push(contributor);
  });

  contributingFlags.sort((a, b) => {
    if (b.points !== a.points) return b.points - a.points;
    return a.engine.localeCompare(b.engine);
  });

  const totalScore = contributingFlags.reduce((sum, item) => sum + item.points, 0);

  return {
    verdict: getVerdictFromScore(totalScore),
    totalScore,
    topContributors: contributingFlags.slice(0, 3),
    ignoredGenericFlags: ignoredGenericFlags.slice(0, 5),
  };
}
