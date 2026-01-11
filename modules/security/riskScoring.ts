/**
 * Risk Scoring Engine
 *
 * Calculates comprehensive risk scores for addresses,
 * transactions, and contracts
 */

import {
  RiskLevel,
  RiskScore,
  RiskFactor,
  SECURITY_THRESHOLDS,
} from "../../utils/constants";

// ===========================================
//          Risk Score Calculation
// ===========================================

/**
 * Calculate weighted risk score from multiple factors
 */
export function calculateRiskScore(factors: RiskFactor[]): RiskScore {
  if (factors.length === 0) {
    return {
      level: RiskLevel.SAFE,
      score: 0,
      factors: [],
      recommendation: "No risk factors identified.",
    };
  }

  // Calculate weighted score based on severity and impact
  let totalScore = 0;
  const severityWeights: Record<RiskLevel, number> = {
    [RiskLevel.CRITICAL]: 1.5,
    [RiskLevel.HIGH]: 1.25,
    [RiskLevel.MEDIUM]: 1.0,
    [RiskLevel.LOW]: 0.75,
    [RiskLevel.SAFE]: 0.5,
  };

  for (const factor of factors) {
    const weight = severityWeights[factor.severity] || 1.0;
    totalScore += factor.impact * weight;
  }

  // Normalize to 0-100 scale
  const normalizedScore = Math.min(100, Math.round(totalScore));

  // Determine risk level
  const level = getRiskLevelFromScore(normalizedScore);
  const recommendation = getRecommendationFromLevel(level, factors);

  return {
    level,
    score: normalizedScore,
    factors,
    recommendation,
  };
}

/**
 * Combine multiple risk scores into a single aggregate score
 */
export function aggregateRiskScores(scores: RiskScore[]): RiskScore {
  if (scores.length === 0) {
    return calculateRiskScore([]);
  }

  // Combine all factors
  const allFactors: RiskFactor[] = [];
  for (const score of scores) {
    allFactors.push(...score.factors);
  }

  // Use highest score as base
  const maxScore = Math.max(...scores.map((s) => s.score));
  const avgScore =
    scores.reduce((sum, s) => sum + s.score, 0) / scores.length;

  // Weighted combination: 70% max, 30% average
  const combinedScore = Math.round(maxScore * 0.7 + avgScore * 0.3);
  const level = getRiskLevelFromScore(combinedScore);

  return {
    level,
    score: combinedScore,
    factors: allFactors,
    recommendation: getRecommendationFromLevel(level, allFactors),
  };
}

// ===========================================
//          Risk Level Determination
// ===========================================

/**
 * Get risk level from numeric score
 */
export function getRiskLevelFromScore(score: number): RiskLevel {
  if (score >= SECURITY_THRESHOLDS.BLOCK_TRANSACTION_SCORE) {
    return RiskLevel.CRITICAL;
  }
  if (score >= SECURITY_THRESHOLDS.WARN_TRANSACTION_SCORE) {
    return RiskLevel.HIGH;
  }
  if (score >= SECURITY_THRESHOLDS.REVIEW_TRANSACTION_SCORE) {
    return RiskLevel.MEDIUM;
  }
  if (score > 0) {
    return RiskLevel.LOW;
  }
  return RiskLevel.SAFE;
}

/**
 * Get recommendation text based on risk level
 */
function getRecommendationFromLevel(
  level: RiskLevel,
  factors: RiskFactor[]
): string {
  const criticalFactors = factors.filter(
    (f) => f.severity === RiskLevel.CRITICAL
  );
  const highFactors = factors.filter((f) => f.severity === RiskLevel.HIGH);

  switch (level) {
    case RiskLevel.CRITICAL:
      return `CRITICAL RISK: ${criticalFactors.length} critical issue(s) detected. Do not proceed without expert review. Issues: ${criticalFactors.map((f) => f.type).join(", ")}`;

    case RiskLevel.HIGH:
      return `HIGH RISK: ${highFactors.length + criticalFactors.length} significant issue(s) detected. Proceed with extreme caution. Manual verification recommended.`;

    case RiskLevel.MEDIUM:
      return `MODERATE RISK: Some concerns identified. Review all risk factors before proceeding.`;

    case RiskLevel.LOW:
      return `LOW RISK: Minor issues detected. Generally safe to proceed with normal caution.`;

    case RiskLevel.SAFE:
      return `SAFE: No significant risks identified. Safe to proceed.`;

    default:
      return "Unable to determine risk level.";
  }
}

// ===========================================
//          Specialized Scoring
// ===========================================

/**
 * Score for address-specific risks
 */
export function scoreAddressRisk(params: {
  isContract: boolean;
  isVerified: boolean;
  transactionCount: number;
  isSanctioned: boolean;
  isLabeled: boolean;
  labelType?: string;
}): RiskScore {
  const factors: RiskFactor[] = [];

  if (params.isSanctioned) {
    factors.push({
      type: "sanctioned_address",
      severity: RiskLevel.CRITICAL,
      description: "Address is on a sanctions list.",
      impact: 100,
    });
  }

  if (params.isContract && !params.isVerified) {
    factors.push({
      type: "unverified_contract",
      severity: RiskLevel.MEDIUM,
      description: "Contract source code is not verified.",
      impact: 25,
    });
  }

  if (params.transactionCount < 5) {
    factors.push({
      type: "new_address",
      severity: RiskLevel.LOW,
      description: "Address has very few transactions.",
      impact: 10,
    });
  }

  if (params.labelType === "scam" || params.labelType === "phishing") {
    factors.push({
      type: "labeled_malicious",
      severity: RiskLevel.CRITICAL,
      description: `Address labeled as ${params.labelType}.`,
      impact: 90,
    });
  }

  if (params.labelType === "mixer") {
    factors.push({
      type: "mixer_interaction",
      severity: RiskLevel.HIGH,
      description: "Address associated with mixing service.",
      impact: 40,
    });
  }

  return calculateRiskScore(factors);
}

/**
 * Score for token-specific risks
 */
export function scoreTokenRisk(params: {
  isVerified: boolean;
  isHoneypot: boolean;
  isMintable: boolean;
  hasTaxes: boolean;
  taxPercentage?: number;
  hasBlacklist: boolean;
  isPausable: boolean;
  ownerHoldsPercentage: number;
}): RiskScore {
  const factors: RiskFactor[] = [];

  if (params.isHoneypot) {
    factors.push({
      type: "honeypot",
      severity: RiskLevel.CRITICAL,
      description: "Token appears to be a honeypot - sells may be blocked.",
      impact: 100,
    });
  }

  if (!params.isVerified) {
    factors.push({
      type: "unverified_token",
      severity: RiskLevel.HIGH,
      description: "Token contract is not verified.",
      impact: 30,
    });
  }

  if (params.hasTaxes) {
    const taxImpact = Math.min(40, (params.taxPercentage || 5) * 4);
    factors.push({
      type: "token_taxes",
      severity: params.taxPercentage && params.taxPercentage > 10 ? RiskLevel.HIGH : RiskLevel.MEDIUM,
      description: `Token has ${params.taxPercentage || "unknown"}% taxes on transfers.`,
      impact: taxImpact,
    });
  }

  if (params.hasBlacklist) {
    factors.push({
      type: "blacklist_capability",
      severity: RiskLevel.MEDIUM,
      description: "Owner can blacklist addresses from trading.",
      impact: 20,
    });
  }

  if (params.isPausable) {
    factors.push({
      type: "pausable",
      severity: RiskLevel.LOW,
      description: "Token transfers can be paused by owner.",
      impact: 15,
    });
  }

  if (params.isMintable) {
    factors.push({
      type: "mintable",
      severity: RiskLevel.MEDIUM,
      description: "Additional tokens can be minted.",
      impact: 20,
    });
  }

  if (params.ownerHoldsPercentage > 50) {
    factors.push({
      type: "concentrated_ownership",
      severity: RiskLevel.HIGH,
      description: `Owner holds ${params.ownerHoldsPercentage}% of supply.`,
      impact: 35,
    });
  } else if (params.ownerHoldsPercentage > 20) {
    factors.push({
      type: "high_ownership",
      severity: RiskLevel.MEDIUM,
      description: `Owner holds ${params.ownerHoldsPercentage}% of supply.`,
      impact: 20,
    });
  }

  return calculateRiskScore(factors);
}

// ===========================================
//          Risk Score Display
// ===========================================

/**
 * Format risk score for display
 */
export function formatRiskScore(score: RiskScore): {
  emoji: string;
  color: string;
  label: string;
  summary: string;
} {
  const levelConfig: Record<
    RiskLevel,
    { emoji: string; color: string; label: string }
  > = {
    [RiskLevel.CRITICAL]: { emoji: "🔴", color: "#dc2626", label: "Critical" },
    [RiskLevel.HIGH]: { emoji: "🟠", color: "#ea580c", label: "High" },
    [RiskLevel.MEDIUM]: { emoji: "🟡", color: "#ca8a04", label: "Medium" },
    [RiskLevel.LOW]: { emoji: "🟢", color: "#16a34a", label: "Low" },
    [RiskLevel.SAFE]: { emoji: "✅", color: "#22c55e", label: "Safe" },
  };

  const config = levelConfig[score.level];

  return {
    ...config,
    summary: `${config.emoji} ${config.label} Risk (Score: ${score.score}/100)`,
  };
}
