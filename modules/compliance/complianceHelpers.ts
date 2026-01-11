/**
 * Ethereum Secure Platform - Compliance Helpers
 *
 * Utilities for regulatory compliance and reporting
 */

import { PublicClient } from "viem";
import { checkSanctions } from "../security/sanctionsChecker";
import { analyzeAddress } from "../security/addressAnalyzer";
import { RiskLevel, SECURITY_THRESHOLDS } from "../../utils/constants";

/**
 * Travel Rule compliance data structure
 */
export interface TravelRuleData {
  originator: {
    name?: string;
    address: string;
    vatpName?: string; // Virtual Asset Transfer Provider
    country?: string;
  };
  beneficiary: {
    name?: string;
    address: string;
    vatpName?: string;
    country?: string;
  };
  transaction: {
    amount: string;
    currency: string;
    txHash?: string;
    timestamp?: string;
  };
}

/**
 * KYC/AML status for an address
 */
export interface AddressComplianceStatus {
  address: string;
  isCompliant: boolean;
  kycVerified: boolean;
  riskLevel: RiskLevel;
  sanctionsStatus: {
    checked: boolean;
    isSanctioned: boolean;
    lists?: string[];
  };
  lastChecked: string;
  expiresAt: string;
  flags: string[];
}

/**
 * Geographic restriction configuration
 */
export interface GeoRestrictions {
  blockedCountries: string[];
  blockedRegions: string[];
  highRiskCountries: string[];
  requireEnhancedDueDiligence: string[];
}

// Default OFAC-related restricted jurisdictions
const DEFAULT_BLOCKED_COUNTRIES = [
  "KP", // North Korea
  "IR", // Iran
  "SY", // Syria
  "CU", // Cuba
  "RU", // Russia (partial)
];

const HIGH_RISK_COUNTRIES = [
  "AF", // Afghanistan
  "BY", // Belarus
  "MM", // Myanmar
  "VE", // Venezuela
  "YE", // Yemen
  "ZW", // Zimbabwe
];

/**
 * Check if transaction meets Travel Rule threshold
 */
export function requiresTravelRule(
  amountUsd: number,
  jurisdiction: "US" | "EU" | "FATF" = "FATF"
): boolean {
  const thresholds = {
    US: 3000, // FinCEN threshold
    EU: 1000, // EU AMLD6 threshold
    FATF: 1000, // FATF recommendation
  };

  return amountUsd >= thresholds[jurisdiction];
}

/**
 * Validate Travel Rule data completeness
 */
export function validateTravelRuleData(data: TravelRuleData): {
  isValid: boolean;
  missingFields: string[];
  warnings: string[];
} {
  const missingFields: string[] = [];
  const warnings: string[] = [];

  // Check originator fields
  if (!data.originator.address) {
    missingFields.push("originator.address");
  }
  if (!data.originator.name) {
    warnings.push("Originator name not provided");
  }

  // Check beneficiary fields
  if (!data.beneficiary.address) {
    missingFields.push("beneficiary.address");
  }
  if (!data.beneficiary.name) {
    warnings.push("Beneficiary name not provided");
  }

  // Check transaction fields
  if (!data.transaction.amount) {
    missingFields.push("transaction.amount");
  }
  if (!data.transaction.currency) {
    missingFields.push("transaction.currency");
  }

  return {
    isValid: missingFields.length === 0,
    missingFields,
    warnings,
  };
}

/**
 * Perform comprehensive compliance check on an address
 */
export async function checkAddressCompliance(
  client: any,
  address: string,
  options: {
    etherscanApiKey?: string;
    chainalysisApiKey?: string;
    geoRestrictions?: GeoRestrictions;
  } = {}
): Promise<AddressComplianceStatus> {
  const flags: string[] = [];
  let isCompliant = true;
  let riskLevel = RiskLevel.LOW;

  // Check sanctions
  const sanctionsResult = await checkSanctions(address, {
    chainalysisApiKey: options.chainalysisApiKey,
  });

  if (sanctionsResult.isSanctioned) {
    isCompliant = false;
    riskLevel = RiskLevel.CRITICAL;
    flags.push("SANCTIONED_ADDRESS");
  }

  // Analyze address risk
  const addressAnalysis = await analyzeAddress(client, address, {
    etherscanApiKey: options.etherscanApiKey,
    checkSanctions: false, // Already checked
  });

  if (addressAnalysis.riskScore.score >= SECURITY_THRESHOLDS.HIGH_RISK) {
    if (riskLevel !== RiskLevel.CRITICAL) {
      riskLevel = RiskLevel.HIGH;
    }
    flags.push(...addressAnalysis.riskScore.factors.map(f => f.type));
  } else if (addressAnalysis.riskScore.score >= SECURITY_THRESHOLDS.MEDIUM_RISK) {
    if (riskLevel === RiskLevel.LOW) {
      riskLevel = RiskLevel.MEDIUM;
    }
    flags.push(...addressAnalysis.riskScore.factors.map(f => f.type));
  }

  // Check for new address (potential concern)
  if (addressAnalysis.transactionCount === 0) {
    flags.push("NEW_ADDRESS");
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

  return {
    address,
    isCompliant,
    kycVerified: false, // Would integrate with KYC provider
    riskLevel,
    sanctionsStatus: {
      checked: true,
      isSanctioned: sanctionsResult.isSanctioned,
      lists: sanctionsResult.lists,
    },
    lastChecked: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    flags,
  };
}

/**
 * Check if a country is blocked or restricted
 */
export function checkGeoRestrictions(
  countryCode: string,
  restrictions: GeoRestrictions = {
    blockedCountries: DEFAULT_BLOCKED_COUNTRIES,
    blockedRegions: [],
    highRiskCountries: HIGH_RISK_COUNTRIES,
    requireEnhancedDueDiligence: [],
  }
): {
  isBlocked: boolean;
  isHighRisk: boolean;
  requiresEnhancedDueDiligence: boolean;
  reason?: string;
} {
  const upperCode = countryCode.toUpperCase();

  if (restrictions.blockedCountries.includes(upperCode)) {
    return {
      isBlocked: true,
      isHighRisk: true,
      requiresEnhancedDueDiligence: false,
      reason: `Country ${upperCode} is on the blocked list`,
    };
  }

  if (restrictions.highRiskCountries.includes(upperCode)) {
    return {
      isBlocked: false,
      isHighRisk: true,
      requiresEnhancedDueDiligence: true,
      reason: `Country ${upperCode} is classified as high-risk`,
    };
  }

  if (restrictions.requireEnhancedDueDiligence.includes(upperCode)) {
    return {
      isBlocked: false,
      isHighRisk: false,
      requiresEnhancedDueDiligence: true,
      reason: `Country ${upperCode} requires enhanced due diligence`,
    };
  }

  return {
    isBlocked: false,
    isHighRisk: false,
    requiresEnhancedDueDiligence: false,
  };
}

/**
 * Calculate transaction risk score for AML purposes
 */
export function calculateAmlRiskScore(params: {
  transactionAmount: number;
  counterpartyRiskScore: number;
  isNewCounterparty: boolean;
  transactionFrequency: "low" | "normal" | "high";
  crossBorder: boolean;
  involvesMixer: boolean;
  involvesHighRiskJurisdiction: boolean;
}): {
  score: number;
  level: RiskLevel;
  factors: string[];
  recommendation: string;
} {
  let score = params.counterpartyRiskScore;
  const factors: string[] = [];

  // Amount-based risk
  if (params.transactionAmount >= 100000) {
    score += 20;
    factors.push("High value transaction");
  } else if (params.transactionAmount >= 10000) {
    score += 10;
    factors.push("Elevated value transaction");
  }

  // Counterparty risk
  if (params.isNewCounterparty) {
    score += 15;
    factors.push("New counterparty");
  }

  // Frequency-based risk
  if (params.transactionFrequency === "high") {
    score += 10;
    factors.push("High transaction frequency");
  }

  // Cross-border risk
  if (params.crossBorder) {
    score += 10;
    factors.push("Cross-border transaction");
  }

  // Mixer involvement
  if (params.involvesMixer) {
    score += 30;
    factors.push("Mixer/tumbler involvement");
  }

  // Jurisdiction risk
  if (params.involvesHighRiskJurisdiction) {
    score += 25;
    factors.push("High-risk jurisdiction");
  }

  // Normalize score to 0-100
  score = Math.min(100, Math.max(0, score));

  // Determine risk level
  let level: RiskLevel;
  let recommendation: string;

  if (score >= SECURITY_THRESHOLDS.CRITICAL_RISK) {
    level = RiskLevel.CRITICAL;
    recommendation = "Block transaction and escalate for review";
  } else if (score >= SECURITY_THRESHOLDS.HIGH_RISK) {
    level = RiskLevel.HIGH;
    recommendation = "Require manual approval before processing";
  } else if (score >= SECURITY_THRESHOLDS.MEDIUM_RISK) {
    level = RiskLevel.MEDIUM;
    recommendation = "Enhanced monitoring recommended";
  } else {
    level = RiskLevel.LOW;
    recommendation = "Standard processing";
  }

  return { score, level, factors, recommendation };
}

/**
 * Generate AML/CFT compliance summary
 */
export function generateComplianceSummary(
  transactions: Array<{
    hash: string;
    from: string;
    to: string;
    value: string;
    riskScore: number;
    blocked: boolean;
  }>
): {
  totalTransactions: number;
  totalBlocked: number;
  averageRiskScore: number;
  riskDistribution: Record<string, number>;
  topRiskyAddresses: Array<{ address: string; riskScore: number }>;
  complianceRate: number;
} {
  const totalTransactions = transactions.length;
  const totalBlocked = transactions.filter((t) => t.blocked).length;
  const avgScore =
    transactions.reduce((sum, t) => sum + t.riskScore, 0) / totalTransactions || 0;

  const riskDistribution = {
    low: transactions.filter((t) => t.riskScore < SECURITY_THRESHOLDS.MEDIUM_RISK)
      .length,
    medium: transactions.filter(
      (t) =>
        t.riskScore >= SECURITY_THRESHOLDS.MEDIUM_RISK &&
        t.riskScore < SECURITY_THRESHOLDS.HIGH_RISK
    ).length,
    high: transactions.filter(
      (t) =>
        t.riskScore >= SECURITY_THRESHOLDS.HIGH_RISK &&
        t.riskScore < SECURITY_THRESHOLDS.CRITICAL_RISK
    ).length,
    critical: transactions.filter(
      (t) => t.riskScore >= SECURITY_THRESHOLDS.CRITICAL_RISK
    ).length,
  };

  // Find top risky addresses
  const addressScores = new Map<string, number>();
  for (const tx of transactions) {
    const currentFromScore = addressScores.get(tx.from) || 0;
    const currentToScore = addressScores.get(tx.to) || 0;
    addressScores.set(tx.from, Math.max(currentFromScore, tx.riskScore));
    addressScores.set(tx.to, Math.max(currentToScore, tx.riskScore));
  }

  const topRiskyAddresses = Array.from(addressScores.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([address, riskScore]) => ({ address, riskScore }));

  const complianceRate =
    totalTransactions > 0
      ? ((totalTransactions - totalBlocked) / totalTransactions) * 100
      : 100;

  return {
    totalTransactions,
    totalBlocked,
    averageRiskScore: Math.round(avgScore),
    riskDistribution,
    topRiskyAddresses,
    complianceRate: Math.round(complianceRate * 100) / 100,
  };
}

/**
 * Check if enhanced due diligence is required
 */
export function requiresEnhancedDueDiligence(params: {
  transactionValue: number;
  riskScore: number;
  isPep?: boolean; // Politically Exposed Person
  isHighRiskCountry?: boolean;
  isNewRelationship?: boolean;
}): {
  required: boolean;
  reasons: string[];
  requirements: string[];
} {
  const reasons: string[] = [];
  const requirements: string[] = [];

  // High value transactions
  if (params.transactionValue >= 15000) {
    reasons.push("Transaction value exceeds EDD threshold");
    requirements.push("Source of funds verification");
  }

  // High risk score
  if (params.riskScore >= SECURITY_THRESHOLDS.HIGH_RISK) {
    reasons.push("High risk score detected");
    requirements.push("Enhanced identity verification");
    requirements.push("Transaction purpose documentation");
  }

  // PEP check
  if (params.isPep) {
    reasons.push("Politically Exposed Person");
    requirements.push("Senior management approval");
    requirements.push("Source of wealth verification");
    requirements.push("Enhanced ongoing monitoring");
  }

  // High risk country
  if (params.isHighRiskCountry) {
    reasons.push("High-risk jurisdiction involvement");
    requirements.push("Additional identity documentation");
    requirements.push("Purpose of relationship documentation");
  }

  // New relationship with high value
  if (params.isNewRelationship && params.transactionValue >= 5000) {
    reasons.push("New relationship with significant value");
    requirements.push("Business purpose verification");
  }

  return {
    required: reasons.length > 0,
    reasons,
    requirements: [...new Set(requirements)], // Remove duplicates
  };
}
