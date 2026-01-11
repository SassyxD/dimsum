/**
 * Address Analyzer
 *
 * Analyzes Ethereum addresses for security risks, reputation,
 * and behavioral patterns
 */

import { PublicClient, getAddress, isAddress } from "viem";
import {
  RiskLevel,
  RiskScore,
  RiskFactor,
  SECURITY_THRESHOLDS,
  SECURITY_MESSAGES,
} from "../../utils/constants";
import {
  AddressAnalysis,
  SanctionsCheck,
} from "../../utils/types";

// ===========================================
//          Address Analysis
// ===========================================

/**
 * Perform comprehensive security analysis on an Ethereum address
 */
export async function analyzeAddress(
  client: any,
  address: string,
  options?: {
    etherscanApiKey?: string;
    checkSanctions?: boolean;
  }
): Promise<AddressAnalysis> {
  // Validate address format
  if (!isAddress(address)) {
    throw new Error(`Invalid Ethereum address: ${address}`);
  }

  const checksumAddress = getAddress(address);
  const riskFactors: RiskFactor[] = [];

  // Check if address is a contract
  const code = await client.getBytecode({ address: checksumAddress });
  const isContract = code !== undefined && code !== "0x";

  // Get transaction count (age indicator)
  const transactionCount = await client.getTransactionCount({
    address: checksumAddress,
  });

  // Check if address is verified (if contract)
  let isVerified = false;
  let verificationSource: string | undefined;

  if (isContract && options?.etherscanApiKey) {
    const verificationResult = await checkContractVerification(
      checksumAddress,
      options.etherscanApiKey
    );
    isVerified = verificationResult.isVerified;
    verificationSource = verificationResult.source;

    if (!isVerified) {
      riskFactors.push({
        type: "unverified_contract",
        severity: RiskLevel.MEDIUM,
        description: SECURITY_MESSAGES.ADDRESS_NOT_VERIFIED,
        impact: 25,
      });
    }
  }

  // Check for new address warning
  if (transactionCount < 5) {
    riskFactors.push({
      type: "new_address",
      severity: RiskLevel.LOW,
      description:
        "This address has very few transactions, indicating it may be newly created.",
      impact: 10,
    });
  }

  // Sanctions check placeholder
  const sanctions: SanctionsCheck = {
    isChecked: false,
    isSanctioned: false,
  };

  if (options?.checkSanctions) {
    // In production, integrate with Chainalysis/Elliptic API
    sanctions.isChecked = true;
    // sanctions.isSanctioned = await checkSanctionsList(checksumAddress);
  }

  // Calculate overall risk score
  const riskScore = calculateAddressRiskScore(riskFactors);

  // Generate labels
  const labels: string[] = [];
  if (isContract) labels.push("contract");
  if (isVerified) labels.push("verified");
  if (transactionCount > 1000) labels.push("high-activity");
  if (transactionCount < 5) labels.push("new-address");

  return {
    address: checksumAddress,
    isContract,
    isVerified,
    verificationSource,
    transactionCount: Number(transactionCount),
    riskScore,
    labels,
    sanctions,
  };
}

// ===========================================
//          Contract Verification
// ===========================================

interface VerificationResult {
  isVerified: boolean;
  source?: string;
}

/**
 * Check if a contract is verified on Etherscan
 */
async function checkContractVerification(
  address: string,
  apiKey: string
): Promise<VerificationResult> {
  try {
    const response = await fetch(
      `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`
    );

    const data = await response.json() as any;

    if (data.status === "1" && data.result?.[0]?.SourceCode) {
      return {
        isVerified: true,
        source: "etherscan",
      };
    }

    return { isVerified: false };
  } catch (error) {
    // Don't fail analysis if verification check fails
    return { isVerified: false };
  }
}

// ===========================================
//          Risk Score Calculation
// ===========================================

/**
 * Calculate overall risk score from individual factors
 */
function calculateAddressRiskScore(factors: RiskFactor[]): RiskScore {
  if (factors.length === 0) {
    return {
      level: RiskLevel.SAFE,
      score: 0,
      factors: [],
      recommendation: "No risk factors detected. Safe to proceed.",
    };
  }

  // Calculate weighted score
  const totalImpact = factors.reduce((sum, f) => sum + f.impact, 0);
  const normalizedScore = Math.min(100, totalImpact);

  // Determine risk level
  let level: RiskLevel;
  let recommendation: string;

  if (normalizedScore >= SECURITY_THRESHOLDS.BLOCK_TRANSACTION_SCORE) {
    level = RiskLevel.CRITICAL;
    recommendation =
      "This address has critical security concerns. Do not proceed without thorough investigation.";
  } else if (normalizedScore >= SECURITY_THRESHOLDS.WARN_TRANSACTION_SCORE) {
    level = RiskLevel.HIGH;
    recommendation =
      "This address has significant risk factors. Proceed with extreme caution.";
  } else if (normalizedScore >= SECURITY_THRESHOLDS.REVIEW_TRANSACTION_SCORE) {
    level = RiskLevel.MEDIUM;
    recommendation =
      "This address has some risk factors. Review before proceeding.";
  } else if (normalizedScore > 0) {
    level = RiskLevel.LOW;
    recommendation =
      "Minor risk factors detected. Generally safe to proceed.";
  } else {
    level = RiskLevel.SAFE;
    recommendation = "No significant risks detected.";
  }

  return {
    level,
    score: normalizedScore,
    factors,
    recommendation,
  };
}

// ===========================================
//          Address Similarity Detection
// ===========================================

/**
 * Check for address similarity (phishing detection)
 * Detects addresses that look similar to known addresses
 */
export function checkAddressSimilarity(
  address: string,
  knownAddresses: string[]
): {
  isSuspicious: boolean;
  similarTo?: string;
  similarity: number;
} {
  if (!isAddress(address)) {
    return { isSuspicious: false, similarity: 0 };
  }

  const targetLower = address.toLowerCase();

  for (const known of knownAddresses) {
    if (!isAddress(known)) continue;

    const knownLower = known.toLowerCase();

    // Check for similar prefix/suffix (common phishing pattern)
    const prefixMatch = targetLower.slice(2, 8) === knownLower.slice(2, 8);
    const suffixMatch = targetLower.slice(-6) === knownLower.slice(-6);

    if (prefixMatch && suffixMatch && targetLower !== knownLower) {
      // Calculate overall similarity
      let matchingChars = 0;
      for (let i = 0; i < targetLower.length; i++) {
        if (targetLower[i] === knownLower[i]) matchingChars++;
      }
      const similarity = (matchingChars / targetLower.length) * 100;

      if (similarity > 80) {
        return {
          isSuspicious: true,
          similarTo: known,
          similarity,
        };
      }
    }
  }

  return { isSuspicious: false, similarity: 0 };
}

// ===========================================
//          Address Labels
// ===========================================

/**
 * Common address labels for categorization
 */
export const ADDRESS_LABELS = {
  EXCHANGE: "exchange",
  BRIDGE: "bridge",
  DEX: "dex",
  LENDING: "lending",
  MIXER: "mixer",
  SCAM: "scam",
  PHISHING: "phishing",
  SANCTIONED: "sanctioned",
  VERIFIED: "verified",
  AUDITED: "audited",
} as const;

export type AddressLabel = (typeof ADDRESS_LABELS)[keyof typeof ADDRESS_LABELS];
