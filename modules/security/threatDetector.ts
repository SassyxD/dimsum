/**
 * Threat Detector
 *
 * Real-time threat detection for transactions and addresses
 * Includes MEV protection, front-running detection, and anomaly detection
 */

import { PublicClient, formatEther, parseGwei } from "viem";
import {
  RiskLevel,
  RiskFactor,
  SECURITY_THRESHOLDS,
  SECURITY_MESSAGES,
} from "../../utils/constants";
import {
  SecureTransaction,
  TransactionRiskAssessment,
  PreFlightCheck,
  TransactionRecommendation,
  AnomalyDetection,
} from "../../utils/types";

// ===========================================
//          Transaction Threat Analysis
// ===========================================

/**
 * Analyze a transaction for potential threats before execution
 */
export async function analyzeTransactionThreats(
  client: any,
  transaction: SecureTransaction,
  options?: {
    checkMEV?: boolean;
    simulateFirst?: boolean;
    historicalBaseline?: GasBaseline;
  }
): Promise<TransactionRiskAssessment> {
  const preFlightChecks: PreFlightCheck[] = [];
  const riskFactors: RiskFactor[] = [];

  // 1. Value-based risk check
  if (transaction.value) {
    const valueCheck = await checkTransactionValue(transaction.value);
    preFlightChecks.push(valueCheck);
    if (!valueCheck.passed) {
      riskFactors.push({
        type: "high_value",
        severity: valueCheck.severity,
        description: valueCheck.message,
        impact: valueCheck.severity === RiskLevel.CRITICAL ? 40 : 25,
      });
    }
  }

  // 2. Gas price anomaly check
  if (transaction.maxFeePerGas || options?.historicalBaseline) {
    const gasCheck = await checkGasAnomaly(
      client,
      transaction,
      options?.historicalBaseline
    );
    preFlightChecks.push(gasCheck);
    if (!gasCheck.passed) {
      riskFactors.push({
        type: "gas_anomaly",
        severity: gasCheck.severity,
        description: gasCheck.message,
        impact: 15,
      });
    }
  }

  // 3. Contract interaction check
  if (transaction.data && transaction.data !== "0x") {
    const contractCheck = await checkContractInteraction(
      client,
      transaction
    );
    preFlightChecks.push(contractCheck);
    if (!contractCheck.passed) {
      riskFactors.push({
        type: "risky_contract_call",
        severity: contractCheck.severity,
        description: contractCheck.message,
        impact: 30,
      });
    }
  }

  // 4. MEV vulnerability check
  if (options?.checkMEV) {
    const mevCheck = await checkMEVVulnerability(transaction);
    preFlightChecks.push(mevCheck);
    if (!mevCheck.passed) {
      riskFactors.push({
        type: "mev_vulnerable",
        severity: mevCheck.severity,
        description: mevCheck.message,
        impact: 20,
      });
    }
  }

  // 5. Recipient check
  const recipientCheck = await checkRecipient(client, transaction.to);
  preFlightChecks.push(recipientCheck);
  if (!recipientCheck.passed) {
    riskFactors.push({
      type: "suspicious_recipient",
      severity: recipientCheck.severity,
      description: recipientCheck.message,
      impact: 35,
    });
  }

  // Calculate overall risk score
  const totalImpact = riskFactors.reduce((sum, f) => sum + f.impact, 0);
  const normalizedScore = Math.min(100, totalImpact);

  // Determine recommendation
  let recommendation: TransactionRecommendation;
  let level: RiskLevel;

  if (normalizedScore >= SECURITY_THRESHOLDS.BLOCK_TRANSACTION_SCORE) {
    recommendation = TransactionRecommendation.BLOCK;
    level = RiskLevel.CRITICAL;
  } else if (normalizedScore >= SECURITY_THRESHOLDS.WARN_TRANSACTION_SCORE) {
    recommendation = TransactionRecommendation.CAUTION;
    level = RiskLevel.HIGH;
  } else if (normalizedScore >= SECURITY_THRESHOLDS.REVIEW_TRANSACTION_SCORE) {
    recommendation = TransactionRecommendation.REVIEW;
    level = RiskLevel.MEDIUM;
  } else {
    recommendation = TransactionRecommendation.PROCEED;
    level = normalizedScore > 0 ? RiskLevel.LOW : RiskLevel.SAFE;
  }

  return {
    transaction,
    riskScore: {
      level,
      score: normalizedScore,
      factors: riskFactors,
      recommendation: getRecommendationText(recommendation),
    },
    preFlightChecks,
    recommendation,
  };
}

// ===========================================
//          Individual Threat Checks
// ===========================================

/**
 * Check transaction value for high-value warning
 */
async function checkTransactionValue(
  value: bigint
): Promise<PreFlightCheck> {
  const ethValue = Number(formatEther(value));

  if (ethValue >= SECURITY_THRESHOLDS.CRITICAL_VALUE_THRESHOLD) {
    return {
      name: "value_check",
      passed: false,
      severity: RiskLevel.CRITICAL,
      message: `Transaction value (${ethValue} ETH) exceeds critical threshold. Requires additional verification.`,
      details: { value: ethValue, threshold: SECURITY_THRESHOLDS.CRITICAL_VALUE_THRESHOLD },
    };
  }

  if (ethValue >= SECURITY_THRESHOLDS.HIGH_VALUE_THRESHOLD) {
    return {
      name: "value_check",
      passed: false,
      severity: RiskLevel.HIGH,
      message: `High-value transaction (${ethValue} ETH). Ensure recipient is correct.`,
      details: { value: ethValue, threshold: SECURITY_THRESHOLDS.HIGH_VALUE_THRESHOLD },
    };
  }

  return {
    name: "value_check",
    passed: true,
    severity: RiskLevel.SAFE,
    message: "Transaction value within normal range.",
  };
}

/**
 * Check for gas price anomalies
 */
interface GasBaseline {
  averageGasPrice: bigint;
  percentile75: bigint;
  percentile99: bigint;
}

async function checkGasAnomaly(
  client: any,
  transaction: SecureTransaction,
  baseline?: GasBaseline
): Promise<PreFlightCheck> {
  try {
    const currentGasPrice = await client.getGasPrice();

    let targetGas = BigInt(transaction.maxFeePerGas || currentGasPrice);
    let referenceGas = BigInt(baseline?.averageGasPrice || currentGasPrice);

    if (referenceGas === 0n) {
      return {
        name: "gas_check",
        passed: true,
        severity: RiskLevel.SAFE,
        message: "Gas price check skipped - no baseline available.",
      };
    }

    const percentageAbove =
      Number(((targetGas - referenceGas) * 100n) / referenceGas);

    if (percentageAbove > Number(SECURITY_THRESHOLDS.GAS_PRICE_ANOMALY_THRESHOLD)) {
      return {
        name: "gas_check",
        passed: false,
        severity: RiskLevel.MEDIUM,
        message: `Gas price is ${percentageAbove}% above average. Possible front-running or network congestion.`,
        details: { targetGas: targetGas.toString(), referenceGas: referenceGas.toString(), percentageAbove },
      };
    }

    return {
      name: "gas_check",
      passed: true,
      severity: RiskLevel.SAFE,
      message: "Gas price within normal range.",
    };
  } catch (error) {
    return {
      name: "gas_check",
      passed: true,
      severity: RiskLevel.LOW,
      message: "Unable to verify gas price. Proceeding with caution.",
    };
  }
}

/**
 * Check contract interaction for known risky patterns
 */
async function checkContractInteraction(
  client: any,
  transaction: SecureTransaction
): Promise<PreFlightCheck> {
  const data = transaction.data as string;

  // Extract function selector (first 4 bytes)
  const selector = data.slice(0, 10);

  // Known risky function selectors
  const riskySelectors: Record<string, { name: string; risk: string }> = {
    "0x095ea7b3": { name: "approve", risk: "Unlimited token approval" },
    "0x39509351": { name: "increaseAllowance", risk: "Increasing token allowance" },
    "0xa22cb465": { name: "setApprovalForAll", risk: "NFT collection approval" },
    "0xf305d719": { name: "addLiquidity", risk: "Adding liquidity to unknown pool" },
  };

  const riskyFunction = riskySelectors[selector];

  if (riskyFunction) {
    // Check for unlimited approval (max uint256)
    if (selector === "0x095ea7b3" && data.includes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")) {
      return {
        name: "contract_interaction_check",
        passed: false,
        severity: RiskLevel.HIGH,
        message: `Detected unlimited token approval. This gives the spender full access to your tokens.`,
        details: { function: riskyFunction.name, risk: riskyFunction.risk },
      };
    }

    return {
      name: "contract_interaction_check",
      passed: false,
      severity: RiskLevel.MEDIUM,
      message: `Detected ${riskyFunction.name}: ${riskyFunction.risk}`,
      details: { function: riskyFunction.name },
    };
  }

  return {
    name: "contract_interaction_check",
    passed: true,
    severity: RiskLevel.SAFE,
    message: "Contract interaction appears safe.",
  };
}

/**
 * Check for MEV vulnerability
 */
async function checkMEVVulnerability(
  transaction: SecureTransaction
): Promise<PreFlightCheck> {
  const data = transaction.data as string | undefined;

  if (!data || data === "0x") {
    return {
      name: "mev_check",
      passed: true,
      severity: RiskLevel.SAFE,
      message: "Simple ETH transfer - low MEV risk.",
    };
  }

  // DEX swap selectors that are MEV-vulnerable
  const dexSelectors = [
    "0x38ed1739", // swapExactTokensForTokens
    "0x7ff36ab5", // swapExactETHForTokens
    "0x18cbafe5", // swapExactTokensForETH
    "0x8803dbee", // swapTokensForExactTokens
    "0xfb3bdb41", // swapETHForExactTokens
    "0x5c11d795", // swapExactTokensForTokensSupportingFeeOnTransferTokens
  ];

  const selector = data.slice(0, 10);

  if (dexSelectors.includes(selector)) {
    return {
      name: "mev_check",
      passed: false,
      severity: RiskLevel.MEDIUM,
      message: SECURITY_MESSAGES.MEV_RISK_DETECTED,
      details: {
        recommendation: "Consider using Flashbots Protect or a private mempool",
      },
    };
  }

  return {
    name: "mev_check",
    passed: true,
    severity: RiskLevel.SAFE,
    message: "No obvious MEV vulnerability detected.",
  };
}

/**
 * Check recipient address
 */
async function checkRecipient(
  client: any,
  to: string
): Promise<PreFlightCheck> {
  const code = await client.getBytecode({ address: to as `0x${string}` });
  const isContract = code !== undefined && code !== "0x";

  if (isContract) {
    // Additional checks for contracts could go here
    return {
      name: "recipient_check",
      passed: true,
      severity: RiskLevel.LOW,
      message: "Recipient is a smart contract. Verify it is the intended contract.",
      details: { isContract: true },
    };
  }

  return {
    name: "recipient_check",
    passed: true,
    severity: RiskLevel.SAFE,
    message: "Recipient is an externally owned account (EOA).",
    details: { isContract: false },
  };
}

// ===========================================
//          Anomaly Detection
// ===========================================

/**
 * Detect anomalies in transaction patterns
 */
export function detectTransactionAnomaly(
  current: { value: bigint; gasPrice: bigint },
  historical: { avgValue: bigint; avgGasPrice: bigint; stdDevValue: bigint; stdDevGasPrice: bigint }
): AnomalyDetection[] {
  const anomalies: AnomalyDetection[] = [];

  // Value anomaly
  if (historical.stdDevValue > 0n) {
    const valueDeviation =
      (current.value - historical.avgValue) / historical.stdDevValue;
    const deviationNumber = Number(valueDeviation);

    if (Math.abs(deviationNumber) > 2) {
      anomalies.push({
        type: "value_anomaly",
        detected: true,
        confidence: Math.min(0.99, 0.5 + Math.abs(deviationNumber) * 0.1),
        baseline: Number(formatEther(historical.avgValue)),
        current: Number(formatEther(current.value)),
        deviation: deviationNumber,
        details: `Transaction value is ${deviationNumber.toFixed(1)} standard deviations from average`,
      });
    }
  }

  // Gas price anomaly
  if (historical.stdDevGasPrice > 0n) {
    const gasDeviation =
      (current.gasPrice - historical.avgGasPrice) / historical.stdDevGasPrice;
    const deviationNumber = Number(gasDeviation);

    if (Math.abs(deviationNumber) > 2) {
      anomalies.push({
        type: "gas_price_anomaly",
        detected: true,
        confidence: Math.min(0.99, 0.5 + Math.abs(deviationNumber) * 0.1),
        baseline: Number(historical.avgGasPrice),
        current: Number(current.gasPrice),
        deviation: deviationNumber,
        details: `Gas price is ${deviationNumber.toFixed(1)} standard deviations from average`,
      });
    }
  }

  return anomalies;
}

// ===========================================
//          Helper Functions
// ===========================================

function getRecommendationText(recommendation: TransactionRecommendation): string {
  switch (recommendation) {
    case TransactionRecommendation.BLOCK:
      return "Transaction blocked due to critical security concerns. Do not proceed.";
    case TransactionRecommendation.CAUTION:
      return "High risk detected. Proceed only if you fully understand the risks.";
    case TransactionRecommendation.REVIEW:
      return "Some risk factors detected. Review carefully before proceeding.";
    case TransactionRecommendation.PROCEED:
      return "No significant risks detected. Safe to proceed.";
  }
}
