/**
 * Honeypot Detector
 *
 * Detects honeypot tokens and scam contracts that prevent
 * users from selling or transferring tokens
 */

import { PublicClient, parseAbi, formatUnits } from "viem";
import { RiskLevel, RiskScore, RiskFactor, ERC20_ABI } from "../../utils/constants";
import { TokenSecurityAnalysis } from "../../utils/types";

// ===========================================
//          Honeypot Detection
// ===========================================

/**
 * Analyze a token for honeypot characteristics
 */
export async function detectHoneypot(
  client: PublicClient,
  tokenAddress: string,
  options?: {
    testAmount?: bigint;
    routerAddress?: string;
  }
): Promise<TokenSecurityAnalysis> {
  const address = tokenAddress as `0x${string}`;
  const riskFactors: RiskFactor[] = [];

  let isHoneypot = false;
  let isMintable = false;
  let isPausable = false;
  let hasBlacklist = false;
  let hasTaxes = false;
  let buyTax: number | undefined;
  let sellTax: number | undefined;

  // Get contract bytecode
  const bytecode = await client.getCode({ address });

  if (!bytecode || bytecode === "0x") {
    return createEmptyAnalysis(tokenAddress, "Not a contract");
  }

  // Analyze bytecode for common patterns
  const bytecodeAnalysis = analyzeBytecodeForHoneypot(bytecode);

  if (bytecodeAnalysis.hasMintFunction) {
    isMintable = true;
    riskFactors.push({
      type: "mintable",
      severity: RiskLevel.MEDIUM,
      description: "Token has minting capability",
      impact: 15,
    });
  }

  if (bytecodeAnalysis.hasPauseFunction) {
    isPausable = true;
    riskFactors.push({
      type: "pausable",
      severity: RiskLevel.MEDIUM,
      description: "Token transfers can be paused",
      impact: 15,
    });
  }

  if (bytecodeAnalysis.hasBlacklistFunction) {
    hasBlacklist = true;
    riskFactors.push({
      type: "blacklist",
      severity: RiskLevel.HIGH,
      description: "Token has blacklist functionality",
      impact: 25,
    });
  }

  if (bytecodeAnalysis.hasFeeFunction) {
    hasTaxes = true;
    riskFactors.push({
      type: "transfer_fees",
      severity: RiskLevel.MEDIUM,
      description: "Token has transfer fee mechanism",
      impact: 20,
    });
  }

  // Check for common honeypot signatures
  if (bytecodeAnalysis.hasMaxTxLimit) {
    riskFactors.push({
      type: "max_tx_limit",
      severity: RiskLevel.MEDIUM,
      description: "Token has maximum transaction limits",
      impact: 15,
    });
  }

  if (bytecodeAnalysis.hasCooldownPeriod) {
    riskFactors.push({
      type: "cooldown",
      severity: RiskLevel.LOW,
      description: "Token has cooldown period between transactions",
      impact: 10,
    });
  }

  // Critical honeypot indicators
  if (bytecodeAnalysis.hasOwnerOnlyTransfer) {
    isHoneypot = true;
    riskFactors.push({
      type: "owner_only_transfer",
      severity: RiskLevel.CRITICAL,
      description: "Only owner can transfer tokens - HONEYPOT",
      impact: 100,
    });
  }

  if (bytecodeAnalysis.hasHiddenOwner) {
    riskFactors.push({
      type: "hidden_owner",
      severity: RiskLevel.HIGH,
      description: "Contract has hidden owner functionality",
      impact: 35,
    });
  }

  if (bytecodeAnalysis.hasExternalCall) {
    riskFactors.push({
      type: "external_call",
      severity: RiskLevel.HIGH,
      description: "Token makes external calls that could block transfers",
      impact: 30,
    });
  }

  // Try to get token info
  let ownerBalance: bigint | undefined;
  try {
    const [totalSupply, name, symbol, decimals] = await Promise.all([
      client.readContract({
        address,
        abi: parseAbi(ERC20_ABI),
        functionName: "totalSupply",
      }),
      client.readContract({
        address,
        abi: parseAbi(ERC20_ABI),
        functionName: "name",
      }).catch(() => "Unknown"),
      client.readContract({
        address,
        abi: parseAbi(ERC20_ABI),
        functionName: "symbol",
      }).catch(() => "???"),
      client.readContract({
        address,
        abi: parseAbi(ERC20_ABI),
        functionName: "decimals",
      }).catch(() => 18),
    ]);

    // Check for suspicious supply
    if (totalSupply === 0n) {
      isHoneypot = true;
      riskFactors.push({
        type: "zero_supply",
        severity: RiskLevel.CRITICAL,
        description: "Token has zero total supply",
        impact: 100,
      });
    }
  } catch (error) {
    riskFactors.push({
      type: "read_error",
      severity: RiskLevel.HIGH,
      description: "Unable to read basic token information",
      impact: 40,
    });
  }

  // Calculate risk score
  const totalImpact = riskFactors.reduce((sum, f) => sum + f.impact, 0);
  const normalizedScore = Math.min(100, totalImpact);

  let level: RiskLevel;
  if (isHoneypot || normalizedScore >= 80) {
    level = RiskLevel.CRITICAL;
    isHoneypot = true;
  } else if (normalizedScore >= 50) {
    level = RiskLevel.HIGH;
  } else if (normalizedScore >= 30) {
    level = RiskLevel.MEDIUM;
  } else if (normalizedScore > 0) {
    level = RiskLevel.LOW;
  } else {
    level = RiskLevel.SAFE;
  }

  return {
    isHoneypot,
    isMintable,
    isPausable,
    hasBlacklist,
    hasTaxes,
    buyTax,
    sellTax,
    ownerBalance,
    riskScore: {
      level,
      score: normalizedScore,
      factors: riskFactors,
      recommendation: isHoneypot
        ? "WARNING: This token appears to be a honeypot. Do NOT buy."
        : level === RiskLevel.HIGH
        ? "High risk token. Proceed with extreme caution."
        : level === RiskLevel.MEDIUM
        ? "Some risks detected. Review before trading."
        : "Token appears relatively safe.",
    },
  };
}

// ===========================================
//          Bytecode Analysis
// ===========================================

interface BytecodeAnalysisResult {
  hasMintFunction: boolean;
  hasPauseFunction: boolean;
  hasBlacklistFunction: boolean;
  hasFeeFunction: boolean;
  hasMaxTxLimit: boolean;
  hasCooldownPeriod: boolean;
  hasOwnerOnlyTransfer: boolean;
  hasHiddenOwner: boolean;
  hasExternalCall: boolean;
}

/**
 * Analyze bytecode for honeypot patterns
 */
function analyzeBytecodeForHoneypot(bytecode: string): BytecodeAnalysisResult {
  const normalized = bytecode.toLowerCase();

  // Function selectors to look for
  const selectors = {
    // Mint functions
    mint: ["40c10f19", "a0712d68", "6a627842"],
    // Pause functions
    pause: ["8456cb59", "5c975abb", "02329a29"],
    // Blacklist functions
    blacklist: ["f9f92be4", "e4997dc5", "44337ea1", "0ecb93c0"],
    // Fee functions
    fee: ["8ea5220f", "2a9e3c9b", "13114a9d"],
    // MaxTx limit
    maxTx: ["2a11ced0", "a457c2d7", "3bbac579"],
    // Owner functions
    owner: ["8da5cb5b", "715018a6", "f2fde38b"],
  };

  return {
    hasMintFunction: selectors.mint.some((s) => normalized.includes(s)),
    hasPauseFunction: selectors.pause.some((s) => normalized.includes(s)),
    hasBlacklistFunction: selectors.blacklist.some((s) => normalized.includes(s)),
    hasFeeFunction: selectors.fee.some((s) => normalized.includes(s)),
    hasMaxTxLimit: selectors.maxTx.some((s) => normalized.includes(s)),
    hasCooldownPeriod: normalized.includes("426c6f636b") || normalized.includes("636f6f6c646f776e"),
    hasOwnerOnlyTransfer: normalized.includes("6f6e6c794f776e6572"),
    hasHiddenOwner: normalized.includes("5f6f776e6572") && !normalized.includes("8da5cb5b"),
    hasExternalCall: normalized.includes("f1") || normalized.includes("f2"),
  };
}

// ===========================================
//          Helper Functions
// ===========================================

function createEmptyAnalysis(
  address: string,
  reason: string
): TokenSecurityAnalysis {
  return {
    isHoneypot: false,
    isMintable: false,
    isPausable: false,
    hasBlacklist: false,
    hasTaxes: false,
    riskScore: {
      level: RiskLevel.MEDIUM,
      score: 50,
      factors: [
        {
          type: "analysis_failed",
          severity: RiskLevel.MEDIUM,
          description: reason,
          impact: 50,
        },
      ],
      recommendation: `Unable to analyze token: ${reason}`,
    },
  };
}

// ===========================================
//          Simulation-Based Detection
// ===========================================

/**
 * Simulate a buy/sell to detect honeypots
 * Note: This requires a DEX router and is more accurate but more complex
 */
export async function simulateTradeForHoneypot(
  client: PublicClient,
  tokenAddress: string,
  routerAddress: string,
  testAmount: bigint
): Promise<{
  canBuy: boolean;
  canSell: boolean;
  buyTax: number;
  sellTax: number;
  isHoneypot: boolean;
}> {
  // This is a placeholder for simulation logic
  // In production, this would use eth_call to simulate trades
  // through Uniswap/PancakeSwap routers

  return {
    canBuy: true,
    canSell: true,
    buyTax: 0,
    sellTax: 0,
    isHoneypot: false,
  };
}
