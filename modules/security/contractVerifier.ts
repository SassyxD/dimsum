/**
 * Contract Verifier
 *
 * Verifies smart contracts on block explorers and performs
 * security analysis of contract source code
 */

import {
  RiskLevel,
  RiskFactor,
  MALICIOUS_BYTECODE_PATTERNS,
} from "../../utils/constants";
import {
  ContractSecurityAnalysis,
  Vulnerability,
  ContractPermission,
  AuditStatus,
} from "../../utils/types";

// ===========================================
//          Contract Verification
// ===========================================

interface EtherscanVerificationResult {
  isVerified: boolean;
  contractName?: string;
  sourceCode?: string;
  abi?: string;
  compilerVersion?: string;
  optimizationUsed?: boolean;
  runs?: number;
  constructorArguments?: string;
  evmVersion?: string;
  library?: string;
  licenseType?: string;
  proxy?: boolean;
  implementation?: string;
}

/**
 * Check contract verification status on Etherscan
 */
export async function verifyContractOnEtherscan(
  address: string,
  apiKey: string,
  chainId: number = 1
): Promise<EtherscanVerificationResult> {
  const apiBaseUrls: Record<number, string> = {
    1: "https://api.etherscan.io/api",
    11155111: "https://api-sepolia.etherscan.io/api",
    42161: "https://api.arbiscan.io/api",
    10: "https://api-optimistic.etherscan.io/api",
    8453: "https://api.basescan.org/api",
    137: "https://api.polygonscan.com/api",
    56: "https://api.bscscan.com/api",
  };

  const apiBaseUrl = apiBaseUrls[chainId] || apiBaseUrls[1];

  try {
    const response = await fetch(
      `${apiBaseUrl}?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`
    );

    const data = await response.json() as any;

    if (data.status !== "1" || !data.result?.[0]) {
      return { isVerified: false };
    }

    const result = data.result[0];

    // Contract is verified if SourceCode is not empty
    if (!result.SourceCode || result.SourceCode === "") {
      return { isVerified: false };
    }

    return {
      isVerified: true,
      contractName: result.ContractName,
      sourceCode: result.SourceCode,
      abi: result.ABI,
      compilerVersion: result.CompilerVersion,
      optimizationUsed: result.OptimizationUsed === "1",
      runs: parseInt(result.Runs, 10),
      constructorArguments: result.ConstructorArguments,
      evmVersion: result.EVMVersion,
      library: result.Library,
      licenseType: result.LicenseType,
      proxy: result.Proxy === "1",
      implementation: result.Implementation,
    };
  } catch (error) {
    console.error("Etherscan verification check failed:", error);
    return { isVerified: false };
  }
}

// ===========================================
//          Source Code Analysis
// ===========================================

/**
 * Analyze contract source code for security vulnerabilities
 */
export async function analyzeContractSource(
  sourceCode: string,
  contractName: string
): Promise<{
  vulnerabilities: Vulnerability[];
  permissions: ContractPermission[];
}> {
  const vulnerabilities: Vulnerability[] = [];
  const permissions: ContractPermission[] = [];

  // Static analysis patterns
  const securityPatterns = [
    {
      id: "reentrancy",
      pattern: /\.call\{value:/g,
      severity: RiskLevel.HIGH,
      name: "Potential Reentrancy",
      description:
        "External call with value transfer detected. Ensure state changes occur before external calls.",
      recommendation: "Use ReentrancyGuard or checks-effects-interactions pattern.",
      swcId: "SWC-107",
    },
    {
      id: "unchecked-return",
      pattern: /\.transfer\(|\.send\(/g,
      severity: RiskLevel.MEDIUM,
      name: "Unchecked Return Value",
      description:
        "Low-level call that may silently fail. Consider using OpenZeppelin's SafeERC20.",
      recommendation: "Check return values or use SafeERC20 for token transfers.",
      swcId: "SWC-104",
    },
    {
      id: "tx-origin",
      pattern: /tx\.origin/g,
      severity: RiskLevel.HIGH,
      name: "tx.origin Usage",
      description:
        "Using tx.origin for authorization is vulnerable to phishing attacks.",
      recommendation: "Use msg.sender instead of tx.origin for authorization.",
      swcId: "SWC-115",
    },
    {
      id: "delegatecall",
      pattern: /\.delegatecall\(/g,
      severity: RiskLevel.CRITICAL,
      name: "Delegatecall Usage",
      description:
        "Delegatecall to external contract can be dangerous if target is user-controlled.",
      recommendation: "Ensure delegatecall targets are trusted and immutable.",
      swcId: "SWC-112",
    },
    {
      id: "selfdestruct",
      pattern: /selfdestruct\(|suicide\(/g,
      severity: RiskLevel.CRITICAL,
      name: "Selfdestruct Detected",
      description:
        "Contract can be destroyed, potentially causing loss of funds.",
      recommendation: "Remove selfdestruct if not absolutely necessary.",
      swcId: "SWC-106",
    },
    {
      id: "arbitrary-send",
      pattern: /payable\([^)]+\)\.transfer\(|\.call\{value:\s*[^}]+\}\(/g,
      severity: RiskLevel.HIGH,
      name: "Arbitrary ETH Send",
      description:
        "Sending ETH to potentially arbitrary address.",
      recommendation: "Validate destination addresses carefully.",
      swcId: "SWC-105",
    },
    {
      id: "timestamp-dependency",
      pattern: /block\.timestamp|now/g,
      severity: RiskLevel.LOW,
      name: "Timestamp Dependency",
      description:
        "Block timestamp can be manipulated by miners within ~15 seconds.",
      recommendation: "Avoid using block.timestamp for critical logic.",
      swcId: "SWC-116",
    },
    {
      id: "weak-randomness",
      pattern: /block\.difficulty|block\.number|blockhash/g,
      severity: RiskLevel.MEDIUM,
      name: "Weak Randomness Source",
      description:
        "Using blockchain values for randomness is predictable.",
      recommendation: "Use Chainlink VRF or similar for secure randomness.",
      swcId: "SWC-120",
    },
  ];

  // Permission/role patterns
  const permissionPatterns = [
    {
      pattern: /onlyOwner|Ownable/g,
      role: "owner",
      description: "Owner role detected",
    },
    {
      pattern: /AccessControl|hasRole/g,
      role: "admin",
      description: "Role-based access control detected",
    },
    {
      pattern: /Pausable|_pause\(\)|whenNotPaused/g,
      role: "pauser",
      description: "Pausable functionality detected",
    },
    {
      pattern: /mint\s*\(/g,
      role: "minter",
      description: "Minting capability detected",
    },
  ];

  // Check for vulnerabilities
  for (const check of securityPatterns) {
    const matches = sourceCode.match(check.pattern);
    if (matches && matches.length > 0) {
      vulnerabilities.push({
        id: check.id,
        name: check.name,
        severity: check.severity,
        description: check.description,
        recommendation: check.recommendation,
        swcId: check.swcId,
        location: `${matches.length} instance(s) found in ${contractName}`,
      });
    }
  }

  // Check for permission patterns
  for (const perm of permissionPatterns) {
    const matches = sourceCode.match(perm.pattern);
    if (matches) {
      permissions.push({
        role: perm.role,
        address: "Unknown - requires on-chain analysis",
        functions: [],
        isRenounced: false,
      });
    }
  }

  return { vulnerabilities, permissions };
}

// ===========================================
//          Bytecode Analysis
// ===========================================

/**
 * Analyze contract bytecode for suspicious patterns
 */
export function analyzeBytecode(bytecode: string): {
  suspicious: boolean;
  patterns: string[];
  riskLevel: RiskLevel;
} {
  const foundPatterns: string[] = [];
  const normalizedBytecode = bytecode.toLowerCase().replace("0x", "");

  // Check for malicious patterns
  for (const pattern of MALICIOUS_BYTECODE_PATTERNS) {
    if (normalizedBytecode.includes(pattern)) {
      foundPatterns.push(pattern);
    }
  }

  // Determine risk level based on patterns
  let riskLevel = RiskLevel.SAFE;
  if (foundPatterns.includes("ff")) {
    riskLevel = RiskLevel.HIGH; // SELFDESTRUCT
  } else if (foundPatterns.length > 0) {
    riskLevel = RiskLevel.MEDIUM;
  }

  return {
    suspicious: foundPatterns.length > 0,
    patterns: foundPatterns,
    riskLevel,
  };
}

// ===========================================
//          Full Contract Analysis
// ===========================================

/**
 * Perform comprehensive contract security analysis
 */
export async function performContractSecurityAnalysis(
  address: string,
  bytecode: string,
  options?: {
    etherscanApiKey?: string;
    chainId?: number;
  }
): Promise<ContractSecurityAnalysis> {
  let isVerified = false;
  let sourceCode: string | undefined;
  let compilerVersion: string | undefined;
  let optimizationEnabled: boolean | undefined;
  let vulnerabilities: Vulnerability[] = [];
  let permissions: ContractPermission[] = [];

  // Check Etherscan verification
  if (options?.etherscanApiKey) {
    const verification = await verifyContractOnEtherscan(
      address,
      options.etherscanApiKey,
      options.chainId
    );

    isVerified = verification.isVerified;
    sourceCode = verification.sourceCode;
    compilerVersion = verification.compilerVersion;
    optimizationEnabled = verification.optimizationUsed;

    // Analyze source if available
    if (sourceCode && verification.contractName) {
      const analysis = await analyzeContractSource(
        sourceCode,
        verification.contractName
      );
      vulnerabilities = analysis.vulnerabilities;
      permissions = analysis.permissions;
    }
  }

  // Analyze bytecode
  const bytecodeAnalysis = analyzeBytecode(bytecode);
  if (bytecodeAnalysis.suspicious) {
    vulnerabilities.push({
      id: "suspicious-bytecode",
      name: "Suspicious Bytecode Patterns",
      severity: bytecodeAnalysis.riskLevel,
      description: `Detected suspicious bytecode patterns: ${bytecodeAnalysis.patterns.join(", ")}`,
      recommendation: "Review contract thoroughly before interacting.",
    });
  }

  // Calculate risk score
  const riskFactors: RiskFactor[] = vulnerabilities.map((v) => ({
    type: v.id,
    severity: v.severity,
    description: v.description,
    impact: v.severity === RiskLevel.CRITICAL ? 40 : v.severity === RiskLevel.HIGH ? 25 : 15,
  }));

  if (!isVerified) {
    riskFactors.push({
      type: "unverified",
      severity: RiskLevel.MEDIUM,
      description: "Contract source code is not verified on block explorer.",
      impact: 20,
    });
  }

  const totalImpact = riskFactors.reduce((sum, f) => sum + f.impact, 0);
  const normalizedScore = Math.min(100, totalImpact);

  let level: RiskLevel;
  if (normalizedScore >= 80) level = RiskLevel.CRITICAL;
  else if (normalizedScore >= 50) level = RiskLevel.HIGH;
  else if (normalizedScore >= 30) level = RiskLevel.MEDIUM;
  else if (normalizedScore > 0) level = RiskLevel.LOW;
  else level = RiskLevel.SAFE;

  return {
    address,
    isVerified,
    sourceCode,
    compilerVersion,
    optimizationEnabled,
    vulnerabilities,
    permissions,
    riskScore: {
      level,
      score: normalizedScore,
      factors: riskFactors,
      recommendation:
        level === RiskLevel.CRITICAL
          ? "Do not interact with this contract without thorough audit."
          : level === RiskLevel.HIGH
          ? "High risk - proceed with extreme caution."
          : level === RiskLevel.MEDIUM
          ? "Some risks detected - review before proceeding."
          : "Contract appears relatively safe.",
    },
  };
}
