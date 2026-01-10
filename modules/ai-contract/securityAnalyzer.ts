/**
 * Security Analyzer for Generated Contracts
 *
 * Performs static analysis and security scoring on Solidity code
 */

import { RiskLevel, RiskFactor } from "../../utils/constants";
import { Vulnerability, ContractSecurityAnalysis } from "../../utils/types";

// ===========================================
//          Security Patterns
// ===========================================

interface SecurityPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: RiskLevel;
  description: string;
  recommendation: string;
  cweId?: string;
  swcId?: string;
}

const SECURITY_PATTERNS: SecurityPattern[] = [
  // Critical vulnerabilities
  {
    id: "reentrancy",
    name: "Reentrancy Vulnerability",
    pattern: /\.call\{value:.*\}.*\n.*(?!.*nonReentrant)/s,
    severity: RiskLevel.CRITICAL,
    description: "External call with value transfer without reentrancy guard",
    recommendation: "Use ReentrancyGuard modifier or checks-effects-interactions pattern",
    swcId: "SWC-107",
    cweId: "CWE-841",
  },
  {
    id: "delegatecall-untrusted",
    name: "Delegatecall to Untrusted Callee",
    pattern: /\.delegatecall\(/g,
    severity: RiskLevel.CRITICAL,
    description: "Delegatecall can execute code in the context of calling contract",
    recommendation: "Only delegatecall to trusted, immutable addresses",
    swcId: "SWC-112",
    cweId: "CWE-829",
  },
  {
    id: "selfdestruct-arbitrary",
    name: "Arbitrary Selfdestruct",
    pattern: /selfdestruct\s*\(/g,
    severity: RiskLevel.CRITICAL,
    description: "Contract can be destroyed, potentially losing funds",
    recommendation: "Remove selfdestruct or add strict access control",
    swcId: "SWC-106",
    cweId: "CWE-284",
  },

  // High severity
  {
    id: "tx-origin-auth",
    name: "Authorization through tx.origin",
    pattern: /require\s*\(\s*tx\.origin/g,
    severity: RiskLevel.HIGH,
    description: "Using tx.origin for authorization is vulnerable to phishing",
    recommendation: "Use msg.sender for authorization",
    swcId: "SWC-115",
    cweId: "CWE-477",
  },
  {
    id: "unchecked-call",
    name: "Unchecked Call Return Value",
    pattern: /\.call\{[^}]*\}\([^)]*\)\s*;/g,
    severity: RiskLevel.HIGH,
    description: "Return value of low-level call is not checked",
    recommendation: "Always check the return value of call",
    swcId: "SWC-104",
    cweId: "CWE-252",
  },
  {
    id: "unprotected-ether",
    name: "Unprotected Ether Withdrawal",
    pattern: /function\s+withdraw[^}]*payable\s*\([^)]*\)/g,
    severity: RiskLevel.HIGH,
    description: "Withdrawal function may lack access control",
    recommendation: "Add onlyOwner or similar access control",
    swcId: "SWC-105",
    cweId: "CWE-284",
  },

  // Medium severity
  {
    id: "timestamp-dependency",
    name: "Timestamp Dependency",
    pattern: /block\.timestamp|now/g,
    severity: RiskLevel.MEDIUM,
    description: "Block timestamp can be manipulated by miners",
    recommendation: "Avoid using block.timestamp for critical logic",
    swcId: "SWC-116",
    cweId: "CWE-829",
  },
  {
    id: "weak-randomness",
    name: "Weak Sources of Randomness",
    pattern: /block\.(difficulty|number|timestamp).*random|keccak256.*block\./g,
    severity: RiskLevel.MEDIUM,
    description: "Using blockchain values for randomness is predictable",
    recommendation: "Use Chainlink VRF or commit-reveal scheme",
    swcId: "SWC-120",
    cweId: "CWE-330",
  },
  {
    id: "floating-pragma",
    name: "Floating Pragma",
    pattern: /pragma solidity\s*\^/g,
    severity: RiskLevel.MEDIUM,
    description: "Floating pragma allows compilation with different versions",
    recommendation: "Lock pragma to specific version for production",
    swcId: "SWC-103",
    cweId: "CWE-664",
  },
  {
    id: "missing-zero-check",
    name: "Missing Zero Address Check",
    pattern: /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)[^{]*\{(?![^}]*require[^}]*!=\s*address\(0\))/g,
    severity: RiskLevel.MEDIUM,
    description: "Function accepts address without zero-address validation",
    recommendation: "Add require(address != address(0)) validation",
    cweId: "CWE-20",
  },

  // Low severity
  {
    id: "unused-return",
    name: "Unused Return Value",
    pattern: /\.\w+\([^)]*\)\s*;(?!\s*(?:return|if|require))/g,
    severity: RiskLevel.LOW,
    description: "Return value from function call is not used",
    recommendation: "Check and use return values",
    swcId: "SWC-135",
  },
  {
    id: "implicit-visibility",
    name: "State Variable Default Visibility",
    pattern: /^\s*(?:uint|int|address|bool|bytes|string|mapping)\s+\w+\s*[=;]/gm,
    severity: RiskLevel.LOW,
    description: "State variable without explicit visibility",
    recommendation: "Explicitly declare visibility (public, private, internal)",
    swcId: "SWC-108",
  },
  {
    id: "outdated-compiler",
    name: "Outdated Compiler Version",
    pattern: /pragma solidity\s*[\^~]?\s*0\.[4-7]\./g,
    severity: RiskLevel.LOW,
    description: "Using older Solidity compiler version",
    recommendation: "Upgrade to Solidity 0.8.x for built-in overflow protection",
    swcId: "SWC-102",
  },
];

// ===========================================
//          Best Practices Checks
// ===========================================

interface BestPracticeCheck {
  id: string;
  name: string;
  check: (code: string) => boolean;
  severity: RiskLevel;
  description: string;
  recommendation: string;
}

const BEST_PRACTICES: BestPracticeCheck[] = [
  {
    id: "has-reentrancy-guard",
    name: "Reentrancy Guard Present",
    check: (code) => code.includes("ReentrancyGuard") || code.includes("nonReentrant"),
    severity: RiskLevel.LOW,
    description: "Contract uses reentrancy protection",
    recommendation: "Good: ReentrancyGuard is implemented",
  },
  {
    id: "has-access-control",
    name: "Access Control Present",
    check: (code) =>
      code.includes("Ownable") ||
      code.includes("AccessControl") ||
      code.includes("onlyOwner"),
    severity: RiskLevel.MEDIUM,
    description: "Contract implements access control",
    recommendation: "Add access control using Ownable or AccessControl",
  },
  {
    id: "has-events",
    name: "Events Emitted",
    check: (code) => code.includes("emit "),
    severity: RiskLevel.LOW,
    description: "Contract emits events for state changes",
    recommendation: "Add events for important state changes",
  },
  {
    id: "has-natspec",
    name: "NatSpec Documentation",
    check: (code) => code.includes("@notice") || code.includes("@dev") || code.includes("@param"),
    severity: RiskLevel.LOW,
    description: "Contract has NatSpec documentation",
    recommendation: "Add NatSpec comments for all public functions",
  },
  {
    id: "uses-safe-math",
    name: "Safe Math or 0.8+",
    check: (code) =>
      code.includes("SafeMath") || code.includes("pragma solidity ^0.8"),
    severity: RiskLevel.MEDIUM,
    description: "Contract uses safe math operations",
    recommendation: "Use Solidity 0.8+ or SafeMath library",
  },
];

// ===========================================
//          Analysis Functions
// ===========================================

/**
 * Perform comprehensive security analysis on Solidity code
 */
export function analyzeContractSecurity(sourceCode: string): {
  vulnerabilities: Vulnerability[];
  bestPractices: { id: string; passed: boolean; message: string }[];
  riskScore: number;
  riskLevel: RiskLevel;
} {
  const vulnerabilities: Vulnerability[] = [];
  const bestPractices: { id: string; passed: boolean; message: string }[] = [];

  // Check security patterns
  for (const pattern of SECURITY_PATTERNS) {
    const matches = sourceCode.match(pattern.pattern);
    if (matches) {
      vulnerabilities.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        recommendation: pattern.recommendation,
        swcId: pattern.swcId,
        cweId: pattern.cweId,
        location: `${matches.length} occurrence(s) found`,
      });
    }
  }

  // Check best practices
  for (const practice of BEST_PRACTICES) {
    const passed = practice.check(sourceCode);
    bestPractices.push({
      id: practice.id,
      passed,
      message: passed ? practice.description : practice.recommendation,
    });

    // Add as vulnerability if critical practice is missing
    if (!passed && practice.severity !== RiskLevel.LOW) {
      vulnerabilities.push({
        id: `missing-${practice.id}`,
        name: `Missing: ${practice.name}`,
        severity: practice.severity,
        description: `Best practice not implemented: ${practice.description}`,
        recommendation: practice.recommendation,
      });
    }
  }

  // Calculate risk score
  const severityScores: Record<RiskLevel, number> = {
    [RiskLevel.CRITICAL]: 40,
    [RiskLevel.HIGH]: 25,
    [RiskLevel.MEDIUM]: 15,
    [RiskLevel.LOW]: 5,
    [RiskLevel.SAFE]: 0,
  };

  const riskScore = Math.min(
    100,
    vulnerabilities.reduce((sum, v) => sum + (severityScores[v.severity] || 0), 0)
  );

  let riskLevel: RiskLevel;
  if (riskScore >= 80) riskLevel = RiskLevel.CRITICAL;
  else if (riskScore >= 50) riskLevel = RiskLevel.HIGH;
  else if (riskScore >= 30) riskLevel = RiskLevel.MEDIUM;
  else if (riskScore > 0) riskLevel = RiskLevel.LOW;
  else riskLevel = RiskLevel.SAFE;

  return {
    vulnerabilities,
    bestPractices,
    riskScore,
    riskLevel,
  };
}

/**
 * Generate a security report
 */
export function generateSecurityReport(
  contractName: string,
  analysis: ReturnType<typeof analyzeContractSecurity>
): string {
  const { vulnerabilities, bestPractices, riskScore, riskLevel } = analysis;

  const criticalCount = vulnerabilities.filter((v) => v.severity === RiskLevel.CRITICAL).length;
  const highCount = vulnerabilities.filter((v) => v.severity === RiskLevel.HIGH).length;
  const mediumCount = vulnerabilities.filter((v) => v.severity === RiskLevel.MEDIUM).length;
  const lowCount = vulnerabilities.filter((v) => v.severity === RiskLevel.LOW).length;

  let report = `# Security Analysis Report: ${contractName}

## Summary
- **Risk Score:** ${riskScore}/100
- **Risk Level:** ${riskLevel.toUpperCase()}
- **Critical Issues:** ${criticalCount}
- **High Issues:** ${highCount}
- **Medium Issues:** ${mediumCount}
- **Low Issues:** ${lowCount}

---

## Vulnerabilities

`;

  if (vulnerabilities.length === 0) {
    report += "✅ No vulnerabilities detected.\n\n";
  } else {
    for (const vuln of vulnerabilities) {
      const emoji = {
        [RiskLevel.CRITICAL]: "🔴",
        [RiskLevel.HIGH]: "🟠",
        [RiskLevel.MEDIUM]: "🟡",
        [RiskLevel.LOW]: "🟢",
        [RiskLevel.SAFE]: "✅",
      }[vuln.severity];

      report += `### ${emoji} ${vuln.name}
- **Severity:** ${vuln.severity.toUpperCase()}
- **Description:** ${vuln.description}
- **Recommendation:** ${vuln.recommendation}
${vuln.swcId ? `- **SWC ID:** ${vuln.swcId}` : ""}
${vuln.cweId ? `- **CWE ID:** ${vuln.cweId}` : ""}

`;
    }
  }

  report += `---

## Best Practices Checklist

`;

  for (const practice of bestPractices) {
    const emoji = practice.passed ? "✅" : "❌";
    report += `- ${emoji} ${practice.message}\n`;
  }

  report += `
---

## Recommendations

1. Address all critical and high severity issues before deployment
2. Consider third-party audit for production contracts
3. Implement comprehensive testing including fuzzing
4. Use formal verification for critical functions
5. Set up monitoring for deployed contracts

---

*Report generated by Ethereum Secure Platform*
`;

  return report;
}

/**
 * Get optimization suggestions
 */
export function getGasOptimizationSuggestions(sourceCode: string): string[] {
  const suggestions: string[] = [];

  // Check for common gas optimization opportunities
  if (sourceCode.includes("memory") && sourceCode.includes("for")) {
    suggestions.push("Consider using `calldata` instead of `memory` for read-only function parameters");
  }

  if (sourceCode.match(/uint256\s+\w+\s*=\s*0/g)) {
    suggestions.push("Default value for uint is 0 - no need to explicitly initialize");
  }

  if (sourceCode.includes("++i") === false && sourceCode.includes("i++")) {
    suggestions.push("Use `++i` instead of `i++` for cheaper increment");
  }

  if (sourceCode.includes("require(") && sourceCode.includes("string")) {
    suggestions.push("Consider using custom errors instead of require strings to save gas");
  }

  if (sourceCode.match(/public\s+(?!view|pure)/g)) {
    suggestions.push("Consider using `external` instead of `public` for functions not called internally");
  }

  if (!sourceCode.includes("unchecked {")) {
    suggestions.push("Use `unchecked` blocks for arithmetic that cannot overflow to save gas");
  }

  if (sourceCode.includes("storage")) {
    suggestions.push("Cache storage variables in memory when reading multiple times in a function");
  }

  return suggestions;
}
