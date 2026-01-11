/**
 * AI Contract Generator
 *
 * Generates smart contracts from natural language descriptions
 * using Claude or GPT-4 APIs
 */

import {
  ContractGenerationRequest,
  GeneratedContract,
  ContractSecurityAnalysis,
} from "../../utils/types";
import { RiskLevel } from "../../utils/constants";

// ===========================================
//          AI Provider Configuration
// ===========================================

export interface AIProviderConfig {
  provider: "claude" | "openai";
  apiKey: string;
  model?: string;
  maxTokens?: number;
  temperature?: number;
}

const DEFAULT_MODELS = {
  claude: "claude-3-5-sonnet-20241022",
  openai: "gpt-4-turbo-preview",
};

// ===========================================
//          Contract Generation
// ===========================================

/**
 * Generate a smart contract from natural language description
 */
export async function generateContract(
  request: ContractGenerationRequest,
  aiConfig: AIProviderConfig
): Promise<GeneratedContract> {
  // Build the prompt
  const prompt = buildGenerationPrompt(request);

  // Call AI provider
  let response: string;
  if (aiConfig.provider === "claude") {
    response = await callClaudeAPI(prompt, aiConfig);
  } else {
    response = await callOpenAIAPI(prompt, aiConfig);
  }

  // Parse the response
  const parsed = parseGeneratedContract(response);

  // Perform security analysis on generated code
  const securityAnalysis = await analyzeGeneratedContract(parsed.sourceCode);

  return {
    ...parsed,
    securityAnalysis,
  };
}

// ===========================================
//          Prompt Building
// ===========================================

/**
 * Build the prompt for contract generation
 */
function buildGenerationPrompt(request: ContractGenerationRequest): string {
  const securityLevel = request.securityLevel || "standard";

  let securityInstructions = "";
  switch (securityLevel) {
    case "enterprise":
      securityInstructions = `
- Include comprehensive access control with role-based permissions
- Add emergency pause functionality
- Implement rate limiting where applicable
- Add reentrancy guards on all external calls
- Include event emission for all state changes
- Add input validation for all functions
- Implement upgradeability using UUPS or Transparent proxy pattern
- Add timelock for sensitive operations`;
      break;
    case "standard":
      securityInstructions = `
- Include basic access control (Ownable)
- Add reentrancy guards where needed
- Include event emission for important operations
- Add basic input validation`;
      break;
    case "basic":
      securityInstructions = `
- Include minimal access control
- Add basic safety checks`;
      break;
  }

  const templateHint = request.template
    ? `\nBase this on the ${request.template} pattern.`
    : "";

  const featuresHint = request.features?.length
    ? `\nInclude these features: ${request.features.join(", ")}`
    : "";

  return `You are an expert Solidity smart contract developer. Generate a production-ready smart contract based on the following requirements.

## Requirements
${request.description}
${templateHint}
${featuresHint}

## Security Level: ${securityLevel}
${securityInstructions}

## Output Format
Provide the complete smart contract in the following format:

\`\`\`solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Your contract code here
\`\`\`

## Additional Requirements
1. Use OpenZeppelin contracts where appropriate
2. Follow Solidity best practices and naming conventions
3. Include NatSpec documentation for all public functions
4. Optimize for gas efficiency
5. Do not use deprecated patterns

After the contract code, provide:
1. A brief explanation of the contract
2. Constructor arguments if any
3. Key functions overview
4. Security considerations
5. Deployment notes`;
}

// ===========================================
//          AI API Calls
// ===========================================

/**
 * Call Claude API for contract generation
 */
async function callClaudeAPI(
  prompt: string,
  config: AIProviderConfig
): Promise<string> {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": config.apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: config.model || DEFAULT_MODELS.claude,
      max_tokens: config.maxTokens || 4096,
      temperature: config.temperature || 0.3,
      messages: [
        {
          role: "user",
          content: prompt,
        },
      ],
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Claude API error: ${error}`);
  }

  const data = await response.json();
  return (data as any).content[0].text;
}

/**
 * Call OpenAI API for contract generation
 */
async function callOpenAIAPI(
  prompt: string,
  config: AIProviderConfig
): Promise<string> {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify({
      model: config.model || DEFAULT_MODELS.openai,
      max_tokens: config.maxTokens || 4096,
      temperature: config.temperature || 0.3,
      messages: [
        {
          role: "system",
          content:
            "You are an expert Solidity smart contract developer specializing in secure, gas-optimized contracts.",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI API error: ${error}`);
  }

  const data = await response.json();
  return (data as any).choices[0].message.content;
}

// ===========================================
//          Response Parsing
// ===========================================

/**
 * Parse the generated contract from AI response
 */
function parseGeneratedContract(response: string): Omit<
  GeneratedContract,
  "securityAnalysis"
> {
  // Extract Solidity code block
  const codeMatch = response.match(/```solidity\n([\s\S]*?)\n```/);
  const sourceCode = codeMatch ? codeMatch[1].trim() : "";

  if (!sourceCode) {
    throw new Error("Failed to extract Solidity code from AI response");
  }

  // Extract documentation
  const docStartIndex = response.lastIndexOf("```") + 3;
  const documentation = response.slice(docStartIndex).trim();

  // Generate placeholder ABI (would need actual compilation)
  const abi: unknown[] = [];

  // Generate placeholder bytecode
  const bytecode = "0x";

  // Estimate gas (placeholder)
  const gasEstimate = BigInt(2000000);

  return {
    sourceCode,
    abi,
    bytecode,
    gasEstimate,
    documentation,
  };
}

// ===========================================
//          Security Analysis
// ===========================================

/**
 * Analyze generated contract for security issues
 */
async function analyzeGeneratedContract(
  sourceCode: string
): Promise<ContractSecurityAnalysis> {
  const vulnerabilities: Array<{
    id: string;
    name: string;
    severity: RiskLevel;
    description: string;
    recommendation: string;
    location?: string;
  }> = [];

  // Static analysis patterns
  const checks = [
    {
      pattern: /\.call\{value:/g,
      id: "external-call",
      name: "External Call with Value",
      severity: RiskLevel.MEDIUM,
      description: "External call with value transfer detected",
      recommendation: "Ensure reentrancy guard is in place",
    },
    {
      pattern: /tx\.origin/g,
      id: "tx-origin",
      name: "tx.origin Usage",
      severity: RiskLevel.HIGH,
      description: "tx.origin should not be used for authorization",
      recommendation: "Use msg.sender instead",
    },
    {
      pattern: /selfdestruct/g,
      id: "selfdestruct",
      name: "Selfdestruct Present",
      severity: RiskLevel.HIGH,
      description: "Contract can be destroyed",
      recommendation: "Remove selfdestruct if not required",
    },
    {
      pattern: /assembly\s*\{/g,
      id: "inline-assembly",
      name: "Inline Assembly",
      severity: RiskLevel.LOW,
      description: "Inline assembly usage detected",
      recommendation: "Ensure assembly code is reviewed carefully",
    },
  ];

  for (const check of checks) {
    const matches = sourceCode.match(check.pattern);
    if (matches) {
      vulnerabilities.push({
        id: check.id,
        name: check.name,
        severity: check.severity,
        description: check.description,
        recommendation: check.recommendation,
        location: `${matches.length} occurrence(s)`,
      });
    }
  }

  // Check for good practices
  const hasReentrancyGuard =
    sourceCode.includes("ReentrancyGuard") ||
    sourceCode.includes("nonReentrant");
  const hasAccessControl =
    sourceCode.includes("Ownable") ||
    sourceCode.includes("AccessControl");
  const hasPausable = sourceCode.includes("Pausable");

  if (!hasReentrancyGuard && sourceCode.includes(".call{")) {
    vulnerabilities.push({
      id: "missing-reentrancy-guard",
      name: "Missing Reentrancy Guard",
      severity: RiskLevel.HIGH,
      description: "External calls present without reentrancy protection",
      recommendation: "Add OpenZeppelin ReentrancyGuard",
    });
  }

  // Calculate risk score
  const totalImpact = vulnerabilities.reduce((sum, v) => {
    const impactMap: Record<RiskLevel, number> = {
      [RiskLevel.CRITICAL]: 40,
      [RiskLevel.HIGH]: 25,
      [RiskLevel.MEDIUM]: 15,
      [RiskLevel.LOW]: 5,
      [RiskLevel.SAFE]: 0,
    };
    return sum + (impactMap[v.severity] || 0);
  }, 0);

  const normalizedScore = Math.min(100, totalImpact);
  let level: RiskLevel;
  if (normalizedScore >= 80) level = RiskLevel.CRITICAL;
  else if (normalizedScore >= 50) level = RiskLevel.HIGH;
  else if (normalizedScore >= 30) level = RiskLevel.MEDIUM;
  else if (normalizedScore > 0) level = RiskLevel.LOW;
  else level = RiskLevel.SAFE;

  return {
    address: "generated",
    isVerified: false,
    sourceCode,
    vulnerabilities,
    permissions: [],
    riskScore: {
      level,
      score: normalizedScore,
      factors: vulnerabilities.map((v) => ({
        type: v.id,
        severity: v.severity,
        description: v.description,
        impact:
          v.severity === RiskLevel.CRITICAL
            ? 40
            : v.severity === RiskLevel.HIGH
            ? 25
            : 15,
      })),
      recommendation:
        normalizedScore > 50
          ? "Generated contract has security issues that need to be addressed."
          : "Generated contract appears relatively secure.",
    },
  };
}

// ===========================================
//          Contract Improvement
// ===========================================

/**
 * Request AI to improve/fix a contract based on security analysis
 */
export async function improveContract(
  sourceCode: string,
  issues: string[],
  aiConfig: AIProviderConfig
): Promise<string> {
  const prompt = `You are an expert Solidity security auditor. Improve the following smart contract to address these issues:

## Issues to Fix
${issues.map((i, idx) => `${idx + 1}. ${i}`).join("\n")}

## Original Contract
\`\`\`solidity
${sourceCode}
\`\`\`

## Requirements
1. Fix all listed issues
2. Maintain the original functionality
3. Follow security best practices
4. Optimize for gas where possible

Provide the improved contract:`;

  if (aiConfig.provider === "claude") {
    return await callClaudeAPI(prompt, aiConfig);
  } else {
    return await callOpenAIAPI(prompt, aiConfig);
  }
}
