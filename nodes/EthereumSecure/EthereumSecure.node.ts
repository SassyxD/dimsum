/**
 * Ethereum Secure Platform - Main Node
 *
 * Comprehensive Ethereum operations with advanced security features
 */

import {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
} from "n8n-workflow";
import {
  createPublicClient,
  http,
  webSocket,
  formatEther,
  formatUnits,
  parseEther,
  parseUnits,
  isAddress,
  PublicClient,
  WalletClient,
} from "viem";
import { privateKeyToAccount, mnemonicToAccount } from "viem/accounts";

// Import modules
import {
  analyzeAddress,
  analyzeTransactionThreats,
  performContractSecurityAnalysis,
  checkSanctions,
  detectHoneypot,
  calculateRiskScore,
  formatRiskScore,
} from "../../modules/security";
import {
  generateContract,
  getTemplates,
  getTemplateById,
  renderTemplate,
  analyzeContractSecurity,
  generateSecurityReport,
} from "../../modules/ai-contract";
import { RiskLevel, AuditEventType } from "../../utils/constants";

export class EthereumSecure implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Ethereum Secure",
    name: "ethereumSecure",
    icon: "file:ethereum-secure.svg",
    group: ["transform"],
    version: 1,
    subtitle: '={{$parameter["resource"] + ": " + $parameter["operation"]}}',
    description:
      "AI-Powered Ethereum Platform with Advanced Cybersecurity",
    defaults: {
      name: "Ethereum Secure",
    },
    inputs: ["main"],
    outputs: ["main"],
    credentials: [
      {
        name: "ethereumRpc",
        required: true,
      },
      {
        name: "ethereumSecureAccount",
        required: false,
      },
      {
        name: "aiProvider",
        required: false,
      },
      {
        name: "threatIntelligence",
        required: false,
      },
    ],
    properties: [
      // ===========================================
      //          Resource Selection
      // ===========================================
      {
        displayName: "Resource",
        name: "resource",
        type: "options",
        noDataExpression: true,
        options: [
          {
            name: "🔒 Security",
            value: "security",
            description: "Security analysis and threat detection",
          },
          {
            name: "🤖 AI Contract",
            value: "aiContract",
            description: "AI-powered contract generation",
          },
          {
            name: "📊 Account",
            value: "account",
            description: "Account operations with security checks",
          },
          {
            name: "📝 Transaction",
            value: "transaction",
            description: "Secure transaction execution",
          },
          {
            name: "📜 Contract",
            value: "contract",
            description: "Smart contract interactions",
          },
          {
            name: "🪙 ERC20",
            value: "erc20",
            description: "Token operations with scam detection",
          },
          {
            name: "🖼️ ERC721",
            value: "erc721",
            description: "NFT operations",
          },
          {
            name: "📦 ERC1155",
            value: "erc1155",
            description: "Multi-token operations",
          },
          {
            name: "⛽ Gas",
            value: "gas",
            description: "Gas estimation and optimization",
          },
          {
            name: "🔧 Utils",
            value: "utils",
            description: "Utility functions",
          },
        ],
        default: "security",
      },

      // ===========================================
      //          Security Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["security"],
          },
        },
        options: [
          {
            name: "Analyze Address",
            value: "analyzeAddress",
            description: "Comprehensive security analysis of an address",
            action: "Analyze address security",
          },
          {
            name: "Analyze Transaction",
            value: "analyzeTransaction",
            description: "Pre-flight security analysis of a transaction",
            action: "Analyze transaction security",
          },
          {
            name: "Verify Contract",
            value: "verifyContract",
            description: "Check contract verification and security",
            action: "Verify contract security",
          },
          {
            name: "Check Sanctions",
            value: "checkSanctions",
            description: "Check if address is on sanctions list",
            action: "Check sanctions status",
          },
          {
            name: "Detect Honeypot",
            value: "detectHoneypot",
            description: "Analyze token for honeypot characteristics",
            action: "Detect honeypot token",
          },
          {
            name: "Get Risk Score",
            value: "getRiskScore",
            description: "Calculate risk score for an address or transaction",
            action: "Get risk score",
          },
        ],
        default: "analyzeAddress",
      },

      // Security: Analyze Address
      {
        displayName: "Address",
        name: "address",
        type: "string",
        displayOptions: {
          show: {
            resource: ["security"],
            operation: [
              "analyzeAddress",
              "verifyContract",
              "checkSanctions",
              "detectHoneypot",
              "getRiskScore",
            ],
          },
        },
        default: "",
        placeholder: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        description: "The Ethereum address to analyze",
        required: true,
      },

      // Security: Analyze Transaction
      {
        displayName: "To Address",
        name: "toAddress",
        type: "string",
        displayOptions: {
          show: {
            resource: ["security"],
            operation: ["analyzeTransaction"],
          },
        },
        default: "",
        required: true,
        description: "Recipient address",
      },
      {
        displayName: "Value (ETH)",
        name: "value",
        type: "number",
        displayOptions: {
          show: {
            resource: ["security"],
            operation: ["analyzeTransaction"],
          },
        },
        default: 0,
        description: "Transaction value in ETH",
      },
      {
        displayName: "Data",
        name: "data",
        type: "string",
        displayOptions: {
          show: {
            resource: ["security"],
            operation: ["analyzeTransaction"],
          },
        },
        default: "0x",
        description: "Transaction calldata (for contract calls)",
      },
      {
        displayName: "Check MEV Vulnerability",
        name: "checkMEV",
        type: "boolean",
        displayOptions: {
          show: {
            resource: ["security"],
            operation: ["analyzeTransaction"],
          },
        },
        default: true,
        description: "Check for MEV (sandwich attack) vulnerability",
      },

      // ===========================================
      //          AI Contract Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["aiContract"],
          },
        },
        options: [
          {
            name: "Generate Contract",
            value: "generateContract",
            description: "Generate a smart contract from natural language",
            action: "Generate smart contract",
          },
          {
            name: "Analyze Code",
            value: "analyzeCode",
            description: "Security analysis of Solidity code",
            action: "Analyze Solidity code",
          },
          {
            name: "List Templates",
            value: "listTemplates",
            description: "Get available contract templates",
            action: "List contract templates",
          },
          {
            name: "Render Template",
            value: "renderTemplate",
            description: "Generate contract from template",
            action: "Render contract template",
          },
          {
            name: "Generate Report",
            value: "generateReport",
            description: "Generate security audit report",
            action: "Generate security report",
          },
        ],
        default: "generateContract",
      },

      // AI Contract: Generate Contract
      {
        displayName: "Description",
        name: "description",
        type: "string",
        typeOptions: {
          rows: 5,
        },
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["generateContract"],
          },
        },
        default: "",
        placeholder:
          "Create an ERC20 token called SecureToken with symbol SCT, 1 million supply, burnable and pausable",
        description: "Natural language description of the contract",
        required: true,
      },
      {
        displayName: "Security Level",
        name: "securityLevel",
        type: "options",
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["generateContract"],
          },
        },
        options: [
          {
            name: "Basic",
            value: "basic",
            description: "Minimal security features",
          },
          {
            name: "Standard",
            value: "standard",
            description: "Recommended security features",
          },
          {
            name: "Enterprise",
            value: "enterprise",
            description: "Maximum security with all protections",
          },
        ],
        default: "standard",
      },
      {
        displayName: "Base Template",
        name: "template",
        type: "options",
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["generateContract"],
          },
        },
        options: [
          { name: "None (Generate from scratch)", value: "" },
          { name: "ERC20 Standard", value: "erc20-standard" },
          { name: "ERC20 Mintable/Burnable", value: "erc20-mintable-burnable" },
          { name: "ERC20 Pausable", value: "erc20-pausable" },
          { name: "ERC721 NFT", value: "erc721-standard" },
          { name: "Multi-Sig Wallet", value: "multisig-wallet" },
          { name: "Timelock Controller", value: "timelock-controller" },
        ],
        default: "",
      },

      // AI Contract: Analyze Code
      {
        displayName: "Solidity Code",
        name: "sourceCode",
        type: "string",
        typeOptions: {
          rows: 20,
        },
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["analyzeCode", "generateReport"],
          },
        },
        default: "",
        description: "Solidity source code to analyze",
        required: true,
      },
      {
        displayName: "Contract Name",
        name: "contractName",
        type: "string",
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["generateReport"],
          },
        },
        default: "Contract",
        description: "Name of the contract for the report",
      },

      // AI Contract: Render Template
      {
        displayName: "Template ID",
        name: "templateId",
        type: "options",
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["renderTemplate"],
          },
        },
        options: [
          { name: "ERC20 Standard", value: "erc20-standard" },
          { name: "ERC20 Mintable/Burnable", value: "erc20-mintable-burnable" },
          { name: "ERC20 Pausable", value: "erc20-pausable" },
          { name: "ERC721 NFT", value: "erc721-standard" },
          { name: "Multi-Sig Wallet", value: "multisig-wallet" },
          { name: "Timelock Controller", value: "timelock-controller" },
        ],
        default: "erc20-standard",
        required: true,
      },
      {
        displayName: "Template Parameters",
        name: "templateParams",
        type: "json",
        displayOptions: {
          show: {
            resource: ["aiContract"],
            operation: ["renderTemplate"],
          },
        },
        default: '{"name": "MyToken", "symbol": "MTK", "initialSupply": "1000000000000000000000000"}',
        description: "Parameters to fill in the template (JSON)",
      },

      // ===========================================
      //          Account Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["account"],
          },
        },
        options: [
          {
            name: "Get Balance (Secure)",
            value: "getBalance",
            description: "Get balance with risk assessment",
            action: "Get balance with security",
          },
          {
            name: "Get Transaction Count",
            value: "getTransactionCount",
            description: "Get nonce for an address",
            action: "Get transaction count",
          },
          {
            name: "Is Contract",
            value: "isContract",
            description: "Check if address is a smart contract",
            action: "Check if contract",
          },
          {
            name: "Get Current Address",
            value: "getCurrentAddress",
            description: "Get configured wallet address",
            action: "Get current address",
          },
        ],
        default: "getBalance",
      },

      // Account: Address parameter
      {
        displayName: "Address",
        name: "accountAddress",
        type: "string",
        displayOptions: {
          show: {
            resource: ["account"],
            operation: ["getBalance", "getTransactionCount", "isContract"],
          },
        },
        default: "",
        placeholder: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        description: "The Ethereum address",
        required: true,
      },
      {
        displayName: "Include Security Analysis",
        name: "includeSecurityAnalysis",
        type: "boolean",
        displayOptions: {
          show: {
            resource: ["account"],
            operation: ["getBalance", "isContract"],
          },
        },
        default: true,
        description: "Include security risk assessment",
      },

      // ===========================================
      //          Transaction Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["transaction"],
          },
        },
        options: [
          {
            name: "Send (Secure)",
            value: "send",
            description: "Send transaction with pre-flight security checks",
            action: "Send secure transaction",
          },
          {
            name: "Simulate",
            value: "simulate",
            description: "Simulate transaction before execution",
            action: "Simulate transaction",
          },
          {
            name: "Get Transaction",
            value: "getTransaction",
            description: "Get transaction details",
            action: "Get transaction",
          },
          {
            name: "Get Receipt",
            value: "getReceipt",
            description: "Get transaction receipt",
            action: "Get transaction receipt",
          },
        ],
        default: "send",
      },

      // Transaction: Send parameters
      {
        displayName: "To",
        name: "txTo",
        type: "string",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["send", "simulate"],
          },
        },
        default: "",
        required: true,
        description: "Recipient address",
      },
      {
        displayName: "Value (ETH)",
        name: "txValue",
        type: "string",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["send", "simulate"],
          },
        },
        default: "0",
        description: "Amount of ETH to send",
      },
      {
        displayName: "Data",
        name: "txData",
        type: "string",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["send", "simulate"],
          },
        },
        default: "0x",
        description: "Transaction data (calldata)",
      },
      {
        displayName: "Enable Security Checks",
        name: "enableSecurityChecks",
        type: "boolean",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["send"],
          },
        },
        default: true,
        description: "Run pre-flight security analysis before sending",
      },
      {
        displayName: "Block If High Risk",
        name: "blockHighRisk",
        type: "boolean",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["send"],
          },
        },
        default: false,
        description: "Automatically block high-risk transactions",
      },

      // Transaction: Get parameters
      {
        displayName: "Transaction Hash",
        name: "txHash",
        type: "string",
        displayOptions: {
          show: {
            resource: ["transaction"],
            operation: ["getTransaction", "getReceipt"],
          },
        },
        default: "",
        required: true,
        description: "The transaction hash",
      },

      // ===========================================
      //          ERC20 Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["erc20"],
          },
        },
        options: [
          {
            name: "Get Token Info (Secure)",
            value: "getTokenInfo",
            description: "Get token info with security analysis",
            action: "Get token info",
          },
          {
            name: "Get Balance",
            value: "getBalance",
            description: "Get token balance of an address",
            action: "Get token balance",
          },
          {
            name: "Transfer (Secure)",
            value: "transfer",
            description: "Transfer tokens with security checks",
            action: "Transfer tokens",
          },
          {
            name: "Approve (Secure)",
            value: "approve",
            description: "Approve spender with warnings",
            action: "Approve spender",
          },
          {
            name: "Check Allowance",
            value: "getAllowance",
            description: "Check spending allowance",
            action: "Check allowance",
          },
        ],
        default: "getTokenInfo",
      },

      // ERC20: Token Address
      {
        displayName: "Token Address",
        name: "tokenAddress",
        type: "string",
        displayOptions: {
          show: {
            resource: ["erc20"],
          },
        },
        default: "",
        required: true,
        description: "The ERC20 token contract address",
      },

      // ERC20: Holder Address
      {
        displayName: "Holder Address",
        name: "holderAddress",
        type: "string",
        displayOptions: {
          show: {
            resource: ["erc20"],
            operation: ["getBalance", "getAllowance"],
          },
        },
        default: "",
        description: "Address to check balance/allowance (leave empty for current wallet)",
      },

      // ERC20: Spender for allowance
      {
        displayName: "Spender Address",
        name: "spenderAddress",
        type: "string",
        displayOptions: {
          show: {
            resource: ["erc20"],
            operation: ["getAllowance", "approve"],
          },
        },
        default: "",
        required: true,
        description: "Spender address",
      },

      // ERC20: Transfer recipient
      {
        displayName: "Recipient",
        name: "recipient",
        type: "string",
        displayOptions: {
          show: {
            resource: ["erc20"],
            operation: ["transfer"],
          },
        },
        default: "",
        required: true,
        description: "Recipient address",
      },

      // ERC20: Amount
      {
        displayName: "Amount",
        name: "amount",
        type: "string",
        displayOptions: {
          show: {
            resource: ["erc20"],
            operation: ["transfer", "approve"],
          },
        },
        default: "",
        required: true,
        description: "Token amount (use MAX for unlimited approval)",
      },

      // ERC20: Security options
      {
        displayName: "Check Honeypot",
        name: "checkHoneypot",
        type: "boolean",
        displayOptions: {
          show: {
            resource: ["erc20"],
            operation: ["getTokenInfo", "transfer"],
          },
        },
        default: true,
        description: "Check if token is a potential honeypot",
      },

      // ===========================================
      //          Gas Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["gas"],
          },
        },
        options: [
          {
            name: "Get Gas Price",
            value: "getGasPrice",
            description: "Get current gas price",
            action: "Get gas price",
          },
          {
            name: "Estimate Gas",
            value: "estimateGas",
            description: "Estimate gas for a transaction",
            action: "Estimate gas",
          },
          {
            name: "Get Max Priority Fee",
            value: "getMaxPriorityFee",
            description: "Get recommended priority fee",
            action: "Get max priority fee",
          },
        ],
        default: "getGasPrice",
      },

      // ===========================================
      //          Utils Operations
      // ===========================================
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["utils"],
          },
        },
        options: [
          {
            name: "Format Units",
            value: "formatUnits",
            description: "Format wei to readable units",
            action: "Format units",
          },
          {
            name: "Parse Units",
            value: "parseUnits",
            description: "Parse units to wei",
            action: "Parse units",
          },
          {
            name: "Validate Address",
            value: "validateAddress",
            description: "Validate Ethereum address format",
            action: "Validate address",
          },
          {
            name: "Checksum Address",
            value: "checksumAddress",
            description: "Convert to checksum address",
            action: "Checksum address",
          },
        ],
        default: "formatUnits",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

    const resource = this.getNodeParameter("resource", 0) as string;
    const operation = this.getNodeParameter("operation", 0) as string;

    // Get credentials
    const rpcCredentials = await this.getCredentials("ethereumRpc");
    let accountCredentials;
    try {
      accountCredentials = await this.getCredentials("ethereumSecureAccount");
    } catch {
      // Account credentials are optional
    }

    let threatIntelCredentials;
    try {
      threatIntelCredentials = await this.getCredentials("threatIntelligence");
    } catch {
      // Threat intel credentials are optional
    }

    let aiCredentials;
    try {
      aiCredentials = await this.getCredentials("aiProvider");
    } catch {
      // AI credentials are optional
    }

    // Create public client
    const rpcUrl = rpcCredentials.rpcUrl as string;
    const isWebSocket = rpcUrl.startsWith("ws://") || rpcUrl.startsWith("wss://");
    const transport = isWebSocket ? webSocket(rpcUrl) : http(rpcUrl);
    const client = createPublicClient({ transport });

    for (let i = 0; i < items.length; i++) {
      try {
        let result: Record<string, unknown> = {};

        // ===========================================
        //          Security Operations
        // ===========================================
        if (resource === "security") {
          if (operation === "analyzeAddress") {
            const address = this.getNodeParameter("address", i) as string;
            const analysis = await analyzeAddress(client, address, {
              etherscanApiKey: threatIntelCredentials?.etherscanApiKey as string,
              checkSanctions: true,
            });
            const formatted = formatRiskScore(analysis.riskScore);
            result = {
              ...analysis,
              riskDisplay: formatted,
            };
          }

          if (operation === "analyzeTransaction") {
            const to = this.getNodeParameter("toAddress", i) as string;
            const value = this.getNodeParameter("value", i) as number;
            const data = this.getNodeParameter("data", i) as string;
            const checkMEV = this.getNodeParameter("checkMEV", i) as boolean;

            const assessment = await analyzeTransactionThreats(
              client,
              {
                to,
                value: parseEther(value.toString()),
                data,
              },
              { checkMEV }
            );
            const formatted = formatRiskScore(assessment.riskScore);
            result = {
              ...assessment,
              riskDisplay: formatted,
            };
          }

          if (operation === "verifyContract") {
            const address = this.getNodeParameter("address", i) as string;
            const code = await client.getCode({ address: address as `0x${string}` });
            const analysis = await performContractSecurityAnalysis(
              address,
              code || "0x",
              {
                etherscanApiKey: threatIntelCredentials?.etherscanApiKey as string,
              }
            );
            result = analysis;
          }

          if (operation === "checkSanctions") {
            const address = this.getNodeParameter("address", i) as string;
            const sanctionsResult = await checkSanctions(address, {
              chainalysisApiKey: threatIntelCredentials?.chainalysisApiKey as string,
            });
            result = sanctionsResult;
          }

          if (operation === "detectHoneypot") {
            const address = this.getNodeParameter("address", i) as string;
            const honeypotResult = await detectHoneypot(client, address);
            result = honeypotResult;
          }

          if (operation === "getRiskScore") {
            const address = this.getNodeParameter("address", i) as string;
            const analysis = await analyzeAddress(client, address, {
              etherscanApiKey: threatIntelCredentials?.etherscanApiKey as string,
            });
            const formatted = formatRiskScore(analysis.riskScore);
            result = {
              address,
              score: analysis.riskScore.score,
              level: analysis.riskScore.level,
              display: formatted.summary,
              recommendation: analysis.riskScore.recommendation,
              factors: analysis.riskScore.factors,
            };
          }
        }

        // ===========================================
        //          AI Contract Operations
        // ===========================================
        if (resource === "aiContract") {
          if (operation === "generateContract") {
            if (!aiCredentials) {
              throw new NodeOperationError(
                this.getNode(),
                "AI Provider credentials required for contract generation"
              );
            }

            const description = this.getNodeParameter("description", i) as string;
            const securityLevel = this.getNodeParameter("securityLevel", i) as string;
            const template = this.getNodeParameter("template", i) as string;

            const generated = await generateContract(
              {
                description,
                template: template || undefined,
                securityLevel: securityLevel as "basic" | "standard" | "enterprise",
              },
              {
                provider: aiCredentials.provider as "claude" | "openai",
                apiKey:
                  aiCredentials.provider === "claude"
                    ? (aiCredentials.anthropicApiKey as string)
                    : (aiCredentials.openaiApiKey as string),
                model:
                  aiCredentials.provider === "claude"
                    ? (aiCredentials.claudeModel as string)
                    : (aiCredentials.openaiModel as string),
              }
            );

            result = {
              sourceCode: generated.sourceCode,
              documentation: generated.documentation,
              securityAnalysis: generated.securityAnalysis,
              gasEstimate: generated.gasEstimate.toString(),
            };
          }

          if (operation === "analyzeCode") {
            const sourceCode = this.getNodeParameter("sourceCode", i) as string;
            const analysis = analyzeContractSecurity(sourceCode);
            result = analysis;
          }

          if (operation === "listTemplates") {
            const templates = getTemplates();
            result = {
              templates: templates.map((t) => ({
                id: t.id,
                name: t.name,
                description: t.description,
                category: t.category,
                features: t.features,
                parameters: t.parameters,
              })),
            };
          }

          if (operation === "renderTemplate") {
            const templateId = this.getNodeParameter("templateId", i) as string;
            const paramsJson = this.getNodeParameter("templateParams", i) as string;
            const params = JSON.parse(paramsJson);

            const template = getTemplateById(templateId);
            if (!template) {
              throw new NodeOperationError(
                this.getNode(),
                `Template not found: ${templateId}`
              );
            }

            const rendered = renderTemplate(template, params);
            const analysis = analyzeContractSecurity(rendered);

            result = {
              sourceCode: rendered,
              templateUsed: templateId,
              securityAnalysis: analysis,
            };
          }

          if (operation === "generateReport") {
            const sourceCode = this.getNodeParameter("sourceCode", i) as string;
            const contractName = this.getNodeParameter("contractName", i) as string;
            const analysis = analyzeContractSecurity(sourceCode);
            const report = generateSecurityReport(contractName, analysis);
            result = {
              report,
              analysis,
            };
          }
        }

        // ===========================================
        //          Account Operations
        // ===========================================
        if (resource === "account") {
          if (operation === "getBalance") {
            const address = this.getNodeParameter("accountAddress", i) as string;
            const includeSecurityAnalysis = this.getNodeParameter(
              "includeSecurityAnalysis",
              i
            ) as boolean;

            const balance = await client.getBalance({
              address: address as `0x${string}`,
            });

            result = {
              address,
              balance: balance.toString(),
              balanceFormatted: formatEther(balance),
            };

            if (includeSecurityAnalysis) {
              const analysis = await analyzeAddress(client, address, {
                etherscanApiKey: threatIntelCredentials?.etherscanApiKey as string,
              });
              result.securityAnalysis = analysis;
            }
          }

          if (operation === "getTransactionCount") {
            const address = this.getNodeParameter("accountAddress", i) as string;
            const count = await client.getTransactionCount({
              address: address as `0x${string}`,
            });
            result = {
              address,
              transactionCount: count,
            };
          }

          if (operation === "isContract") {
            const address = this.getNodeParameter("accountAddress", i) as string;
            const includeSecurityAnalysis = this.getNodeParameter(
              "includeSecurityAnalysis",
              i
            ) as boolean;

            const code = await client.getCode({
              address: address as `0x${string}`,
            });
            const isContract = code !== undefined && code !== "0x";

            result = {
              address,
              isContract,
              codeSize: code ? (code.length - 2) / 2 : 0,
            };

            if (includeSecurityAnalysis && isContract) {
              const analysis = await performContractSecurityAnalysis(
                address,
                code || "0x",
                {
                  etherscanApiKey: threatIntelCredentials?.etherscanApiKey as string,
                }
              );
              result.securityAnalysis = analysis;
            }
          }

          if (operation === "getCurrentAddress") {
            if (!accountCredentials) {
              throw new NodeOperationError(
                this.getNode(),
                "Ethereum Secure Account credentials required"
              );
            }

            const accountType = accountCredentials.accountType as string;
            let address: string;

            if (accountType === "privateKey") {
              const privateKey = accountCredentials.privateKey as string;
              const formattedKey = privateKey.startsWith("0x")
                ? (privateKey as `0x${string}`)
                : (`0x${privateKey}` as `0x${string}`);
              const account = privateKeyToAccount(formattedKey);
              address = account.address;
            } else if (accountType === "mnemonic") {
              const mnemonic = accountCredentials.mnemonic as string;
              const path = (accountCredentials.path as string) || "m/44'/60'/0'/0/0";
              const account = mnemonicToAccount(mnemonic, {
                path: path as `m/44'/60'/${string}`,
              });
              address = account.address;
            } else {
              throw new NodeOperationError(
                this.getNode(),
                `Account type ${accountType} not yet supported for address derivation`
              );
            }

            result = { address };
          }
        }

        // ===========================================
        //          Gas Operations
        // ===========================================
        if (resource === "gas") {
          if (operation === "getGasPrice") {
            const gasPrice = await client.getGasPrice();
            result = {
              gasPrice: gasPrice.toString(),
              gasPriceGwei: formatUnits(gasPrice, 9),
            };
          }

          if (operation === "getMaxPriorityFee") {
            const [gasPrice, block] = await Promise.all([
              client.getGasPrice(),
              client.getBlock({ blockTag: "latest" }),
            ]);

            const baseFee = block.baseFeePerGas || 0n;
            const priorityFee = gasPrice > baseFee ? gasPrice - baseFee : 0n;

            result = {
              maxPriorityFeePerGas: priorityFee.toString(),
              maxPriorityFeeGwei: formatUnits(priorityFee, 9),
              baseFeePerGas: baseFee.toString(),
              baseFeeGwei: formatUnits(baseFee, 9),
            };
          }
        }

        // ===========================================
        //          Utils Operations
        // ===========================================
        if (resource === "utils") {
          if (operation === "validateAddress") {
            const address = this.getNodeParameter("address", i) as string;
            result = {
              address,
              isValid: isAddress(address),
            };
          }
        }

        returnData.push({
          json: result,
          pairedItem: { item: i },
        });
      } catch (error) {
        if (this.continueOnFail()) {
          returnData.push({
            json: {
              error: error instanceof Error ? error.message : String(error),
            },
            pairedItem: { item: i },
          });
          continue;
        }
        throw error;
      }
    }

    return [returnData];
  }
}
