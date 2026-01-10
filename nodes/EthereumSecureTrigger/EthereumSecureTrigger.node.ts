/**
 * Ethereum Secure Trigger Node
 *
 * Real-time blockchain monitoring with security alerts
 */

import {
  ITriggerFunctions,
  INodeType,
  INodeTypeDescription,
  ITriggerResponse,
  NodeOperationError,
} from "n8n-workflow";
import {
  createPublicClient,
  http,
  webSocket,
  formatEther,
  formatUnits,
  parseAbiItem,
  Log,
  Block,
  Transaction,
  PublicClient,
  WatchBlocksReturnType,
  WatchEventReturnType,
} from "viem";

import {
  analyzeAddress,
  analyzeTransactionThreats,
  checkSanctions,
  detectHoneypot,
  formatRiskScore,
} from "../../modules/security";
import { RiskLevel, SECURITY_THRESHOLDS } from "../../utils/constants";

export class EthereumSecureTrigger implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Ethereum Secure Trigger",
    name: "ethereumSecureTrigger",
    icon: "file:ethereum-secure-trigger.svg",
    group: ["trigger"],
    version: 1,
    subtitle: '={{$parameter["triggerOn"]}}',
    description:
      "Real-time blockchain monitoring with security alerts",
    defaults: {
      name: "Ethereum Secure Trigger",
    },
    inputs: [],
    outputs: ["main"],
    credentials: [
      {
        name: "ethereumRpc",
        required: true,
      },
      {
        name: "threatIntelligence",
        required: false,
      },
    ],
    properties: [
      // ===========================================
      //          Trigger Type Selection
      // ===========================================
      {
        displayName: "Trigger On",
        name: "triggerOn",
        type: "options",
        noDataExpression: true,
        options: [
          {
            name: "🔔 New Block",
            value: "block",
            description: "Trigger on every new block",
          },
          {
            name: "📋 Contract Event",
            value: "contractEvent",
            description: "Trigger on specific contract events",
          },
          {
            name: "💰 Address Activity",
            value: "addressActivity",
            description: "Monitor specific address for activity",
          },
          {
            name: "🚨 Security Alert",
            value: "securityAlert",
            description: "Trigger on security-related events",
          },
          {
            name: "⚠️ Whale Alert",
            value: "whaleAlert",
            description: "Trigger on large value transfers",
          },
          {
            name: "💀 Threat Detection",
            value: "threatDetection",
            description: "Real-time threat monitoring",
          },
        ],
        default: "block",
      },

      // ===========================================
      //          Block Trigger Options
      // ===========================================
      {
        displayName: "Include Transactions",
        name: "includeTransactions",
        type: "boolean",
        displayOptions: {
          show: {
            triggerOn: ["block"],
          },
        },
        default: false,
        description: "Include full transaction data in block",
      },
      {
        displayName: "Include Block Security Analysis",
        name: "includeBlockSecurity",
        type: "boolean",
        displayOptions: {
          show: {
            triggerOn: ["block"],
          },
        },
        default: false,
        description: "Analyze block for suspicious transactions",
      },

      // ===========================================
      //          Contract Event Options
      // ===========================================
      {
        displayName: "Contract Address",
        name: "contractAddress",
        type: "string",
        displayOptions: {
          show: {
            triggerOn: ["contractEvent"],
          },
        },
        default: "",
        placeholder: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        description: "Contract address to monitor",
        required: true,
      },
      {
        displayName: "Event Signature",
        name: "eventSignature",
        type: "string",
        displayOptions: {
          show: {
            triggerOn: ["contractEvent"],
          },
        },
        default: "Transfer(address indexed from, address indexed to, uint256 value)",
        placeholder: "Transfer(address indexed from, address indexed to, uint256 value)",
        description: "ABI event signature to monitor",
        required: true,
      },
      {
        displayName: "Analyze Event Participants",
        name: "analyzeParticipants",
        type: "boolean",
        displayOptions: {
          show: {
            triggerOn: ["contractEvent"],
          },
        },
        default: true,
        description: "Run security analysis on event addresses",
      },

      // ===========================================
      //          Address Activity Options
      // ===========================================
      {
        displayName: "Watched Addresses",
        name: "watchedAddresses",
        type: "string",
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            triggerOn: ["addressActivity"],
          },
        },
        default: [],
        placeholder: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        description: "Addresses to monitor for activity",
      },
      {
        displayName: "Activity Types",
        name: "activityTypes",
        type: "multiOptions",
        displayOptions: {
          show: {
            triggerOn: ["addressActivity"],
          },
        },
        options: [
          {
            name: "Incoming ETH",
            value: "incomingEth",
            description: "ETH transfers to address",
          },
          {
            name: "Outgoing ETH",
            value: "outgoingEth",
            description: "ETH transfers from address",
          },
          {
            name: "Token Transfers",
            value: "tokenTransfers",
            description: "ERC20/721/1155 transfers",
          },
          {
            name: "Contract Interactions",
            value: "contractCalls",
            description: "Contract method calls",
          },
        ],
        default: ["incomingEth", "outgoingEth"],
      },

      // ===========================================
      //          Security Alert Options
      // ===========================================
      {
        displayName: "Alert Types",
        name: "alertTypes",
        type: "multiOptions",
        displayOptions: {
          show: {
            triggerOn: ["securityAlert"],
          },
        },
        options: [
          {
            name: "Sanctioned Address",
            value: "sanctioned",
            description: "Interaction with sanctioned addresses",
          },
          {
            name: "Honeypot Token",
            value: "honeypot",
            description: "Honeypot token detection",
          },
          {
            name: "Flash Loan Attack",
            value: "flashLoan",
            description: "Potential flash loan attack",
          },
          {
            name: "Rug Pull Warning",
            value: "rugPull",
            description: "Potential rug pull indicators",
          },
          {
            name: "MEV Attack",
            value: "mev",
            description: "MEV sandwich/frontrun attack",
          },
          {
            name: "Price Manipulation",
            value: "priceManipulation",
            description: "Price oracle manipulation",
          },
        ],
        default: ["sanctioned", "honeypot", "flashLoan"],
      },
      {
        displayName: "Minimum Risk Level",
        name: "minRiskLevel",
        type: "options",
        displayOptions: {
          show: {
            triggerOn: ["securityAlert"],
          },
        },
        options: [
          { name: "Info", value: "INFO" },
          { name: "Low", value: "LOW" },
          { name: "Medium", value: "MEDIUM" },
          { name: "High", value: "HIGH" },
          { name: "Critical", value: "CRITICAL" },
        ],
        default: "MEDIUM",
        description: "Minimum risk level to trigger alert",
      },

      // ===========================================
      //          Whale Alert Options
      // ===========================================
      {
        displayName: "Minimum ETH Value",
        name: "minEthValue",
        type: "number",
        displayOptions: {
          show: {
            triggerOn: ["whaleAlert"],
          },
        },
        default: 100,
        description: "Minimum ETH value to trigger whale alert",
      },
      {
        displayName: "Token Contracts",
        name: "whaleTokenContracts",
        type: "string",
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            triggerOn: ["whaleAlert"],
          },
        },
        default: [],
        description: "Token contracts to monitor (leave empty for ETH only)",
      },
      {
        displayName: "Include Whale Analysis",
        name: "includeWhaleAnalysis",
        type: "boolean",
        displayOptions: {
          show: {
            triggerOn: ["whaleAlert"],
          },
        },
        default: true,
        description: "Analyze whale wallet history",
      },

      // ===========================================
      //          Threat Detection Options
      // ===========================================
      {
        displayName: "Detection Modes",
        name: "detectionModes",
        type: "multiOptions",
        displayOptions: {
          show: {
            triggerOn: ["threatDetection"],
          },
        },
        options: [
          {
            name: "Contract Deployment",
            value: "deployment",
            description: "New contract deployments",
          },
          {
            name: "Large Approvals",
            value: "approvals",
            description: "Unlimited or large token approvals",
          },
          {
            name: "Ownership Changes",
            value: "ownership",
            description: "Contract ownership transfers",
          },
          {
            name: "Unusual Gas",
            value: "unusualGas",
            description: "Transactions with unusual gas patterns",
          },
          {
            name: "Suspicious Patterns",
            value: "patterns",
            description: "Known exploit patterns",
          },
        ],
        default: ["deployment", "approvals", "ownership"],
      },
      {
        displayName: "Contracts to Monitor",
        name: "monitorContracts",
        type: "string",
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            triggerOn: ["threatDetection"],
          },
        },
        default: [],
        description: "Specific contracts to monitor (leave empty for all)",
      },

      // ===========================================
      //          Common Options
      // ===========================================
      {
        displayName: "Options",
        name: "options",
        type: "collection",
        placeholder: "Add Option",
        default: {},
        options: [
          {
            displayName: "Polling Interval (ms)",
            name: "pollingInterval",
            type: "number",
            default: 12000,
            description: "Polling interval when WebSocket not available",
          },
          {
            displayName: "Use WebSocket",
            name: "useWebSocket",
            type: "boolean",
            default: true,
            description: "Use WebSocket for real-time updates",
          },
          {
            displayName: "Max Events Per Trigger",
            name: "maxEvents",
            type: "number",
            default: 100,
            description: "Maximum events to emit per trigger",
          },
        ],
      },
    ],
  };

  async trigger(this: ITriggerFunctions): Promise<ITriggerResponse> {
    const triggerOn = this.getNodeParameter("triggerOn") as string;
    const options = this.getNodeParameter("options", {}) as Record<string, unknown>;

    // Get credentials
    const rpcCredentials = await this.getCredentials("ethereumRpc");
    let threatIntelCredentials;
    try {
      threatIntelCredentials = await this.getCredentials("threatIntelligence");
    } catch {
      // Optional
    }

    const rpcUrl = rpcCredentials.rpcUrl as string;
    const useWebSocket = (options.useWebSocket as boolean) !== false;
    const isWebSocketUrl = rpcUrl.startsWith("ws://") || rpcUrl.startsWith("wss://");

    // Create appropriate transport
    const transport =
      useWebSocket && isWebSocketUrl ? webSocket(rpcUrl) : http(rpcUrl);
    const client = createPublicClient({ transport });

    let unwatch: WatchBlocksReturnType | WatchEventReturnType | (() => void) | undefined;

    // ===========================================
    //          Block Trigger
    // ===========================================
    if (triggerOn === "block") {
      const includeTransactions = this.getNodeParameter(
        "includeTransactions"
      ) as boolean;
      const includeBlockSecurity = this.getNodeParameter(
        "includeBlockSecurity"
      ) as boolean;

      if (isWebSocketUrl && useWebSocket) {
        unwatch = client.watchBlocks({
          includeTransactions,
          onBlock: async (block: Block) => {
            const blockData = formatBlockData(block, includeTransactions);

            if (includeBlockSecurity && includeTransactions && block.transactions) {
              // Analyze transactions for suspicious activity
              const suspiciousTransactions: unknown[] = [];
              const txs = block.transactions as Transaction[];

              for (const tx of txs.slice(0, 10)) {
                // Limit analysis
                if (tx.to) {
                  try {
                    const analysis = await analyzeTransactionThreats(
                      client,
                      {
                        to: tx.to,
                        value: tx.value,
                        data: tx.input || "0x",
                      },
                      { checkMEV: false }
                    );

                    if (analysis.riskScore.score >= SECURITY_THRESHOLDS.MEDIUM_RISK) {
                      suspiciousTransactions.push({
                        hash: tx.hash,
                        analysis,
                      });
                    }
                  } catch (e) {
                    // Skip failed analysis
                  }
                }
              }

              if (suspiciousTransactions.length > 0) {
                (blockData as Record<string, unknown>).securityAlerts = suspiciousTransactions;
              }
            }

            this.emit([this.helpers.returnJsonArray([blockData])]);
          },
        });
      } else {
        // Polling mode
        let lastBlockNumber = 0n;
        const interval = (options.pollingInterval as number) || 12000;

        const pollBlocks = async () => {
          try {
            const block = await client.getBlock({
              blockTag: "latest",
              includeTransactions,
            });

            if (block.number && block.number > lastBlockNumber) {
              lastBlockNumber = block.number;
              const blockData = formatBlockData(block, includeTransactions);
              this.emit([this.helpers.returnJsonArray([blockData])]);
            }
          } catch (error) {
            console.error("Block polling error:", error);
          }
        };

        const intervalId = setInterval(pollBlocks, interval);
        await pollBlocks(); // Initial poll

        unwatch = () => clearInterval(intervalId);
      }
    }

    // ===========================================
    //          Contract Event Trigger
    // ===========================================
    if (triggerOn === "contractEvent") {
      const contractAddress = this.getNodeParameter("contractAddress") as string;
      const eventSignature = this.getNodeParameter("eventSignature") as string;
      const analyzeParticipants = this.getNodeParameter(
        "analyzeParticipants"
      ) as boolean;

      const eventAbi = parseAbiItem(`event ${eventSignature}`);

      if (isWebSocketUrl && useWebSocket) {
        unwatch = client.watchEvent({
          address: contractAddress as `0x${string}`,
          event: eventAbi,
          onLogs: async (logs: Log[]) => {
            const processedLogs: Record<string, unknown>[] = [];

            for (const log of logs) {
              const logData: Record<string, unknown> = {
                address: log.address,
                blockNumber: log.blockNumber?.toString(),
                blockHash: log.blockHash,
                transactionHash: log.transactionHash,
                transactionIndex: log.transactionIndex,
                logIndex: log.logIndex,
                topics: log.topics,
                data: log.data,
              };

              if (analyzeParticipants && log.topics.length > 1) {
                // Extract addresses from indexed params
                const addresses: string[] = [];
                for (const topic of log.topics.slice(1)) {
                  if (topic && topic.length === 66) {
                    // Potential address (padded to 32 bytes)
                    const potentialAddr = `0x${topic.slice(-40)}`;
                    if (potentialAddr !== "0x0000000000000000000000000000000000000000") {
                      addresses.push(potentialAddr);
                    }
                  }
                }

                if (addresses.length > 0) {
                  const participantAnalysis: Record<string, unknown>[] = [];
                  for (const addr of addresses.slice(0, 3)) {
                    // Limit
                    try {
                      const analysis = await analyzeAddress(client, addr, {
                        etherscanApiKey:
                          threatIntelCredentials?.etherscanApiKey as string,
                      });
                      participantAnalysis.push({
                        address: addr,
                        riskScore: analysis.riskScore,
                      });
                    } catch {
                      // Skip
                    }
                  }
                  logData.participantAnalysis = participantAnalysis;
                }
              }

              processedLogs.push(logData);
            }

            if (processedLogs.length > 0) {
              this.emit([this.helpers.returnJsonArray(processedLogs)]);
            }
          },
        });
      } else {
        // Polling mode for events
        let lastBlock = 0n;
        const interval = (options.pollingInterval as number) || 12000;

        const pollEvents = async () => {
          try {
            const currentBlock = await client.getBlockNumber();
            if (lastBlock === 0n) {
              lastBlock = currentBlock - 1n;
            }

            if (currentBlock > lastBlock) {
              const logs = await client.getLogs({
                address: contractAddress as `0x${string}`,
                event: eventAbi,
                fromBlock: lastBlock + 1n,
                toBlock: currentBlock,
              });

              lastBlock = currentBlock;

              if (logs.length > 0) {
                const processedLogs = logs.map((log) => ({
                  address: log.address,
                  blockNumber: log.blockNumber?.toString(),
                  blockHash: log.blockHash,
                  transactionHash: log.transactionHash,
                  topics: log.topics,
                  data: log.data,
                }));

                this.emit([this.helpers.returnJsonArray(processedLogs)]);
              }
            }
          } catch (error) {
            console.error("Event polling error:", error);
          }
        };

        const intervalId = setInterval(pollEvents, interval);
        await pollEvents();

        unwatch = () => clearInterval(intervalId);
      }
    }

    // ===========================================
    //          Whale Alert Trigger
    // ===========================================
    if (triggerOn === "whaleAlert") {
      const minEthValue = this.getNodeParameter("minEthValue") as number;
      const includeWhaleAnalysis = this.getNodeParameter(
        "includeWhaleAnalysis"
      ) as boolean;
      const minValueWei = BigInt(Math.floor(minEthValue * 1e18));

      if (isWebSocketUrl && useWebSocket) {
        unwatch = client.watchBlocks({
          includeTransactions: true,
          onBlock: async (block: Block) => {
            if (!block.transactions) return;

            const whaleTransactions: Record<string, unknown>[] = [];
            const txs = block.transactions as Transaction[];

            for (const tx of txs) {
              if (tx.value >= minValueWei) {
                const whaleData: Record<string, unknown> = {
                  type: "whale_transfer",
                  hash: tx.hash,
                  from: tx.from,
                  to: tx.to,
                  value: tx.value.toString(),
                  valueEth: formatEther(tx.value),
                  blockNumber: block.number?.toString(),
                  timestamp: block.timestamp?.toString(),
                };

                if (includeWhaleAnalysis && tx.from) {
                  try {
                    const fromAnalysis = await analyzeAddress(client, tx.from, {
                      etherscanApiKey:
                        threatIntelCredentials?.etherscanApiKey as string,
                    });
                    whaleData.senderAnalysis = {
                      riskScore: fromAnalysis.riskScore,
                      isContract: fromAnalysis.isContract,
                      transactionCount: fromAnalysis.transactionCount,
                    };
                  } catch {
                    // Skip
                  }
                }

                whaleTransactions.push(whaleData);
              }
            }

            if (whaleTransactions.length > 0) {
              this.emit([this.helpers.returnJsonArray(whaleTransactions)]);
            }
          },
        });
      } else {
        // Polling fallback
        let lastBlock = 0n;
        const interval = (options.pollingInterval as number) || 12000;

        const pollWhales = async () => {
          try {
            const block = await client.getBlock({
              blockTag: "latest",
              includeTransactions: true,
            });

            if (block.number && block.number > lastBlock) {
              lastBlock = block.number;
              const txs = block.transactions as Transaction[];
              const whaleTransactions: Record<string, unknown>[] = [];

              for (const tx of txs) {
                if (tx.value >= minValueWei) {
                  whaleTransactions.push({
                    type: "whale_transfer",
                    hash: tx.hash,
                    from: tx.from,
                    to: tx.to,
                    value: tx.value.toString(),
                    valueEth: formatEther(tx.value),
                    blockNumber: block.number.toString(),
                  });
                }
              }

              if (whaleTransactions.length > 0) {
                this.emit([this.helpers.returnJsonArray(whaleTransactions)]);
              }
            }
          } catch (error) {
            console.error("Whale polling error:", error);
          }
        };

        const intervalId = setInterval(pollWhales, interval);
        await pollWhales();

        unwatch = () => clearInterval(intervalId);
      }
    }

    // ===========================================
    //          Security Alert Trigger
    // ===========================================
    if (triggerOn === "securityAlert") {
      const alertTypes = this.getNodeParameter("alertTypes") as string[];
      const minRiskLevel = this.getNodeParameter("minRiskLevel") as string;

      const riskLevelOrder = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const minRiskIndex = riskLevelOrder.indexOf(minRiskLevel);

      // Watch for Transfer events on ERC20 tokens (common pattern for most alerts)
      const transferEvent = parseAbiItem(
        "event Transfer(address indexed from, address indexed to, uint256 value)"
      );

      let lastBlock = 0n;
      const interval = (options.pollingInterval as number) || 15000;

      const scanForSecurityAlerts = async () => {
        try {
          const currentBlock = await client.getBlockNumber();
          if (lastBlock === 0n) {
            lastBlock = currentBlock - 1n;
          }

          if (currentBlock > lastBlock) {
            const block = await client.getBlock({
              blockNumber: currentBlock,
              includeTransactions: true,
            });
            lastBlock = currentBlock;

            const alerts: Record<string, unknown>[] = [];
            const txs = (block.transactions || []) as Transaction[];

            for (const tx of txs.slice(0, 20)) {
              // Limit per block
              // Check for contract deployments
              if (alertTypes.includes("deployment") && !tx.to) {
                alerts.push({
                  type: "contract_deployment",
                  severity: "MEDIUM",
                  hash: tx.hash,
                  deployer: tx.from,
                  blockNumber: currentBlock.toString(),
                  message: "New contract deployed",
                });
              }

              // Check for large approvals
              if (alertTypes.includes("approvals") && tx.input) {
                const approveSelector = "0x095ea7b3";
                if (tx.input.startsWith(approveSelector)) {
                  // Check if unlimited approval (max uint256)
                  if (tx.input.includes("ffffffffffffffffffffffffffffffffffffffff")) {
                    alerts.push({
                      type: "unlimited_approval",
                      severity: "HIGH",
                      hash: tx.hash,
                      from: tx.from,
                      contract: tx.to,
                      blockNumber: currentBlock.toString(),
                      message: "Unlimited token approval detected",
                    });
                  }
                }
              }

              // Check for sanctioned addresses
              if (alertTypes.includes("sanctioned") && tx.to) {
                try {
                  const sanctionCheck = await checkSanctions(tx.to, {
                    chainalysisApiKey:
                      threatIntelCredentials?.chainalysisApiKey as string,
                  });

                  if (sanctionCheck.isSanctioned) {
                    alerts.push({
                      type: "sanctioned_interaction",
                      severity: "CRITICAL",
                      hash: tx.hash,
                      from: tx.from,
                      to: tx.to,
                      blockNumber: currentBlock.toString(),
                      message: `Interaction with sanctioned address: ${sanctionCheck.reason}`,
                    });
                  }
                } catch {
                  // Skip if sanctions check fails
                }
              }
            }

            // Filter by minimum risk level
            const filteredAlerts = alerts.filter((alert) => {
              const alertRiskIndex = riskLevelOrder.indexOf(
                alert.severity as string
              );
              return alertRiskIndex >= minRiskIndex;
            });

            if (filteredAlerts.length > 0) {
              this.emit([this.helpers.returnJsonArray(filteredAlerts)]);
            }
          }
        } catch (error) {
          console.error("Security scan error:", error);
        }
      };

      const intervalId = setInterval(scanForSecurityAlerts, interval);
      await scanForSecurityAlerts();

      unwatch = () => clearInterval(intervalId);
    }

    // ===========================================
    //          Threat Detection Trigger
    // ===========================================
    if (triggerOn === "threatDetection") {
      const detectionModes = this.getNodeParameter("detectionModes") as string[];

      let lastBlock = 0n;
      const interval = (options.pollingInterval as number) || 15000;

      const scanForThreats = async () => {
        try {
          const currentBlock = await client.getBlockNumber();
          if (lastBlock === 0n) {
            lastBlock = currentBlock - 1n;
          }

          if (currentBlock > lastBlock) {
            const block = await client.getBlock({
              blockNumber: currentBlock,
              includeTransactions: true,
            });
            lastBlock = currentBlock;

            const threats: Record<string, unknown>[] = [];
            const txs = (block.transactions || []) as Transaction[];

            for (const tx of txs.slice(0, 30)) {
              // Contract deployment detection
              if (detectionModes.includes("deployment") && !tx.to) {
                threats.push({
                  type: "new_contract_deployment",
                  severity: "INFO",
                  hash: tx.hash,
                  deployer: tx.from,
                  gasUsed: tx.gas?.toString(),
                  blockNumber: currentBlock.toString(),
                  timestamp: new Date().toISOString(),
                });
              }

              // Unusual gas detection
              if (detectionModes.includes("unusualGas") && tx.gas) {
                const gasLimit = tx.gas;
                // Very high gas limit might indicate complex/unusual operations
                if (gasLimit > 2000000n) {
                  threats.push({
                    type: "high_gas_transaction",
                    severity: "LOW",
                    hash: tx.hash,
                    from: tx.from,
                    to: tx.to,
                    gasLimit: gasLimit.toString(),
                    blockNumber: currentBlock.toString(),
                    message: "Transaction with unusually high gas limit",
                  });
                }
              }

              // Ownership changes detection
              if (detectionModes.includes("ownership") && tx.input) {
                // Common ownership transfer selectors
                const ownershipSelectors = [
                  "0xf2fde38b", // transferOwnership(address)
                  "0x79ba5097", // acceptOwnership()
                  "0x715018a6", // renounceOwnership()
                ];

                for (const selector of ownershipSelectors) {
                  if (tx.input.startsWith(selector)) {
                    threats.push({
                      type: "ownership_change",
                      severity: "HIGH",
                      hash: tx.hash,
                      contract: tx.to,
                      initiator: tx.from,
                      selector,
                      blockNumber: currentBlock.toString(),
                      message: "Contract ownership change detected",
                    });
                    break;
                  }
                }
              }

              // Known exploit pattern detection
              if (detectionModes.includes("patterns") && tx.input) {
                // Flash loan function selectors
                const flashLoanSelectors = [
                  "0xab9c4b5d", // flashLoan
                  "0x5cffe9de", // flashLoan (Aave)
                ];

                for (const selector of flashLoanSelectors) {
                  if (tx.input.startsWith(selector)) {
                    threats.push({
                      type: "flash_loan_detected",
                      severity: "MEDIUM",
                      hash: tx.hash,
                      contract: tx.to,
                      initiator: tx.from,
                      blockNumber: currentBlock.toString(),
                      message: "Flash loan execution detected",
                    });
                    break;
                  }
                }
              }
            }

            if (threats.length > 0) {
              this.emit([this.helpers.returnJsonArray(threats)]);
            }
          }
        } catch (error) {
          console.error("Threat detection error:", error);
        }
      };

      const intervalId = setInterval(scanForThreats, interval);
      await scanForThreats();

      unwatch = () => clearInterval(intervalId);
    }

    // ===========================================
    //          Address Activity Trigger
    // ===========================================
    if (triggerOn === "addressActivity") {
      const watchedAddresses = this.getNodeParameter("watchedAddresses") as string[];
      const activityTypes = this.getNodeParameter("activityTypes") as string[];

      const addressSet = new Set(
        watchedAddresses.map((a) => a.toLowerCase())
      );

      let lastBlock = 0n;
      const interval = (options.pollingInterval as number) || 12000;

      const pollAddressActivity = async () => {
        try {
          const currentBlock = await client.getBlockNumber();
          if (lastBlock === 0n) {
            lastBlock = currentBlock - 1n;
          }

          if (currentBlock > lastBlock) {
            const block = await client.getBlock({
              blockNumber: currentBlock,
              includeTransactions: true,
            });
            lastBlock = currentBlock;

            const activities: Record<string, unknown>[] = [];
            const txs = (block.transactions || []) as Transaction[];

            for (const tx of txs) {
              const fromLower = tx.from?.toLowerCase();
              const toLower = tx.to?.toLowerCase();

              // Check for incoming ETH
              if (
                activityTypes.includes("incomingEth") &&
                toLower &&
                addressSet.has(toLower) &&
                tx.value > 0n
              ) {
                activities.push({
                  type: "incoming_eth",
                  watchedAddress: tx.to,
                  hash: tx.hash,
                  from: tx.from,
                  value: tx.value.toString(),
                  valueEth: formatEther(tx.value),
                  blockNumber: currentBlock.toString(),
                });
              }

              // Check for outgoing ETH
              if (
                activityTypes.includes("outgoingEth") &&
                fromLower &&
                addressSet.has(fromLower) &&
                tx.value > 0n
              ) {
                activities.push({
                  type: "outgoing_eth",
                  watchedAddress: tx.from,
                  hash: tx.hash,
                  to: tx.to,
                  value: tx.value.toString(),
                  valueEth: formatEther(tx.value),
                  blockNumber: currentBlock.toString(),
                });
              }

              // Check for contract calls
              if (
                activityTypes.includes("contractCalls") &&
                fromLower &&
                addressSet.has(fromLower) &&
                tx.input &&
                tx.input !== "0x"
              ) {
                activities.push({
                  type: "contract_call",
                  watchedAddress: tx.from,
                  hash: tx.hash,
                  contract: tx.to,
                  methodSelector: tx.input.slice(0, 10),
                  blockNumber: currentBlock.toString(),
                });
              }
            }

            if (activities.length > 0) {
              this.emit([this.helpers.returnJsonArray(activities)]);
            }
          }
        } catch (error) {
          console.error("Address activity polling error:", error);
        }
      };

      const intervalId = setInterval(pollAddressActivity, interval);
      await pollAddressActivity();

      unwatch = () => clearInterval(intervalId);
    }

    // Return cleanup function
    return {
      closeFunction: async () => {
        if (unwatch) {
          if (typeof unwatch === "function") {
            unwatch();
          }
        }
      },
    };
  }
}

// ===========================================
//          Helper Functions
// ===========================================

function formatBlockData(
  block: Block,
  includeTransactions: boolean
): Record<string, unknown> {
  const data: Record<string, unknown> = {
    number: block.number?.toString(),
    hash: block.hash,
    parentHash: block.parentHash,
    timestamp: block.timestamp?.toString(),
    miner: block.miner,
    gasUsed: block.gasUsed?.toString(),
    gasLimit: block.gasLimit?.toString(),
    baseFeePerGas: block.baseFeePerGas?.toString(),
    transactionCount:
      typeof block.transactions === "object"
        ? block.transactions.length
        : block.transactions,
  };

  if (includeTransactions && block.transactions) {
    data.transactions = (block.transactions as Transaction[]).map((tx) => ({
      hash: tx.hash,
      from: tx.from,
      to: tx.to,
      value: tx.value?.toString(),
      gas: tx.gas?.toString(),
      gasPrice: tx.gasPrice?.toString(),
      nonce: tx.nonce,
    }));
  }

  return data;
}
