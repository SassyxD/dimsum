/**
 * Ethereum Secure Platform - Type Definitions
 *
 * Core TypeScript interfaces and types for the security platform
 */

import { RiskLevel, RiskScore, AuditLogEntry } from "./constants";

// ===========================================
//          Client Types
// ===========================================

export interface SecureClientConfig {
  rpcUrl: string;
  customHeaders?: Record<string, string>;
  enableSecurityChecks?: boolean;
  threatIntelApiKey?: string;
  etherscanApiKey?: string;
}

export interface WalletConfig {
  privateKey?: string;
  mnemonic?: string;
  path?: string;
  passphrase?: string;
}

// ===========================================
//          Security Analysis Types
// ===========================================

export interface AddressAnalysis {
  address: string;
  isContract: boolean;
  isVerified: boolean;
  verificationSource?: string;
  age?: number; // Days since first transaction
  transactionCount?: number;
  riskScore: RiskScore;
  labels: string[];
  sanctions: SanctionsCheck;
}

export interface SanctionsCheck {
  isChecked: boolean;
  isSanctioned: boolean;
  source?: string;
  matchType?: string;
  details?: string;
  lists?: string[];
  reason?: string;
}

export interface ContractSecurityAnalysis {
  address: string;
  isVerified: boolean;
  sourceCode?: string;
  compilerVersion?: string;
  optimizationEnabled?: boolean;
  vulnerabilities: Vulnerability[];
  permissions: ContractPermission[];
  riskScore: RiskScore;
  auditStatus?: AuditStatus;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: RiskLevel;
  description: string;
  location?: string;
  recommendation: string;
  cweId?: string;
  swcId?: string;
}

export interface ContractPermission {
  role: string;
  address: string;
  functions: string[];
  isRenounced: boolean;
}

export interface AuditStatus {
  isAudited: boolean;
  auditor?: string;
  auditDate?: string;
  reportUrl?: string;
}

// ===========================================
//          Transaction Types
// ===========================================

export interface SecureTransaction {
  to: string;
  value?: bigint;
  data?: string;
  nonce?: number;
  gasLimit?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
}

export interface TransactionRiskAssessment {
  transaction: SecureTransaction;
  riskScore: RiskScore;
  preFlightChecks: PreFlightCheck[];
  simulation?: TransactionSimulation;
  recommendation: TransactionRecommendation;
}

export interface PreFlightCheck {
  name: string;
  passed: boolean;
  severity: RiskLevel;
  message: string;
  details?: Record<string, unknown>;
}

export interface TransactionSimulation {
  success: boolean;
  gasUsed: bigint;
  returnData?: string;
  revertReason?: string;
  events: SimulatedEvent[];
  stateChanges: StateChange[];
}

export interface SimulatedEvent {
  address: string;
  name: string;
  args: Record<string, unknown>;
}

export interface StateChange {
  address: string;
  slot: string;
  before: string;
  after: string;
}

export enum TransactionRecommendation {
  PROCEED = "proceed",
  REVIEW = "review",
  CAUTION = "caution",
  BLOCK = "block",
}

// ===========================================
//          Token Types
// ===========================================

export interface TokenInfo {
  address: string;
  name: string;
  symbol: string;
  decimals: number;
  totalSupply: bigint;
  isVerified: boolean;
  securityAnalysis?: TokenSecurityAnalysis;
}

export interface TokenSecurityAnalysis {
  isHoneypot: boolean;
  isMintable: boolean;
  isPausable: boolean;
  hasBlacklist: boolean;
  hasTaxes: boolean;
  buyTax?: number;
  sellTax?: number;
  maxTransactionAmount?: bigint;
  ownerBalance?: bigint;
  riskScore: RiskScore;
}

// ===========================================
//          AI Contract Types
// ===========================================

export interface ContractGenerationRequest {
  description: string;
  template?: string;
  features?: string[];
  parameters?: Record<string, unknown>;
  securityLevel?: "basic" | "standard" | "enterprise";
}

export interface GeneratedContract {
  sourceCode: string;
  abi: unknown[];
  bytecode: string;
  constructorArgs?: unknown[];
  securityAnalysis: ContractSecurityAnalysis;
  gasEstimate: bigint;
  documentation: string;
  testSuite?: string;
}

export interface ContractTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  features: string[];
  parameters: TemplateParameter[];
  baseCode: string;
}

export interface TemplateParameter {
  name: string;
  type: string;
  required: boolean;
  defaultValue?: unknown;
  description: string;
  validation?: string;
}

// ===========================================
//          Monitoring Types
// ===========================================

export interface MonitoringConfig {
  addresses: string[];
  events?: string[];
  thresholds?: Record<string, number>;
  alertChannels: AlertChannel[];
}

export interface AlertChannel {
  type: "email" | "webhook" | "telegram" | "discord" | "slack";
  config: Record<string, string>;
  severity: RiskLevel[];
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  type: string;
  severity: RiskLevel;
  title: string;
  description: string;
  affectedAddress?: string;
  transactionHash?: string;
  recommendation: string;
  acknowledged: boolean;
}

export interface AnomalyDetection {
  type: string;
  detected: boolean;
  confidence: number;
  baseline: number;
  current: number;
  deviation: number;
  details: string;
}

// ===========================================
//          Compliance Types
// ===========================================

export interface ComplianceCheck {
  type: string;
  passed: boolean;
  requirement: string;
  evidence: string;
  timestamp: string;
}

export interface AuditReport {
  id: string;
  generatedAt: string;
  period: {
    from: string;
    to: string;
  };
  entries: AuditLogEntry[];
  summary: AuditSummary;
  hash: string; // Cryptographic hash for verification
}

export interface AuditSummary {
  totalTransactions: number;
  totalValue: bigint;
  securityAlerts: number;
  complianceViolations: number;
  riskDistribution: Record<RiskLevel, number>;
}

// ===========================================
//          Multi-Sig Types
// ===========================================

export interface MultiSigWallet {
  address: string;
  owners: string[];
  threshold: number;
  nonce: number;
  pendingTransactions: MultiSigTransaction[];
}

export interface MultiSigTransaction {
  id: string;
  to: string;
  value: bigint;
  data: string;
  signatures: MultiSigSignature[];
  executed: boolean;
  createdAt: string;
  expiresAt?: string;
}

export interface MultiSigSignature {
  signer: string;
  signature: string;
  timestamp: string;
}

// ===========================================
//          Node Execution Types
// ===========================================

export interface SecureExecutionContext {
  operationId: string;
  timestamp: string;
  actor: string;
  securityLevel: "basic" | "standard" | "enterprise";
  auditLog: AuditLogEntry[];
}

export interface SecureOperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  riskAssessment?: RiskScore;
  auditEntry: AuditLogEntry;
  warnings: string[];
}
