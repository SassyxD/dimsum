/**
 * Ethereum Secure Platform - Constants
 *
 * Core constants, ABIs, and configuration for the security platform
 */

// ===========================================
//          Network Configuration
// ===========================================

export interface ChainConfig {
  id: number;
  name: string;
  nativeCurrency: {
    name: string;
    symbol: string;
    decimals: number;
  };
  blockExplorerUrl?: string;
  blockExplorerApiUrl?: string;
  isTestnet: boolean;
}

export const SUPPORTED_CHAINS: Record<string, ChainConfig> = {
  mainnet: {
    id: 1,
    name: "Ethereum Mainnet",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://etherscan.io",
    blockExplorerApiUrl: "https://api.etherscan.io/api",
    isTestnet: false,
  },
  sepolia: {
    id: 11155111,
    name: "Ethereum Sepolia",
    nativeCurrency: { name: "Sepolia Ether", symbol: "SEP", decimals: 18 },
    blockExplorerUrl: "https://sepolia.etherscan.io",
    blockExplorerApiUrl: "https://api-sepolia.etherscan.io/api",
    isTestnet: true,
  },
  arbitrum: {
    id: 42161,
    name: "Arbitrum One",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://arbiscan.io",
    blockExplorerApiUrl: "https://api.arbiscan.io/api",
    isTestnet: false,
  },
  optimism: {
    id: 10,
    name: "Optimism",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://optimistic.etherscan.io",
    blockExplorerApiUrl: "https://api-optimistic.etherscan.io/api",
    isTestnet: false,
  },
  base: {
    id: 8453,
    name: "Base",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://basescan.org",
    blockExplorerApiUrl: "https://api.basescan.org/api",
    isTestnet: false,
  },
  polygon: {
    id: 137,
    name: "Polygon",
    nativeCurrency: { name: "MATIC", symbol: "MATIC", decimals: 18 },
    blockExplorerUrl: "https://polygonscan.com",
    blockExplorerApiUrl: "https://api.polygonscan.com/api",
    isTestnet: false,
  },
  bnb: {
    id: 56,
    name: "BNB Chain",
    nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 },
    blockExplorerUrl: "https://bscscan.com",
    blockExplorerApiUrl: "https://api.bscscan.com/api",
    isTestnet: false,
  },
  avalanche: {
    id: 43114,
    name: "Avalanche C-Chain",
    nativeCurrency: { name: "AVAX", symbol: "AVAX", decimals: 18 },
    blockExplorerUrl: "https://snowtrace.io",
    blockExplorerApiUrl: "https://api.snowtrace.io/api",
    isTestnet: false,
  },
  linea: {
    id: 59144,
    name: "Linea",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://lineascan.build",
    blockExplorerApiUrl: "https://api.lineascan.build/api",
    isTestnet: false,
  },
  zkSync: {
    id: 324,
    name: "zkSync Era",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrl: "https://explorer.zksync.io",
    isTestnet: false,
  },
};

// ===========================================
//          Security Risk Levels
// ===========================================

export enum RiskLevel {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  SAFE = "safe",
}

export interface RiskScore {
  level: RiskLevel;
  score: number; // 0-100
  factors: RiskFactor[];
  recommendation: string;
}

export interface RiskFactor {
  type: string;
  severity: RiskLevel;
  description: string;
  impact: number; // 0-100 contribution to overall score
}

// ===========================================
//          Token Standard ABIs
// ===========================================

export const ERC20_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
  "function balanceOf(address owner) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function transferFrom(address from, address to, uint256 amount) returns (bool)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "event Approval(address indexed owner, address indexed spender, uint256 value)",
] as const;

export const ERC721_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function balanceOf(address owner) view returns (uint256)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function safeTransferFrom(address from, address to, uint256 tokenId)",
  "function transferFrom(address from, address to, uint256 tokenId)",
  "function approve(address to, uint256 tokenId)",
  "function getApproved(uint256 tokenId) view returns (address)",
  "function setApprovalForAll(address operator, bool approved)",
  "function isApprovedForAll(address owner, address operator) view returns (bool)",
  "event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)",
  "event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)",
  "event ApprovalForAll(address indexed owner, address indexed operator, bool approved)",
] as const;

export const ERC1155_ABI = [
  "function uri(uint256 id) view returns (string)",
  "function balanceOf(address account, uint256 id) view returns (uint256)",
  "function balanceOfBatch(address[] accounts, uint256[] ids) view returns (uint256[])",
  "function setApprovalForAll(address operator, bool approved)",
  "function isApprovedForAll(address account, address operator) view returns (bool)",
  "function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)",
  "function safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)",
  "event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value)",
  "event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values)",
  "event ApprovalForAll(address indexed account, address indexed operator, bool approved)",
  "event URI(string value, uint256 indexed id)",
] as const;

// ===========================================
//          Known Threat Indicators
// ===========================================

export const KNOWN_SCAM_SIGNATURES = [
  // Common honeypot patterns
  "0x70a08231", // balanceOf (when combined with transfer restrictions)
  "0xa9059cbb", // transfer (when modified maliciously)
];

export const SUSPICIOUS_FUNCTION_SELECTORS = [
  "0x95d89b41", // symbol() - often used in phishing tokens
  "0x06fdde03", // name() - often used in phishing tokens
];

// Known malicious contract patterns (hex signatures)
export const MALICIOUS_BYTECODE_PATTERNS = [
  // Self-destruct patterns
  "ff", // SELFDESTRUCT opcode
  // Delegatecall to unknown
  "f4", // DELEGATECALL opcode (when misused)
];

// ===========================================
//          Security Thresholds
// ===========================================

export const SECURITY_THRESHOLDS = {
  // Transaction value thresholds (in ETH)
  HIGH_VALUE_THRESHOLD: 10,
  CRITICAL_VALUE_THRESHOLD: 100,

  // Gas price anomaly thresholds (percentage above average)
  GAS_PRICE_ANOMALY_THRESHOLD: 50,

  // Address age thresholds (in days)
  NEW_ADDRESS_WARNING_DAYS: 7,
  YOUNG_CONTRACT_WARNING_DAYS: 30,

  // Risk score thresholds
  BLOCK_TRANSACTION_SCORE: 80,
  WARN_TRANSACTION_SCORE: 50,
  REVIEW_TRANSACTION_SCORE: 30,

  // Risk level thresholds
  LOW_RISK: 20,
  MEDIUM_RISK: 40,
  HIGH_RISK: 60,
  CRITICAL_RISK: 80,
};

// ===========================================
//          Audit Trail Event Types
// ===========================================

export enum AuditEventType {
  // Transaction events
  TRANSACTION_INITIATED = "transaction.initiated",
  TRANSACTION_SIGNED = "transaction.signed",
  TRANSACTION_SUBMITTED = "transaction.submitted",
  TRANSACTION_CONFIRMED = "transaction.confirmed",
  TRANSACTION_FAILED = "transaction.failed",
  TRANSACTION_EXECUTED = "transaction.executed",
  TRANSACTION_SIMULATED = "transaction.simulated",

  // Security events
  SECURITY_CHECK_PASSED = "security.check.passed",
  SECURITY_CHECK_FAILED = "security.check.failed",
  SECURITY_ALERT_TRIGGERED = "security.alert.triggered",
  THREAT_DETECTED = "security.threat.detected",
  SECURITY_ALERT = "security.alert",
  SANCTIONS_CHECK = "security.sanctions.check",

  // Contract events
  CONTRACT_GENERATED = "contract.generated",
  CONTRACT_ANALYZED = "contract.analyzed",
  CONTRACT_DEPLOYED = "contract.deployed",
  CONTRACT_VERIFIED = "contract.verified",

  // AI events
  AI_GENERATION = "ai.generation",

  // Access events
  CREDENTIAL_ACCESSED = "credential.accessed",
  OPERATION_AUTHORIZED = "operation.authorized",
}

export interface AuditLogEntry {
  timestamp: string;
  eventType: AuditEventType;
  actor: string;
  resource: string;
  action: string;
  details: Record<string, unknown>;
  riskLevel?: RiskLevel;
  hash?: string; // For cryptographic verification
}

// ===========================================
//          AI Contract Templates
// ===========================================

export const CONTRACT_TEMPLATES = {
  ERC20_STANDARD: "erc20-standard",
  ERC20_MINTABLE: "erc20-mintable",
  ERC20_BURNABLE: "erc20-burnable",
  ERC20_PAUSABLE: "erc20-pausable",
  ERC721_STANDARD: "erc721-standard",
  ERC721_ENUMERABLE: "erc721-enumerable",
  ERC1155_STANDARD: "erc1155-standard",
  MULTISIG_WALLET: "multisig-wallet",
  TIMELOCK: "timelock-controller",
  GOVERNANCE: "governance-token",
} as const;

// ===========================================
//          Default Messages
// ===========================================

export const SECURITY_MESSAGES = {
  ADDRESS_NOT_VERIFIED:
    "Target address is not verified on the block explorer. Proceed with caution.",
  HIGH_RISK_SCORE:
    "This transaction has been flagged with a high risk score. Manual review recommended.",
  SANCTIONS_CHECK_REQUIRED:
    "Unable to verify sanctions status. Please check manually before proceeding.",
  NEW_CONTRACT_WARNING:
    "This smart contract was deployed recently. New contracts may pose higher risks.",
  HONEYPOT_DETECTED:
    "This token appears to be a honeypot. Transfers may be restricted.",
  MEV_RISK_DETECTED:
    "This transaction may be vulnerable to MEV attacks. Consider using private mempool.",
};
