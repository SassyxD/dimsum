/**
 * Ethereum Secure Platform - Audit Trail Module
 *
 * Comprehensive logging and compliance tracking for all operations
 */

import { AuditEventType } from "../../utils/constants";

/**
 * Audit log entry structure
 */
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  actor: {
    address?: string;
    nodeId?: string;
    workflowId?: string;
  };
  target: {
    type: "address" | "contract" | "transaction" | "token";
    identifier: string;
    chainId?: number;
  };
  action: string;
  details: Record<string, unknown>;
  riskAssessment?: {
    score: number;
    level: string;
    factors: string[];
  };
  outcome: "SUCCESS" | "BLOCKED" | "WARNING" | "ERROR";
  metadata: {
    ipHash?: string;
    userAgent?: string;
    correlationId?: string;
  };
}

/**
 * Compliance report structure
 */
export interface ComplianceReport {
  reportId: string;
  generatedAt: string;
  period: {
    start: string;
    end: string;
  };
  summary: {
    totalTransactions: number;
    blockedTransactions: number;
    sanctionsHits: number;
    highRiskEvents: number;
    avgRiskScore: number;
  };
  events: AuditLogEntry[];
  riskBreakdown: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

/**
 * In-memory audit log storage (replace with database in production)
 */
class AuditStore {
  private logs: AuditLogEntry[] = [];
  private maxLogs: number = 10000;

  add(entry: AuditLogEntry): void {
    this.logs.unshift(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(0, this.maxLogs);
    }
  }

  getAll(): AuditLogEntry[] {
    return [...this.logs];
  }

  getByType(eventType: AuditEventType): AuditLogEntry[] {
    return this.logs.filter((log) => log.eventType === eventType);
  }

  getByAddress(address: string): AuditLogEntry[] {
    const lowerAddress = address.toLowerCase();
    return this.logs.filter(
      (log) =>
        log.actor.address?.toLowerCase() === lowerAddress ||
        log.target.identifier.toLowerCase() === lowerAddress
    );
  }

  getByTimeRange(start: Date, end: Date): AuditLogEntry[] {
    return this.logs.filter((log) => {
      const logTime = new Date(log.timestamp);
      return logTime >= start && logTime <= end;
    });
  }

  getBySeverity(severity: AuditLogEntry["severity"]): AuditLogEntry[] {
    return this.logs.filter((log) => log.severity === severity);
  }

  clear(): void {
    this.logs = [];
  }
}

// Global audit store instance
const auditStore = new AuditStore();

/**
 * Generate a unique audit log ID
 */
function generateAuditId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `audit_${timestamp}_${random}`;
}

/**
 * Log an audit event
 */
export function logAuditEvent(params: {
  eventType: AuditEventType;
  severity?: AuditLogEntry["severity"];
  actor?: AuditLogEntry["actor"];
  target: AuditLogEntry["target"];
  action: string;
  details?: Record<string, unknown>;
  riskAssessment?: AuditLogEntry["riskAssessment"];
  outcome: AuditLogEntry["outcome"];
  metadata?: AuditLogEntry["metadata"];
}): AuditLogEntry {
  const entry: AuditLogEntry = {
    id: generateAuditId(),
    timestamp: new Date().toISOString(),
    eventType: params.eventType,
    severity: params.severity || "INFO",
    actor: params.actor || {},
    target: params.target,
    action: params.action,
    details: params.details || {},
    riskAssessment: params.riskAssessment,
    outcome: params.outcome,
    metadata: params.metadata || {},
  };

  auditStore.add(entry);

  // Console log for development
  const logPrefix = `[${entry.severity}] [${entry.eventType}]`;
  console.log(`${logPrefix} ${entry.action} - ${entry.outcome}`);

  return entry;
}

/**
 * Log a transaction event
 */
export function logTransactionEvent(params: {
  txHash?: string;
  from: string;
  to: string;
  value?: string;
  action: "INITIATED" | "SIMULATED" | "EXECUTED" | "BLOCKED" | "FAILED";
  riskScore?: number;
  riskLevel?: string;
  riskFactors?: string[];
  blockReason?: string;
  workflowId?: string;
}): AuditLogEntry {
  const severity = getSeverityFromAction(params.action, params.riskScore);

  return logAuditEvent({
    eventType: AuditEventType.TRANSACTION_EXECUTED,
    severity,
    actor: {
      address: params.from,
      workflowId: params.workflowId,
    },
    target: {
      type: "address",
      identifier: params.to,
    },
    action: `Transaction ${params.action}`,
    details: {
      txHash: params.txHash,
      value: params.value,
      blockReason: params.blockReason,
    },
    riskAssessment: params.riskScore
      ? {
          score: params.riskScore,
          level: params.riskLevel || "UNKNOWN",
          factors: params.riskFactors || [],
        }
      : undefined,
    outcome:
      params.action === "BLOCKED"
        ? "BLOCKED"
        : params.action === "FAILED"
        ? "ERROR"
        : params.action === "EXECUTED"
        ? "SUCCESS"
        : "WARNING",
  });
}

/**
 * Log a security alert
 */
export function logSecurityAlert(params: {
  alertType:
    | "SANCTIONED_ADDRESS"
    | "HONEYPOT_DETECTED"
    | "HIGH_RISK_TX"
    | "MEV_ATTACK"
    | "PHISHING"
    | "RUG_PULL"
    | "FLASH_LOAN";
  address: string;
  severity: AuditLogEntry["severity"];
  description: string;
  recommendations?: string[];
  source?: string;
}): AuditLogEntry {
  return logAuditEvent({
    eventType: AuditEventType.SECURITY_ALERT,
    severity: params.severity,
    target: {
      type: "address",
      identifier: params.address,
    },
    action: `Security Alert: ${params.alertType}`,
    details: {
      alertType: params.alertType,
      description: params.description,
      recommendations: params.recommendations,
      source: params.source,
    },
    outcome: "WARNING",
  });
}

/**
 * Log a sanctions check
 */
export function logSanctionsCheck(params: {
  address: string;
  isSanctioned: boolean;
  source?: string;
  lists?: string[];
  country?: string;
}): AuditLogEntry {
  return logAuditEvent({
    eventType: AuditEventType.SANCTIONS_CHECK,
    severity: params.isSanctioned ? "CRITICAL" : "INFO",
    target: {
      type: "address",
      identifier: params.address,
    },
    action: params.isSanctioned
      ? "Address found on sanctions list"
      : "Address cleared sanctions check",
    details: {
      source: params.source,
      lists: params.lists,
      country: params.country,
    },
    outcome: params.isSanctioned ? "BLOCKED" : "SUCCESS",
  });
}

/**
 * Log contract verification
 */
export function logContractVerification(params: {
  address: string;
  isVerified: boolean;
  hasSecurityIssues: boolean;
  vulnerabilities?: string[];
  source?: string;
}): AuditLogEntry {
  const severity = params.hasSecurityIssues
    ? "HIGH"
    : params.isVerified
    ? "INFO"
    : "MEDIUM";

  return logAuditEvent({
    eventType: AuditEventType.CONTRACT_VERIFIED,
    severity,
    target: {
      type: "contract",
      identifier: params.address,
    },
    action: params.isVerified
      ? "Contract verification successful"
      : "Contract not verified",
    details: {
      isVerified: params.isVerified,
      hasSecurityIssues: params.hasSecurityIssues,
      vulnerabilities: params.vulnerabilities,
      source: params.source,
    },
    outcome: params.hasSecurityIssues ? "WARNING" : "SUCCESS",
  });
}

/**
 * Log AI contract generation
 */
export function logContractGeneration(params: {
  description: string;
  template?: string;
  securityLevel: string;
  provider: string;
  success: boolean;
  vulnerabilitiesFound?: number;
}): AuditLogEntry {
  return logAuditEvent({
    eventType: AuditEventType.AI_GENERATION,
    severity: "INFO",
    target: {
      type: "contract",
      identifier: "generated",
    },
    action: "AI Contract Generation",
    details: {
      description: params.description.substring(0, 200),
      template: params.template,
      securityLevel: params.securityLevel,
      provider: params.provider,
      vulnerabilitiesFound: params.vulnerabilitiesFound,
    },
    outcome: params.success ? "SUCCESS" : "ERROR",
  });
}

/**
 * Get all audit logs
 */
export function getAuditLogs(): AuditLogEntry[] {
  return auditStore.getAll();
}

/**
 * Get audit logs for a specific address
 */
export function getAddressAuditHistory(address: string): AuditLogEntry[] {
  return auditStore.getByAddress(address);
}

/**
 * Get high-risk events
 */
export function getHighRiskEvents(): AuditLogEntry[] {
  return auditStore
    .getAll()
    .filter((log) => log.severity === "HIGH" || log.severity === "CRITICAL");
}

/**
 * Generate compliance report
 */
export function generateComplianceReport(
  startDate: Date,
  endDate: Date
): ComplianceReport {
  const logs = auditStore.getByTimeRange(startDate, endDate);

  const summary = {
    totalTransactions: logs.filter(
      (l) =>
        l.eventType === AuditEventType.TRANSACTION_EXECUTED ||
        l.eventType === AuditEventType.TRANSACTION_SIMULATED
    ).length,
    blockedTransactions: logs.filter((l) => l.outcome === "BLOCKED").length,
    sanctionsHits: logs.filter(
      (l) =>
        l.eventType === AuditEventType.SANCTIONS_CHECK &&
        l.outcome === "BLOCKED"
    ).length,
    highRiskEvents: logs.filter(
      (l) => l.severity === "HIGH" || l.severity === "CRITICAL"
    ).length,
    avgRiskScore: calculateAverageRiskScore(logs),
  };

  const riskBreakdown = {
    low: logs.filter((l) => l.severity === "LOW").length,
    medium: logs.filter((l) => l.severity === "MEDIUM").length,
    high: logs.filter((l) => l.severity === "HIGH").length,
    critical: logs.filter((l) => l.severity === "CRITICAL").length,
  };

  return {
    reportId: `report_${Date.now().toString(36)}`,
    generatedAt: new Date().toISOString(),
    period: {
      start: startDate.toISOString(),
      end: endDate.toISOString(),
    },
    summary,
    events: logs,
    riskBreakdown,
  };
}

/**
 * Export audit logs in various formats
 */
export function exportAuditLogs(
  format: "json" | "csv",
  filters?: {
    startDate?: Date;
    endDate?: Date;
    eventTypes?: AuditEventType[];
    severity?: AuditLogEntry["severity"][];
  }
): string {
  let logs = auditStore.getAll();

  // Apply filters
  if (filters) {
    if (filters.startDate && filters.endDate) {
      logs = logs.filter((log) => {
        const logTime = new Date(log.timestamp);
        return logTime >= filters.startDate! && logTime <= filters.endDate!;
      });
    }

    if (filters.eventTypes) {
      logs = logs.filter((log) => filters.eventTypes!.includes(log.eventType));
    }

    if (filters.severity) {
      logs = logs.filter((log) => filters.severity!.includes(log.severity));
    }
  }

  if (format === "json") {
    return JSON.stringify(logs, null, 2);
  }

  // CSV format
  const headers = [
    "id",
    "timestamp",
    "eventType",
    "severity",
    "action",
    "target",
    "outcome",
    "riskScore",
  ];

  const rows = logs.map((log) =>
    [
      log.id,
      log.timestamp,
      log.eventType,
      log.severity,
      log.action.replace(/,/g, ";"),
      log.target.identifier,
      log.outcome,
      log.riskAssessment?.score || "",
    ].join(",")
  );

  return [headers.join(","), ...rows].join("\n");
}

/**
 * Clear audit logs (admin function)
 */
export function clearAuditLogs(): void {
  auditStore.clear();
}

// ===========================================
//          Helper Functions
// ===========================================

function getSeverityFromAction(
  action: string,
  riskScore?: number
): AuditLogEntry["severity"] {
  if (action === "BLOCKED") return "HIGH";
  if (action === "FAILED") return "MEDIUM";

  if (riskScore !== undefined) {
    if (riskScore >= 80) return "CRITICAL";
    if (riskScore >= 60) return "HIGH";
    if (riskScore >= 40) return "MEDIUM";
    if (riskScore >= 20) return "LOW";
  }

  return "INFO";
}

function calculateAverageRiskScore(logs: AuditLogEntry[]): number {
  const scoresWithRisk = logs.filter((l) => l.riskAssessment?.score);
  if (scoresWithRisk.length === 0) return 0;

  const total = scoresWithRisk.reduce(
    (sum, log) => sum + (log.riskAssessment?.score || 0),
    0
  );
  return Math.round(total / scoresWithRisk.length);
}
