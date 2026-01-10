/**
 * Threat Intelligence Credentials
 *
 * API keys for threat intelligence services
 * (Chainalysis, Elliptic, Etherscan, etc.)
 */

import {
  ICredentialType,
  INodeProperties,
} from "n8n-workflow";

export class ThreatIntelligence implements ICredentialType {
  name = "threatIntelligence";
  displayName = "Threat Intelligence APIs";
  documentationUrl = "https://www.chainalysis.com/free-cryptocurrency-sanctions-screening-tools/";
  icon = "file:security.svg" as const;

  properties: INodeProperties[] = [
    // Block Explorer APIs
    {
      displayName: "Block Explorer APIs",
      name: "blockExplorerHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "Etherscan API Key",
      name: "etherscanApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      placeholder: "YOUR-ETHERSCAN-API-KEY",
      description:
        "API key for Etherscan and related explorers (Arbiscan, Polygonscan, etc.)",
    },
    {
      displayName: "Basescan API Key",
      name: "basescanApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API key for Base chain explorer",
    },

    // Sanctions & Compliance APIs
    {
      displayName: "Compliance APIs",
      name: "complianceHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "Chainalysis API Key",
      name: "chainalysisApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      placeholder: "YOUR-CHAINALYSIS-API-KEY",
      description:
        "API key for Chainalysis sanctions screening (free tier available)",
    },
    {
      displayName: "Elliptic API Key",
      name: "ellipticApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API key for Elliptic compliance and risk scoring",
    },

    // Token Security APIs
    {
      displayName: "Token Security APIs",
      name: "tokenSecurityHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "GoPlus API Key",
      name: "goPlusApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description:
        "API key for GoPlus Security API (token security, honeypot detection)",
    },
    {
      displayName: "TokenSniffer API Key",
      name: "tokenSnifferApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API key for TokenSniffer scam detection",
    },

    // Monitoring & Alerting
    {
      displayName: "Monitoring & Alerting",
      name: "monitoringHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "Forta API Key",
      name: "fortaApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API key for Forta threat detection network",
    },
    {
      displayName: "OpenZeppelin Defender API Key",
      name: "defenderApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API key for OpenZeppelin Defender",
    },
    {
      displayName: "OpenZeppelin Defender API Secret",
      name: "defenderApiSecret",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "API secret for OpenZeppelin Defender",
    },

    // Alert Channels
    {
      displayName: "Alert Channels",
      name: "alertChannelsHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "Telegram Bot Token",
      name: "telegramBotToken",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      description: "Telegram bot token for security alerts",
    },
    {
      displayName: "Telegram Chat ID",
      name: "telegramChatId",
      type: "string",
      default: "",
      description: "Telegram chat ID for receiving alerts",
    },
    {
      displayName: "Discord Webhook URL",
      name: "discordWebhookUrl",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      placeholder: "https://discord.com/api/webhooks/...",
      description: "Discord webhook URL for security alerts",
    },
    {
      displayName: "Slack Webhook URL",
      name: "slackWebhookUrl",
      type: "string",
      typeOptions: {
        password: true,
      },
      default: "",
      placeholder: "https://hooks.slack.com/services/...",
      description: "Slack webhook URL for security alerts",
    },

    // Configuration
    {
      displayName: "Configuration",
      name: "configHeader",
      type: "notice",
      default: "",
    },
    {
      displayName: "Enable Real-time Alerts",
      name: "enableAlerts",
      type: "boolean",
      default: true,
      description: "Enable real-time security alerts",
    },
    {
      displayName: "Alert Severity Threshold",
      name: "alertSeverityThreshold",
      type: "options",
      options: [
        { name: "Critical Only", value: "critical" },
        { name: "High and Above", value: "high" },
        { name: "Medium and Above", value: "medium" },
        { name: "All Alerts", value: "low" },
      ],
      default: "high",
      description: "Minimum severity level for alerts",
    },
  ];
}
