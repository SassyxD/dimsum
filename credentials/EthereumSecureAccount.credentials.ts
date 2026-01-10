/**
 * Ethereum Secure Account Credentials
 *
 * Enhanced wallet credentials with security features
 * Supports private key, mnemonic, and hardware wallet hints
 */

import {
  ICredentialType,
  INodeProperties,
} from "n8n-workflow";

export class EthereumSecureAccount implements ICredentialType {
  name = "ethereumSecureAccount";
  displayName = "Ethereum Secure Account";
  documentationUrl = "https://ethereum.org/en/developers/docs/accounts/";
  icon = "file:ethereum.svg" as const;

  properties: INodeProperties[] = [
    // Account Type Selection
    {
      displayName: "Account Type",
      name: "accountType",
      type: "options",
      options: [
        {
          name: "Private Key",
          value: "privateKey",
          description: "Use a private key for signing",
        },
        {
          name: "Mnemonic Phrase",
          value: "mnemonic",
          description: "Use a mnemonic (seed phrase) for signing",
        },
        {
          name: "Hardware Wallet (Ledger)",
          value: "ledger",
          description: "Use a Ledger hardware wallet (requires local setup)",
        },
        {
          name: "AWS KMS",
          value: "awsKms",
          description: "Use AWS Key Management Service for signing",
        },
        {
          name: "HashiCorp Vault",
          value: "vault",
          description: "Use HashiCorp Vault for key management",
        },
      ],
      default: "privateKey",
      description: "Select the type of account to use for signing transactions",
    },

    // Private Key Configuration
    {
      displayName: "Private Key",
      name: "privateKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          accountType: ["privateKey"],
        },
      },
      default: "",
      placeholder: "0x1234567890abcdef...",
      description:
        "The private key of your Ethereum wallet (64 hex characters, with or without 0x prefix)",
    },

    // Mnemonic Configuration
    {
      displayName: "Mnemonic Phrase",
      name: "mnemonic",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          accountType: ["mnemonic"],
        },
      },
      default: "",
      placeholder: "word1 word2 word3 ... word12",
      description: "The 12 or 24 word mnemonic phrase (seed phrase)",
    },
    {
      displayName: "Derivation Path",
      name: "path",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["mnemonic", "ledger"],
        },
      },
      default: "m/44'/60'/0'/0/0",
      placeholder: "m/44'/60'/0'/0/0",
      description: "The BIP-44 derivation path for account derivation",
    },
    {
      displayName: "Passphrase",
      name: "passphrase",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          accountType: ["mnemonic"],
        },
      },
      default: "",
      placeholder: "Optional passphrase",
      description: "Optional passphrase for BIP-39 mnemonic (25th word)",
    },

    // Hardware Wallet Configuration
    {
      displayName: "Ledger Device Path",
      name: "ledgerPath",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["ledger"],
        },
      },
      default: "",
      placeholder: "USB device path or 'hid'",
      description:
        "Path to Ledger device. Leave empty for auto-detection. Requires local n8n instance.",
    },
    {
      displayName: "Ledger Account Index",
      name: "ledgerAccountIndex",
      type: "number",
      displayOptions: {
        show: {
          accountType: ["ledger"],
        },
      },
      default: 0,
      description: "Account index on the Ledger device (0 = first account)",
    },

    // AWS KMS Configuration
    {
      displayName: "AWS Region",
      name: "awsRegion",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["awsKms"],
        },
      },
      default: "us-east-1",
      description: "AWS region where the KMS key is located",
    },
    {
      displayName: "KMS Key ID",
      name: "kmsKeyId",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["awsKms"],
        },
      },
      default: "",
      placeholder: "arn:aws:kms:region:account:key/key-id",
      description: "The ARN or ID of the AWS KMS key",
    },
    {
      displayName: "AWS Access Key ID",
      name: "awsAccessKeyId",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["awsKms"],
        },
      },
      default: "",
      description: "AWS Access Key ID (or use IAM role)",
    },
    {
      displayName: "AWS Secret Access Key",
      name: "awsSecretAccessKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          accountType: ["awsKms"],
        },
      },
      default: "",
      description: "AWS Secret Access Key (or use IAM role)",
    },

    // HashiCorp Vault Configuration
    {
      displayName: "Vault URL",
      name: "vaultUrl",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["vault"],
        },
      },
      default: "",
      placeholder: "https://vault.example.com:8200",
      description: "URL of the HashiCorp Vault server",
    },
    {
      displayName: "Vault Token",
      name: "vaultToken",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          accountType: ["vault"],
        },
      },
      default: "",
      description: "Vault authentication token",
    },
    {
      displayName: "Vault Secret Path",
      name: "vaultSecretPath",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["vault"],
        },
      },
      default: "",
      placeholder: "secret/data/ethereum/wallet",
      description: "Path to the secret in Vault containing the private key",
    },
    {
      displayName: "Vault Key Field",
      name: "vaultKeyField",
      type: "string",
      displayOptions: {
        show: {
          accountType: ["vault"],
        },
      },
      default: "privateKey",
      description: "Name of the field containing the private key in the Vault secret",
    },

    // Security Options
    {
      displayName: "Security Options",
      name: "securityOptions",
      type: "collection",
      placeholder: "Add Security Option",
      default: {},
      options: [
        {
          displayName: "Require Confirmation",
          name: "requireConfirmation",
          type: "boolean",
          default: false,
          description:
            "Require manual confirmation for high-value transactions",
        },
        {
          displayName: "Max Transaction Value (ETH)",
          name: "maxTransactionValue",
          type: "number",
          default: 10,
          description:
            "Maximum allowed transaction value without additional confirmation",
        },
        {
          displayName: "Allowed Contract Addresses",
          name: "allowedContracts",
          type: "string",
          default: "",
          placeholder: "0x123..., 0x456...",
          description:
            "Comma-separated list of allowed contract addresses (leave empty to allow all)",
        },
        {
          displayName: "IP Whitelist",
          name: "ipWhitelist",
          type: "string",
          default: "",
          placeholder: "192.168.1.0/24, 10.0.0.1",
          description:
            "Comma-separated list of allowed IP addresses or CIDR ranges",
        },
        {
          displayName: "Enable Audit Logging",
          name: "enableAuditLogging",
          type: "boolean",
          default: true,
          description: "Log all signing operations for audit trail",
        },
      ],
    },
  ];
}
