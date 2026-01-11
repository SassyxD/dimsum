/**
 * Ethereum Secure Platform - Viem Client Factory
 *
 * Creates and manages viem clients with security enhancements
 */

import {
  createPublicClient as viemCreatePublicClient,
  createWalletClient as viemCreateWalletClient,
  http,
  webSocket,
  PublicClient,
  WalletClient,
  Chain,
  Transport,
} from "viem";
import { privateKeyToAccount, mnemonicToAccount } from "viem/accounts";
import * as chains from "viem/chains";
import { SecureClientConfig, WalletConfig } from "./types";
import { SUPPORTED_CHAINS } from "./constants";

// ===========================================
//          Chain Resolution
// ===========================================

/**
 * Get viem chain configuration by chain name or ID
 */
export function getChain(chainNameOrId: string | number): Chain | undefined {
  const chainId =
    typeof chainNameOrId === "string"
      ? SUPPORTED_CHAINS[chainNameOrId]?.id
      : chainNameOrId;

  if (!chainId) return undefined;

  // Map to viem chains
  const chainMap: Record<number, any> = {
    1: chains.mainnet,
    11155111: chains.sepolia,
    42161: chains.arbitrum,
    10: chains.optimism,
    8453: chains.base,
    137: chains.polygon,
    56: chains.bsc,
    43114: chains.avalanche,
    59144: chains.linea,
    324: chains.zkSync,
  };

  return chainMap[chainId];
}

// ===========================================
//          Public Client Factory
// ===========================================

/**
 * Create a public client with security-aware configuration
 */
export function createSecurePublicClient(
  config: SecureClientConfig
): any {
  const { rpcUrl, customHeaders } = config;

  // Parse headers if provided
  let headers: Record<string, string> = {};
  if (customHeaders && typeof customHeaders === "string") {
    try {
      headers = JSON.parse(customHeaders);
    } catch (error) {
      throw new Error("Invalid custom headers JSON format");
    }
  } else if (customHeaders && typeof customHeaders === "object") {
    headers = customHeaders;
  }

  // Determine transport type
  const isWebSocket =
    rpcUrl.startsWith("ws://") || rpcUrl.startsWith("wss://");

  const transport = isWebSocket
    ? webSocket(rpcUrl)
    : http(rpcUrl, {
        fetchOptions: {
          headers,
        },
        timeout: 30000,
        retryCount: 3,
        retryDelay: 1000,
      });

  return viemCreatePublicClient({
    transport,
  }) as any;
}

// ===========================================
//          Wallet Client Factory
// ===========================================

/**
 * Create a wallet client with secure account derivation
 */
export function createSecureWalletClient(
  publicClient: any,
  rpcConfig: SecureClientConfig,
  walletConfig: WalletConfig
): WalletClient {
  const { privateKey, mnemonic, path, passphrase } = walletConfig;

  // Validate wallet configuration
  const hasPrivateKey = privateKey && privateKey.trim() !== "";
  const hasMnemonic = mnemonic && mnemonic.trim() !== "";

  if (!hasPrivateKey && !hasMnemonic) {
    throw new Error(
      "Either Private Key or Mnemonic Phrase is required for wallet operations"
    );
  }

  let account;

  if (hasPrivateKey) {
    account = deriveAccountFromPrivateKey(privateKey);
  } else if (hasMnemonic) {
    account = deriveAccountFromMnemonic(mnemonic, path, passphrase);
  }

  // Recreate transport for wallet client
  const isWebSocket =
    rpcConfig.rpcUrl.startsWith("ws://") ||
    rpcConfig.rpcUrl.startsWith("wss://");

  let headers: Record<string, string> = {};
  if (rpcConfig.customHeaders) {
    if (typeof rpcConfig.customHeaders === "string") {
      headers = JSON.parse(rpcConfig.customHeaders);
    } else {
      headers = rpcConfig.customHeaders;
    }
  }

  const transport = isWebSocket
    ? webSocket(rpcConfig.rpcUrl)
    : http(rpcConfig.rpcUrl, {
        fetchOptions: { headers },
      });

  return viemCreateWalletClient({
    account,
    chain: publicClient.chain,
    transport,
  });
}

// ===========================================
//          Account Derivation
// ===========================================

/**
 * Derive account from private key with validation
 */
function deriveAccountFromPrivateKey(privateKey: string) {
  // Format private key
  const formattedKey = privateKey.startsWith("0x")
    ? (privateKey as `0x${string}`)
    : (`0x${privateKey}` as `0x${string}`);

  // Validate format
  const keyWithoutPrefix = formattedKey.slice(2);
  if (keyWithoutPrefix.length !== 64 || !/^[0-9a-fA-F]+$/.test(keyWithoutPrefix)) {
    throw new Error(
      "Invalid private key format. Must be 64 hexadecimal characters."
    );
  }

  try {
    return privateKeyToAccount(formattedKey);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid private key: ${message}`);
  }
}

/**
 * Derive account from mnemonic with BIP-44 path validation
 */
function deriveAccountFromMnemonic(
  mnemonic: string,
  path?: string,
  passphrase?: string
) {
  // Validate mnemonic word count
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 12 && words.length !== 24) {
    throw new Error("Invalid mnemonic: must be either 12 or 24 words");
  }

  // Set default path if not provided
  const derivationPath = path || "m/44'/60'/0'/0/0";

  // Validate path format
  if (!derivationPath.startsWith("m/44'/60'/")) {
    throw new Error(
      `Invalid derivation path: must start with m/44'/60'/`
    );
  }

  try {
    return mnemonicToAccount(mnemonic, {
      path: derivationPath as `m/44'/60'/${string}`,
      ...(passphrase && { passphrase }),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid mnemonic or derivation path: ${message}`);
  }
}

// ===========================================
//          Client Utilities
// ===========================================

/**
 * Get the current address from wallet client
 */
export function getWalletAddress(walletClient: WalletClient): string {
  if (!walletClient.account) {
    throw new Error("No account configured in wallet client");
  }
  return walletClient.account.address;
}

/**
 * Check if RPC endpoint is healthy
 */
export async function checkRpcHealth(
  client: any
): Promise<{ healthy: boolean; blockNumber?: bigint; latency?: number }> {
  const startTime = Date.now();

  try {
    const blockNumber = await client.getBlockNumber();
    const latency = Date.now() - startTime;

    return {
      healthy: true,
      blockNumber,
      latency,
    };
  } catch (error) {
    return {
      healthy: false,
    };
  }
}
