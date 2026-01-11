/**
 * Sanctions Checker
 *
 * Checks addresses against known sanctions lists
 * Integrates with compliance APIs (Chainalysis, Elliptic, etc.)
 */

import { SanctionsCheck } from "../../utils/types";
import { RiskLevel } from "../../utils/constants";

// ===========================================
//          Known Sanctioned Addresses
// ===========================================

/**
 * OFAC sanctioned addresses (sample - in production, use API)
 * These are publicly known sanctioned addresses
 */
const KNOWN_SANCTIONED_ADDRESSES: Set<string> = new Set([
  // Tornado Cash (OFAC sanctioned)
  "0x8589427373D6D84E98730D7795D8f6f8731FDA16".toLowerCase(),
  "0x722122dF12D4e14e13Ac3b6895a86e84145b6967".toLowerCase(),
  "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384".toLowerCase(),
  "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b".toLowerCase(),
  "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307".toLowerCase(),
  "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBa9D".toLowerCase(),
  "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3".toLowerCase(),
  "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF".toLowerCase(),
  "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291".toLowerCase(),
  "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144".toLowerCase(),
  "0xF60dD140cFf0706bAE9Cd734Ac3ae76AD9eBC32A".toLowerCase(),
  "0x22aaA7720ddd5388A3c0A3333430953C68f1849b".toLowerCase(),
  "0xBA214C1c1928a32Bffe790263E38B4Af9bFCD659".toLowerCase(),
  "0xb1C8094B234DcE6e03f10a5b673c1d8C69739A00".toLowerCase(),
  "0x527653eA119F3E6a1F5BD18fbF4714081D7B31ce".toLowerCase(),
  "0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2".toLowerCase(),
  "0xD691F27f38B395864Ea86CfC7253969B409c362d".toLowerCase(),
  "0xaEaaC358560e11f52454D997AAFF2c5731B6f8a6".toLowerCase(),
  "0x1356c899D8C9467C7f71C195612F8A395aBf2f0a".toLowerCase(),
  "0xA60C772958a3eD56c1F15dD055bA37AC8e523a0D".toLowerCase(),
]);

// ===========================================
//          Sanctions Check
// ===========================================

/**
 * Check if an address is sanctioned
 */
export async function checkSanctions(
  address: string,
  options?: {
    chainalysisApiKey?: string;
    ellipticApiKey?: string;
    useLocalList?: boolean;
  }
): Promise<SanctionsCheck> {
  const normalizedAddress = address.toLowerCase();

  // Start with local list check
  if (options?.useLocalList !== false) {
    const isLocalMatch = KNOWN_SANCTIONED_ADDRESSES.has(normalizedAddress);
    if (isLocalMatch) {
      return {
        isChecked: true,
        isSanctioned: true,
        source: "local_ofac_list",
        matchType: "exact",
        details: "Address matches known OFAC sanctioned address",
      };
    }
  }

  // Check with Chainalysis API if key provided
  if (options?.chainalysisApiKey) {
    try {
      const chainalysisResult = await checkChainalysis(
        address,
        options.chainalysisApiKey
      );
      if (chainalysisResult.isSanctioned) {
        return chainalysisResult;
      }
    } catch (error) {
      console.warn("Chainalysis check failed:", error);
    }
  }

  // Check with Elliptic API if key provided
  if (options?.ellipticApiKey) {
    try {
      const ellipticResult = await checkElliptic(
        address,
        options.ellipticApiKey
      );
      if (ellipticResult.isSanctioned) {
        return ellipticResult;
      }
    } catch (error) {
      console.warn("Elliptic check failed:", error);
    }
  }

  // No sanctions found
  return {
    isChecked: true,
    isSanctioned: false,
    source: options?.chainalysisApiKey || options?.ellipticApiKey
      ? "api_verified"
      : "local_list",
  };
}

/**
 * Check address with Chainalysis API
 */
async function checkChainalysis(
  address: string,
  apiKey: string
): Promise<SanctionsCheck> {
  // Chainalysis Sanctions API endpoint
  const response = await fetch(
    `https://public.chainalysis.com/api/v1/address/${address}`,
    {
      headers: {
        "X-API-Key": apiKey,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Chainalysis API error: ${response.status}`);
  }

  const data = await response.json() as any;

  // Chainalysis returns identifications for sanctioned addresses
  if (data.identifications && data.identifications.length > 0) {
    const sanctionedId = data.identifications.find(
      (id: any) => id.category === "sanctions"
    );

    if (sanctionedId) {
      return {
        isChecked: true,
        isSanctioned: true,
        source: "chainalysis",
        matchType: sanctionedId.name || "sanctions",
        details: sanctionedId.description || "Address is sanctioned",
      };
    }
  }

  return {
    isChecked: true,
    isSanctioned: false,
    source: "chainalysis",
  };
}

/**
 * Check address with Elliptic API
 */
async function checkElliptic(
  address: string,
  apiKey: string
): Promise<SanctionsCheck> {
  // Elliptic Lens API endpoint (placeholder - actual implementation varies)
  const response = await fetch(
    `https://api.elliptic.co/v2/wallet/synchronous`,
    {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        subject: {
          asset: "holistic",
          blockchain: "ethereum",
          hash: address,
          type: "address",
        },
        type: "wallet_exposure",
      }),
    }
  );

  if (!response.ok) {
    throw new Error(`Elliptic API error: ${response.status}`);
  }

  const data = await response.json() as any;

  // Check for sanctions in the response
  if (data.risk_score && data.risk_score >= 10) {
    // Risk score of 10 typically indicates sanctioned
    return {
      isChecked: true,
      isSanctioned: true,
      source: "elliptic",
      matchType: "high_risk",
      details: `Risk score: ${data.risk_score}`,
    };
  }

  return {
    isChecked: true,
    isSanctioned: false,
    source: "elliptic",
  };
}

// ===========================================
//          Batch Sanctions Check
// ===========================================

/**
 * Check multiple addresses for sanctions
 */
export async function checkSanctionsBatch(
  addresses: string[],
  options?: {
    chainalysisApiKey?: string;
    ellipticApiKey?: string;
  }
): Promise<Map<string, SanctionsCheck>> {
  const results = new Map<string, SanctionsCheck>();

  // Check in parallel with rate limiting
  const batchSize = 10;
  for (let i = 0; i < addresses.length; i += batchSize) {
    const batch = addresses.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((addr) => checkSanctions(addr, options))
    );

    for (let j = 0; j < batch.length; j++) {
      results.set(batch[j], batchResults[j]);
    }

    // Rate limiting delay between batches
    if (i + batchSize < addresses.length) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  return results;
}

// ===========================================
//          Sanctions List Management
// ===========================================

/**
 * Add address to local sanctions list
 */
export function addToLocalSanctionsList(address: string): void {
  KNOWN_SANCTIONED_ADDRESSES.add(address.toLowerCase());
}

/**
 * Remove address from local sanctions list
 */
export function removeFromLocalSanctionsList(address: string): void {
  KNOWN_SANCTIONED_ADDRESSES.delete(address.toLowerCase());
}

/**
 * Get count of addresses in local sanctions list
 */
export function getLocalSanctionsListSize(): number {
  return KNOWN_SANCTIONED_ADDRESSES.size;
}

/**
 * Check if address is in local sanctions list
 */
export function isInLocalSanctionsList(address: string): boolean {
  return KNOWN_SANCTIONED_ADDRESSES.has(address.toLowerCase());
}
