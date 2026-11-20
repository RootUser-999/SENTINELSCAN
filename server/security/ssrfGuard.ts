import dns from 'node:dns';
import net from 'node:net';

export const PRACTICE_LAB_HOSTNAME = 'practice-shop.sentinel-lab.internal';

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

function inIpv4Cidr(ip: string, cidrBase: string, maskBits: number): boolean {
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(cidrBase);
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase();

  // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
  if (normalized.startsWith('::ffff:')) {
    const v4 = normalized.slice(7);
    if (net.isIPv4(v4)) {
      return isPrivateOrReservedIp(v4);
    }
  }

  if (net.isIPv4(normalized)) {
    const blockedCidrs: Array<[string, number]> = [
      ['0.0.0.0', 8],       // Current network
      ['10.0.0.0', 8],      // RFC 1918 Private
      ['100.64.0.0', 10],   // Carrier-grade NAT (RFC 6598)
      ['127.0.0.0', 8],     // Loopback
      ['169.254.0.0', 16],  // Link-local & Cloud Metadata (169.254.169.254)
      ['172.16.0.0', 12],   // RFC 1918 Private
      ['192.0.0.0', 24],    // IETF Protocol Assignments
      ['192.0.2.0', 24],    // TEST-NET-1
      ['192.168.0.0', 16],  // RFC 1918 Private
      ['198.18.0.0', 15],   // Benchmarking
      ['198.51.100.0', 24], // TEST-NET-2
      ['203.0.113.0', 24],  // TEST-NET-3
      ['224.0.0.0', 4],     // Multicast
      ['240.0.0.0', 4],     // Reserved / Broadcast
    ];
    return blockedCidrs.some(([base, bits]) => inIpv4Cidr(normalized, base, bits));
  }

  if (net.isIPv6(normalized)) {
    if (normalized === '::' || normalized === '::1') return true; // Unspecified / Loopback
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
      return true; // Link-local fe80::/10
    }
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
      return true; // Unique local fc00::/7
    }
    if (normalized.startsWith('ff')) {
      return true; // Multicast ff00::/8
    }
    return false;
  }

  // Unrecognized format -> fail closed
  return true;
}

export function isBlockedHostnameSyntax(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.arpa')) {
    return true;
  }
  if (h === 'metadata.google.internal' || h === '169.254.169.254') return true;
  return false;
}

export interface ValidatedTarget {
  url: URL;
  hostname: string;
  isPracticeTarget: boolean;
  resolvedIps: string[];
}

export async function validateTargetUrl(
  rawUrl: string,
  options: { allowPracticeTarget?: boolean; skipDnsLookup?: boolean } = {}
): Promise<ValidatedTarget> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid URL format. Provide a full http:// or https:// URL.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported URL scheme "${parsed.protocol}". Only http: and https: are permitted.`);
  }

  if (parsed.username || parsed.password) {
    throw new Error('Embedded credentials in target URLs are not permitted.');
  }

  const hostname = parsed.hostname.toLowerCase();

  // Explicit isolated in-process practice lab target (never opens network sockets)
  if (hostname === PRACTICE_LAB_HOSTNAME) {
    if (!options.allowPracticeTarget) {
      throw new Error('Practice lab target is only permitted in authorized practice lab mode.');
    }
    return {
      url: parsed,
      hostname,
      isPracticeTarget: true,
      resolvedIps: ['in-process-isolated-lab'],
    };
  }

  if (isBlockedHostnameSyntax(hostname)) {
    throw new Error(`Target hostname "${hostname}" is blocked by SSRF scope protection.`);
  }

  // Direct IP literal check
  if (net.isIP(hostname) !== 0) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error(`Target IP "${hostname}" is in a private, loopback, or reserved range.`);
    }
    return {
      url: parsed,
      hostname,
      isPracticeTarget: false,
      resolvedIps: [hostname],
    };
  }

  if (options.skipDnsLookup) {
    return {
      url: parsed,
      hostname,
      isPracticeTarget: false,
      resolvedIps: [],
    };
  }

  let records: dns.LookupAddress[];
  try {
    records = await dns.promises.lookup(hostname, { all: true });
  } catch {
    throw new Error(`DNS resolution failed for "${hostname}". Verify the domain exists and is publicly reachable.`);
  }

  if (!records.length) {
    throw new Error(`No DNS A/AAAA records found for "${hostname}".`);
  }

  const resolvedIps = records.map((r) => r.address);
  for (const ip of resolvedIps) {
    if (isPrivateOrReservedIp(ip)) {
      throw new Error(
        `SSRF protection blocked "${hostname}" because DNS resolved to non-public IP ${ip}.`
      );
    }
  }

  return {
    url: parsed,
    hostname,
    isPracticeTarget: false,
    resolvedIps,
  };
}
