import crypto from 'node:crypto';

const EPHEMERAL_VAULT_KEY = crypto.randomBytes(32);

function getVaultKey(): Buffer {
  const envKey = process.env.SENTINEL_VAULT_KEY;
  if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey.trim())) {
    return Buffer.from(envKey.trim(), 'hex');
  }
  if (envKey && envKey.trim().length >= 16) {
    return crypto.createHash('sha256').update(envKey.trim()).digest();
  }
  return EPHEMERAL_VAULT_KEY;
}

export interface EncryptedBlob {
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
}

export function encryptSecret(plaintext: string): EncryptedBlob {
  const key = getVaultKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertextHex: encrypted.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
  };
}

export function decryptSecret(blob: EncryptedBlob): string | null {
  try {
    const key = getVaultKey();
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(blob.ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(blob.authTagHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertextHex, 'hex')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

export function redactSecrets(input: string, extraSecrets: string[] = []): string {
  let out = input;
  for (const s of extraSecrets) {
    if (s && s.length >= 4) {
      out = out.split(s).join('[REDACTED]');
    }
  }
  // Redact common Authorization / Cookie / Token patterns
  out = out.replace(/(Bearer\s+)(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+=*/gi, '$1[REDACTED]');
  out = out.replace(/(Basic\s+)(?!\[REDACTED\])[A-Za-z0-9+/=]+/gi, '$1[REDACTED]');
  out = out.replace(/((?:api_?key|token|secret|password|cookie)\s*[:=]\s*["']?)(?!\[REDACTED\])[^\s"';\r\n]+/gi, '$1[REDACTED]');
  return out;
}
