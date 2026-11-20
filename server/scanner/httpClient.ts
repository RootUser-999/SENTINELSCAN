import { PRACTICE_LAB_HOSTNAME, validateTargetUrl } from '../security/ssrfGuard.ts';
import { simulatePracticeHttp } from './practiceTarget.ts';
import type { HttpResponseSnapshot } from './types.ts';

export class RequestBudgetExceededError extends Error {
  constructor(limit: number) {
    super(`Scan HTTP request budget reached (${limit} requests).`);
    this.name = 'RequestBudgetExceededError';
  }
}

export type MockHttpTransport = (
  rawUrl: string,
  method: string,
  headers: Record<string, string>,
  body?: string
) => HttpResponseSnapshot;

export class SsrfSafeHttpClient {
  private nextSlotAt = 0;
  private throttleChain: Promise<void> = Promise.resolve();
  private readonly minIntervalMs: number;
  private readonly allowedHostname: string;
  private readonly allowPracticeTarget: boolean;
  private readonly timeoutMs: number;
  private readonly maxRequests: number;
  private readonly maxRetries: number;
  private readonly defaultHeaders: Record<string, string>;
  private readonly mockTransport?: MockHttpTransport;

  private requestsSent = 0;
  private retries = 0;
  private errors = 0;

  constructor(options: {
    allowedHostname: string;
    allowPracticeTarget: boolean;
    rateLimitRps: number;
    timeoutMs: number;
    maxRequests?: number;
    maxRetries?: number;
    defaultHeaders?: Record<string, string>;
    mockTransport?: MockHttpTransport;
  }) {
    this.allowedHostname = options.allowedHostname.toLowerCase();
    this.allowPracticeTarget = options.allowPracticeTarget;
    this.minIntervalMs = options.mockTransport || options.allowPracticeTarget
      ? Math.max(2, Math.floor(200 / Math.max(1, options.rateLimitRps)))
      : Math.max(40, Math.floor(1000 / Math.max(1, options.rateLimitRps)));
    this.timeoutMs = Math.min(25000, Math.max(1500, options.timeoutMs));
    this.maxRequests = Math.max(20, Math.min(2000, options.maxRequests ?? 250));
    this.maxRetries = options.maxRetries ?? 2;
    this.defaultHeaders = options.defaultHeaders ?? {};
    this.mockTransport = options.mockTransport;
  }

  getStats(): { requestsSent: number; retries: number; errors: number; budgetRemaining: number } {
    return {
      requestsSent: this.requestsSent,
      retries: this.retries,
      errors: this.errors,
      budgetRemaining: Math.max(0, this.maxRequests - this.requestsSent),
    };
  }

  private async acquireSlot(): Promise<void> {
    const waitPromise = this.throttleChain.then(async () => {
      const now = Date.now();
      const delay = Math.max(0, this.nextSlotAt - now);
      this.nextSlotAt = Math.max(now, this.nextSlotAt) + this.minIntervalMs;
      if (delay > 0) {
        await new Promise((r) => setTimeout(r, delay));
      }
    });
    this.throttleChain = waitPromise.catch(() => {});
    await waitPromise;
  }

  async request(
    rawUrl: string,
    init: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
      followRedirects?: boolean;
    } = {}
  ): Promise<HttpResponseSnapshot> {
    const method = (init.method || 'GET').toUpperCase();
    const isIdempotent = method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
    const maxAttempts = isIdempotent ? 1 + this.maxRetries : 1;

    let lastError: unknown;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (this.requestsSent >= this.maxRequests) {
        throw new RequestBudgetExceededError(this.maxRequests);
      }

      if (attempt > 0) {
        this.retries += 1;
        await new Promise((r) => setTimeout(r, Math.min(1200, 150 * Math.pow(2, attempt - 1))));
      }

      try {
        const res = await this.executeSingleAttempt(rawUrl, method, init);
        if (isIdempotent && (res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504) && attempt + 1 < maxAttempts) {
          const retryAfter = Number(res.headers['retry-after']);
          if (Number.isFinite(retryAfter) && retryAfter > 0 && retryAfter <= 2) {
            await new Promise((r) => setTimeout(r, retryAfter * 1000));
          }
          continue;
        }
        return res;
      } catch (err) {
        lastError = err;
        if (err instanceof RequestBudgetExceededError) throw err;
        const msg = err instanceof Error ? err.message : '';
        // Never retry scope or SSRF rejections
        if (msg.includes('Scope violation blocked') || msg.includes('SSRF') || msg.includes('Target URL')) {
          this.errors += 1;
          throw err;
        }
        if (attempt + 1 >= maxAttempts) {
          this.errors += 1;
          throw err;
        }
      }
    }

    this.errors += 1;
    throw lastError instanceof Error ? lastError : new Error('HTTP request failed');
  }

  private async executeSingleAttempt(
    rawUrl: string,
    method: string,
    init: {
      headers?: Record<string, string>;
      body?: string;
      followRedirects?: boolean;
    }
  ): Promise<HttpResponseSnapshot> {
    await this.acquireSlot();
    this.requestsSent += 1;

    const followRedirects = init.followRedirects !== false;
    const redirectChain: Array<{ from: string; to: string; status: number }> = [];
    let currentUrl = rawUrl;
    const started = Date.now();
    const mergedHeaders: Record<string, string> = {
      ...this.defaultHeaders,
      ...(init.headers || {}),
    };

    for (let hop = 0; hop < 5; hop++) {
      const validated = await validateTargetUrl(currentUrl, {
        allowPracticeTarget: this.allowPracticeTarget,
        skipDnsLookup: Boolean(this.mockTransport) || this.allowPracticeTarget,
      });

      if (validated.hostname !== this.allowedHostname) {
        throw new Error(
          `Scope violation blocked: redirect or request to "${validated.hostname}" leaves authorized host "${this.allowedHostname}".`
        );
      }

      if (this.mockTransport) {
        const snap = this.mockTransport(currentUrl, method, mergedHeaders, init.body);
        if (followRedirects && snap.status >= 300 && snap.status < 400 && snap.headers['location']) {
          const nextUrl = new URL(snap.headers['location'], validated.url).toString();
          redirectChain.push({ from: currentUrl, to: nextUrl, status: snap.status });
          currentUrl = nextUrl;
          continue;
        }
        return { ...snap, url: rawUrl, redirectChain };
      }

      if (validated.isPracticeTarget || validated.hostname === PRACTICE_LAB_HOSTNAME) {
        const snap = simulatePracticeHttp(currentUrl, method, mergedHeaders, init.body);
        if (followRedirects && snap.status >= 300 && snap.status < 400 && snap.headers['location']) {
          const nextUrl = new URL(snap.headers['location'], validated.url).toString();
          redirectChain.push({ from: currentUrl, to: nextUrl, status: snap.status });
          currentUrl = nextUrl;
          continue;
        }
        return { ...snap, url: rawUrl, redirectChain };
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(validated.url.toString(), {
          method,
          headers: {
            'User-Agent': 'SentinelScan-Authorized-Assessor/2.0 (+security-assessment)',
            Accept: 'text/html,application/json,application/xml;q=0.9,*/*;q=0.8',
            ...mergedHeaders,
          },
          body: method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' ? init.body : undefined,
          redirect: 'manual',
          signal: controller.signal,
        });

        const headers: Record<string, string> = {};
        res.headers.forEach((v, k) => {
          headers[k.toLowerCase()] = v;
        });

        const setCookies =
          typeof (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function'
            ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
            : headers['set-cookie']
              ? [headers['set-cookie']]
              : [];

        if (followRedirects && res.status >= 300 && res.status < 400 && headers['location']) {
          const nextUrl = new URL(headers['location'], validated.url).toString();
          redirectChain.push({ from: currentUrl, to: nextUrl, status: res.status });
          currentUrl = nextUrl;
          continue;
        }

        const text = await res.text();
        const bodyText = text.length > 524288 ? text.slice(0, 524288) : text;

        return {
          url: rawUrl,
          finalUrl: currentUrl,
          status: res.status,
          headers,
          setCookies,
          bodyText,
          redirectChain,
          durationMs: Date.now() - started,
        };
      } finally {
        clearTimeout(timer);
      }
    }

    throw new Error('Exceeded maximum safe redirect hops (5)');
  }
}
