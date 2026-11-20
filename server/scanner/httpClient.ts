import { PRACTICE_LAB_HOSTNAME, validateTargetUrl } from '../security/ssrfGuard.ts';
import { simulatePracticeHttp } from './practiceTarget.ts';
import type { HttpResponseSnapshot } from './types.ts';

export class SsrfSafeHttpClient {
  private lastRequestAt = 0;
  private readonly minIntervalMs: number;
  private readonly allowedHostname: string;
  private readonly allowPracticeTarget: boolean;
  private readonly timeoutMs: number;

  constructor(options: {
    allowedHostname: string;
    allowPracticeTarget: boolean;
    rateLimitRps: number;
    timeoutMs: number;
  }) {
    this.allowedHostname = options.allowedHostname.toLowerCase();
    this.allowPracticeTarget = options.allowPracticeTarget;
    this.minIntervalMs = Math.max(50, Math.floor(1000 / Math.max(1, options.rateLimitRps)));
    this.timeoutMs = Math.min(15000, Math.max(1500, options.timeoutMs));
  }

  private async throttle(): Promise<void> {
    const now = Date.now();
    const wait = this.lastRequestAt + this.minIntervalMs - now;
    if (wait > 0) {
      await new Promise((r) => setTimeout(r, wait));
    }
    this.lastRequestAt = Date.now();
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
    await this.throttle();

    const method = (init.method || 'GET').toUpperCase();
    const followRedirects = init.followRedirects !== false;
    const redirectChain: Array<{ from: string; to: string; status: number }> = [];
    let currentUrl = rawUrl;
    const started = Date.now();

    for (let hop = 0; hop < 5; hop++) {
      const validated = await validateTargetUrl(currentUrl, {
        allowPracticeTarget: this.allowPracticeTarget,
      });

      if (validated.hostname !== this.allowedHostname) {
        throw new Error(
          `Scope violation blocked: redirect or request to "${validated.hostname}" leaves authorized host "${this.allowedHostname}".`
        );
      }

      if (validated.isPracticeTarget || validated.hostname === PRACTICE_LAB_HOSTNAME) {
        return simulatePracticeHttp(currentUrl, method, init.headers || {});
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(validated.url.toString(), {
          method,
          headers: {
            'User-Agent': 'SentinelScan-Authorized-Assessor/1.0 (+security-assessment)',
            Accept: 'text/html,application/json,application/xml;q=0.9,*/*;q=0.8',
            ...(init.headers || {}),
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

        // Cap body read to 512 KB for safety
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
