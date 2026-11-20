import { RequestBudgetExceededError } from './httpClient.ts';
import type {
  CrawledPage,
  CrawlResult,
  DiscoveredEndpointCandidate,
  DiscoveredForm,
  DiscoveredJsResource,
  HttpResponseSnapshot,
  ScanContext,
} from './types.ts';

const SKIPPED_BINARY_EXT = /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|mp4|mp3|webm|pdf|zip|tar|gz|rar|css|map)(?:\?|$)/i;
const CSRF_FIELD_NAME_REGEX = /(csrf|_token|xsrf|authenticity_token|__RequestVerificationToken|anti_forgery)/i;
const DOM_XSS_JS_REGEX = /(?:location\.search|location\.hash|document\.URL|document\.referrer|window\.name|URLSearchParams)[\s\S]{0,240}(?:\.innerHTML\b|\.outerHTML\b|document\.write\(|insertAdjacentHTML\(|dangerouslySetInnerHTML|bypassSecurityTrustHtml|\beval\()/gi;
const JS_API_ROUTE_REGEX = /["'`]((?:\/api\/|\/rest\/|\/graphql\b|\/v[1-9]\/|\/auth\/|\/admin\/|\/users\b|\/orders\b)[^"'`\s\\<>{}]{0,120})["'`]/gi;
const JS_SECRET_REGEX = /(?:sk_live_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})/g;

export function isPathInScope(path: string, includePaths: string[], excludePaths: string[]): boolean {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  for (const ex of excludePaths) {
    const clean = ex.trim();
    if (clean && normalized.startsWith(clean)) return false;
  }
  if (!includePaths || includePaths.length === 0) return true;
  return includePaths.some((inc) => {
    const clean = inc.trim();
    if (!clean || clean === '/') return true;
    return normalized.startsWith(clean);
  });
}

function canonicalCrawlKey(urlObj: URL): string {
  const params = Array.from(urlObj.searchParams.keys()).sort().join('&');
  const normPath = urlObj.pathname === '/' ? '/' : urlObj.pathname.replace(/\/+$/, '');
  return `${urlObj.origin}${normPath}${params ? `?keys=${params}` : ''}`;
}

function extractUrlsFromHtml(html: string, baseUrl: string, origin: string): string[] {
  const found = new Set<string>();
  const attrRegex = /(?:href|src|action)=["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = attrRegex.exec(html)) !== null) {
    const raw = m[1].trim();
    if (!raw || /^(?:mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    try {
      const resolved = new URL(raw, baseUrl);
      if (resolved.origin !== origin) continue;
      if (SKIPPED_BINARY_EXT.test(resolved.pathname)) continue;
      resolved.hash = '';
      found.add(resolved.toString());
    } catch {
      // Ignore malformed relative href
    }
  }
  return Array.from(found);
}

function extractScriptUrls(html: string, baseUrl: string, origin: string): string[] {
  const scripts = new Set<string>();
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRegex.exec(html)) !== null) {
    try {
      const resolved = new URL(m[1].trim(), baseUrl);
      if (resolved.origin === origin) {
        resolved.hash = '';
        scripts.add(resolved.toString());
      }
    } catch {
      // ignore
    }
  }
  return Array.from(scripts);
}

export function extractFormsFromHtml(html: string, pageUrl: string, origin: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m: RegExpExecArray | null;
  while ((m = formRegex.exec(html)) !== null) {
    const attrs = m[1] || '';
    const inner = m[2] || '';
    const actionMatch = attrs.match(/action\s*=\s*["']([^"']*)["']/i);
    const methodMatch = attrs.match(/method\s*=\s*["']([^"']*)["']/i);
    const enctypeMatch = attrs.match(/enctype\s*=\s*["']([^"']*)["']/i);

    let actionUrl = pageUrl;
    if (actionMatch && actionMatch[1].trim()) {
      try {
        const resolved = new URL(actionMatch[1].trim(), pageUrl);
        if (resolved.origin === origin) actionUrl = resolved.toString();
      } catch {
        // default to pageUrl
      }
    }

    const fields: Array<{ name: string; type: string }> = [];
    const inputRegex = /<(?:input|select|textarea)\b([^>]*)>/gi;
    let im: RegExpExecArray | null;
    while ((im = inputRegex.exec(inner)) !== null) {
      const iAttrs = im[1] || '';
      const nameMatch = iAttrs.match(/name\s*=\s*["']([^"']+)["']/i);
      const typeMatch = iAttrs.match(/type\s*=\s*["']([^"']+)["']/i);
      if (nameMatch) {
        fields.push({ name: nameMatch[1], type: (typeMatch?.[1] || 'text').toLowerCase() });
      }
    }

    const method = (methodMatch?.[1] || 'GET').toUpperCase();
    const enctype = (enctypeMatch?.[1] || 'application/x-www-form-urlencoded').toLowerCase();
    const hasCsrfField =
      fields.some((f) => CSRF_FIELD_NAME_REGEX.test(f.name)) ||
      CSRF_FIELD_NAME_REGEX.test(inner);
    const hasPasswordField = fields.some((f) => f.type === 'password');
    const hasFileInput = fields.some((f) => f.type === 'file') || enctype.includes('multipart/form-data');

    forms.push({
      pageUrl,
      actionUrl,
      method,
      enctype,
      fields,
      hasCsrfField,
      hasPasswordField,
      hasFileInput,
    });
  }
  return forms;
}

export async function crawlTargetSurface(ctx: ScanContext): Promise<CrawlResult> {
  if (ctx.sharedState.crawlResult) {
    return ctx.sharedState.crawlResult;
  }

  const baseRes = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
  ctx.sharedState.homepageResponse = baseRes;
  const origin = new URL(baseRes.finalUrl).origin;

  const maxDepth = ctx.profile === 'quick' ? 1 : Math.min(5, Math.max(1, ctx.maxDepth || 2));
  const maxUrls =
    ctx.profile === 'quick'
      ? Math.min(12, Math.max(1, ctx.maxUrls || 12))
      : Math.min(250, Math.max(1, ctx.maxUrls || 60));
  const concurrency = Math.min(6, Math.max(1, ctx.concurrencyLimit || 3));

  const visitedKeys = new Set<string>();
  const pages: CrawledPage[] = [];
  const allForms: DiscoveredForm[] = [];
  const paramMap = new Map<string, { url: string; path: string; method: string; params: Set<string> }>();
  const endpointMap = new Map<string, DiscoveredEndpointCandidate>();
  const scriptUrls = new Set<string>();
  const discoveredApiRoutes = new Set<string>();
  const loginPages = new Set<string>();
  const uploadEndpoints: Array<{ pageUrl: string; actionUrl: string; fieldNames: string[] }> = [];

  let maxDepthReached = 0;
  let stoppedReason: CrawlResult['stats']['stoppedReason'] = 'completed';

  const recordEndpoint = (ep: DiscoveredEndpointCandidate) => {
    const key = `${ep.method}|${ep.path}|${ep.source}`;
    const existing = endpointMap.get(key);
    if (!existing) {
      endpointMap.set(key, ep);
    } else {
      const mergedParams = new Set([...existing.parameters, ...ep.parameters]);
      existing.parameters = Array.from(mergedParams);
      if (ep.statusCode !== null) existing.statusCode = ep.statusCode;
    }
  };

  const recordParameterized = (urlStr: string, method: string, params: string[]) => {
    if (params.length === 0) return;
    try {
      const u = new URL(urlStr);
      const key = `${method}|${u.pathname}`;
      const existing = paramMap.get(key);
      if (!existing) {
        paramMap.set(key, { url: urlStr, path: u.pathname, method, params: new Set(params) });
      } else {
        for (const p of params) existing.params.add(p);
      }
    } catch {
      // ignore
    }
  };

  const processPage = (res: HttpResponseSnapshot, depth: number): Array<{ url: string; depth: number }> => {
    maxDepthReached = Math.max(maxDepthReached, depth);
    const finalU = new URL(res.finalUrl);
    const queryParams = Array.from(finalU.searchParams.keys());
    const contentType = res.headers['content-type'] || null;

    if (res.url !== res.finalUrl) {
      try {
        const origU = new URL(res.url);
        if (isPathInScope(origU.pathname, ctx.scopeIncludePaths, ctx.scopeExcludePaths)) {
          const origParams = Array.from(origU.searchParams.keys());
          recordEndpoint({
            url: res.url,
            path: origU.pathname,
            method: 'GET',
            source: 'crawl',
            authRequired: 'none_detected',
            statusCode: res.redirectChain[0]?.status ?? res.status,
            contentType,
            parameters: origParams,
            notes: `Redirected during crawl (depth ${depth}) -> ${finalU.pathname}`,
          });
          recordParameterized(res.url, 'GET', origParams);
        }
      } catch {
        // ignore invalid original URL
      }
    }

    if (!isPathInScope(finalU.pathname, ctx.scopeIncludePaths, ctx.scopeExcludePaths)) {
      return [];
    }

    ctx.sharedState.discoveredUrls.add(res.finalUrl);
    pages.push({
      url: res.url,
      finalUrl: res.finalUrl,
      path: finalU.pathname,
      depth,
      status: res.status,
      contentType,
      headers: res.headers,
      setCookies: res.setCookies,
      bodyText: res.bodyText,
      queryParams,
    });

    recordEndpoint({
      url: res.finalUrl,
      path: finalU.pathname,
      method: 'GET',
      source: 'crawl',
      authRequired: res.status === 401 || res.status === 403 ? 'required' : 'none_detected',
      statusCode: res.status,
      contentType,
      parameters: queryParams,
      notes: `Crawled at depth ${depth}`,
    });
    recordParameterized(res.finalUrl, 'GET', queryParams);

    if (/\/(?:login|signin|sign-in|auth|sso|session)/i.test(finalU.pathname)) {
      loginPages.add(res.finalUrl);
    }

    const nextQueue: Array<{ url: string; depth: number }> = [];
    if (!contentType || /html|xhtml/i.test(contentType)) {
      const forms = extractFormsFromHtml(res.bodyText, res.finalUrl, origin);
      for (const form of forms) {
        allForms.push(form);
        const fUrl = new URL(form.actionUrl);
        const fieldNames = form.fields.map((f) => f.name);
        recordEndpoint({
          url: form.actionUrl,
          path: fUrl.pathname,
          method: form.method,
          source: 'crawl',
          authRequired: form.hasPasswordField ? 'required' : 'unknown',
          statusCode: null,
          contentType: form.enctype,
          parameters: fieldNames,
          notes: form.hasPasswordField
            ? 'Login / authentication form discovered'
            : form.hasFileInput
              ? 'File upload form discovered'
              : 'HTML form discovered during crawl',
        });
        recordParameterized(form.actionUrl, form.method, fieldNames);
        if (form.hasPasswordField) loginPages.add(res.finalUrl);
        if (form.hasFileInput) {
          uploadEndpoints.push({
            pageUrl: form.pageUrl,
            actionUrl: form.actionUrl,
            fieldNames: form.fields.filter((f) => f.type === 'file').map((f) => f.name),
          });
        }
      }

      for (const sUrl of extractScriptUrls(res.bodyText, res.finalUrl, origin)) {
        scriptUrls.add(sUrl);
      }

      // Extract inline JS API route hints as well
      let apiM: RegExpExecArray | null;
      JS_API_ROUTE_REGEX.lastIndex = 0;
      while ((apiM = JS_API_ROUTE_REGEX.exec(res.bodyText)) !== null) {
        discoveredApiRoutes.add(apiM[1]);
      }

      if (depth < maxDepth) {
        for (const link of extractUrlsFromHtml(res.bodyText, res.finalUrl, origin)) {
          nextQueue.push({ url: link, depth: depth + 1 });
        }
      }
    }
    return nextQueue;
  };

  const queue: Array<{ url: string; depth: number }> = [];
  const homeU = new URL(baseRes.finalUrl);
  visitedKeys.add(canonicalCrawlKey(homeU));
  queue.push(...processPage(baseRes, 0));

  // Seed from robots.txt and sitemap.xml if not quick mode
  if (ctx.profile !== 'quick') {
    for (const metaPath of ['/robots.txt', '/sitemap.xml']) {
      if (ctx.isCancelled()) break;
      try {
        const metaRes = await ctx.httpFetch(`${origin}${metaPath}`, { followRedirects: false });
        if (metaRes.status === 200) {
          if (metaPath === '/robots.txt') {
            const pathMatches = metaRes.bodyText.matchAll(/(?:Disallow|Allow):\s*(\/[^\s#*]+)/gi);
            for (const pm of pathMatches) {
              const p = pm[1].trim();
              if (p && p !== '/' && isPathInScope(p, ctx.scopeIncludePaths, ctx.scopeExcludePaths)) {
                queue.push({ url: `${origin}${p}`, depth: 1 });
              }
            }
          } else {
            const locMatches = metaRes.bodyText.matchAll(/<loc>([^<]+)<\/loc>/gi);
            for (const lm of locMatches) {
              try {
                const u = new URL(lm[1].trim());
                if (u.origin === origin && !SKIPPED_BINARY_EXT.test(u.pathname)) {
                  queue.push({ url: u.toString(), depth: 1 });
                }
              } catch {
                // ignore
              }
            }
          }
        }
      } catch (err) {
        if (err instanceof RequestBudgetExceededError) {
          stoppedReason = 'request_budget';
          break;
        }
      }
    }
  }

  // BFS crawl loop with bounded concurrency
  while (queue.length > 0 && pages.length < maxUrls && stoppedReason === 'completed') {
    if (ctx.isCancelled()) {
      stoppedReason = 'cancelled';
      break;
    }

    const batch: Array<{ url: string; depth: number }> = [];
    while (queue.length > 0 && batch.length < concurrency && pages.length + batch.length < maxUrls) {
      const candidate = queue.shift()!;
      try {
        const u = new URL(candidate.url);
        if (u.origin !== origin) continue;
        if (!isPathInScope(u.pathname, ctx.scopeIncludePaths, ctx.scopeExcludePaths)) continue;
        const key = canonicalCrawlKey(u);
        if (visitedKeys.has(key)) continue;
        visitedKeys.add(key);
        batch.push(candidate);
      } catch {
        // ignore invalid url
      }
    }

    if (batch.length === 0) break;

    const results = await Promise.allSettled(
      batch.map(async (item) => {
        const pageRes = await ctx.httpFetch(item.url);
        return { pageRes, depth: item.depth };
      })
    );

    for (const r of results) {
      if (r.status === 'fulfilled') {
        const children = processPage(r.value.pageRes, r.value.depth);
        for (const ch of children) {
          if (pages.length + queue.length < maxUrls * 3) {
            queue.push(ch);
          }
        }
      } else if (r.reason instanceof RequestBudgetExceededError) {
        stoppedReason = 'request_budget';
      }
    }
  }

  if (pages.length >= maxUrls && queue.length > 0 && stoppedReason === 'completed') {
    stoppedReason = 'url_limit';
  }

  // Inspect same-origin JavaScript bundles for hidden API routes, DOM XSS sinks, and client-side secrets
  const jsResources: DiscoveredJsResource[] = [];
  const jsList = Array.from(scriptUrls).slice(0, ctx.profile === 'quick' ? 3 : 15);
  for (const sUrl of jsList) {
    if (ctx.isCancelled() || stoppedReason === 'request_budget') break;
    try {
      const jsPath = new URL(sUrl).pathname;
      if (!isPathInScope(jsPath, ctx.scopeIncludePaths, ctx.scopeExcludePaths)) continue;
      const jsRes = await ctx.httpFetch(sUrl);
      if (jsRes.status !== 200) continue;

      const apiHits = new Set<string>();
      let am: RegExpExecArray | null;
      JS_API_ROUTE_REGEX.lastIndex = 0;
      while ((am = JS_API_ROUTE_REGEX.exec(jsRes.bodyText)) !== null) {
        apiHits.add(am[1]);
        discoveredApiRoutes.add(am[1]);
        const routePath = am[1].split('?')[0];
        recordEndpoint({
          url: `${origin}${routePath}`,
          path: routePath,
          method: 'GET',
          source: 'crawl',
          authRequired: 'unknown',
          statusCode: null,
          contentType: 'application/json',
          parameters: [],
          notes: `Extracted from JS bundle ${jsPath}`,
        });
      }

      const domMatches: string[] = [];
      let dm: RegExpExecArray | null;
      DOM_XSS_JS_REGEX.lastIndex = 0;
      while ((dm = DOM_XSS_JS_REGEX.exec(jsRes.bodyText)) !== null && domMatches.length < 4) {
        domMatches.push(dm[0].slice(0, 180));
      }

      const secretMatches: string[] = [];
      let sm: RegExpExecArray | null;
      JS_SECRET_REGEX.lastIndex = 0;
      while ((sm = JS_SECRET_REGEX.exec(jsRes.bodyText)) !== null && secretMatches.length < 3) {
        secretMatches.push(sm[0].slice(0, 8) + '...[REDACTED]');
      }

      jsResources.push({
        url: sUrl,
        extractedApiRoutes: Array.from(apiHits),
        domXssMatches: domMatches,
        secretMatches,
      });
    } catch (err) {
      if (err instanceof RequestBudgetExceededError) {
        stoppedReason = 'request_budget';
        break;
      }
    }
  }

  const parameterizedUrls = Array.from(paramMap.values()).map((entry) => ({
    url: entry.url,
    path: entry.path,
    method: entry.method,
    params: Array.from(entry.params),
  }));

  const crawlResult: CrawlResult = {
    pages,
    forms: allForms,
    parameterizedUrls,
    jsResources,
    discoveredApiRoutes: Array.from(discoveredApiRoutes),
    loginPages: Array.from(loginPages),
    uploadEndpoints,
    endpoints: Array.from(endpointMap.values()),
    stats: {
      pagesCrawled: pages.length,
      maxDepthReached,
      formsFound: allForms.length,
      paramsFound: parameterizedUrls.reduce((acc, p) => acc + p.params.length, 0),
      jsFilesFetched: jsResources.length,
      apiRoutesFromJs: discoveredApiRoutes.size,
      stoppedReason,
    },
  };

  ctx.sharedState.crawlResult = crawlResult;
  return crawlResult;
}
