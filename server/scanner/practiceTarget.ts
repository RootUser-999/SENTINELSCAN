import type { HttpResponseSnapshot } from './types.ts';

/**
 * Isolated, intentionally misconfigured in-memory practice target
 * (`https://practice-shop.sentinel-lab.internal`).
 * Never opens network sockets and never touches localhost or production systems.
 */
export const PRACTICE_OPENAPI_SAMPLE = JSON.stringify(
  {
    openapi: '3.0.3',
    info: { title: 'Practice Shop API', version: '1.4.0-lab' },
    paths: {
      '/api/v1/users': {
        get: {
          summary: 'List registered customer profiles',
          responses: { '200': { description: 'OK' } },
        },
      },
      '/api/v1/orders/{orderId}': {
        get: {
          summary: 'Retrieve order details by ID',
          parameters: [{ name: 'orderId', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'OK' } },
        },
      },
      '/api/v1/admin/settings': {
        put: {
          summary: 'Update store configuration',
          security: [{ bearerAuth: [] }],
          responses: { '200': { description: 'Updated' } },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
  },
  null,
  2
);

export const PRACTICE_PACKAGE_JSON_SAMPLE = JSON.stringify(
  {
    name: 'practice-shop-web',
    version: '1.2.0',
    dependencies: {
      lodash: '4.17.20',
      express: '4.18.2',
      jsonwebtoken: '8.5.1',
      minimist: '1.2.5',
    },
  },
  null,
  2
);

export const PRACTICE_SAST_SAMPLE = `// Practice Shop Checkout Handler (Authorized Review Sample)
import crypto from 'node:crypto';

const LEGACY_SIGNING_SECRET = "sk_live_practice_hardcoded_demo_key_98765";

export function hashLegacyToken(raw: string) {
  return crypto.createHash('md5').update(raw).digest('hex');
}

export async function findOrderByCustomer(db: any, customerEmail: string) {
  const query = "SELECT * FROM orders WHERE email = '" + customerEmail + "'";
  return db.query(query);
}

export function renderReceiptBanner(noteHtml: string) {
  document.getElementById('banner')!.innerHTML = noteHtml;
}
`;

export function simulatePracticeHttp(
  rawUrl: string,
  method = 'GET',
  requestHeaders: Record<string, string> = {}
): HttpResponseSnapshot {
  const parsed = new URL(rawUrl);
  const path = parsed.pathname;
  const upperMethod = method.toUpperCase();
  const origin = requestHeaders['Origin'] || requestHeaders['origin'] || '';
  const hasAuth = Boolean(requestHeaders['Authorization'] || requestHeaders['authorization'] || requestHeaders['Cookie']);

  const baseHeaders: Record<string, string> = {
    server: 'nginx/1.18.0 (Ubuntu)',
    'x-powered-by': 'Express 4.18.2',
    'content-type': 'text/html; charset=utf-8',
    'x-content-type-options': 'nosniff',
    'cache-control': 'public, max-age=3600',
    // Intentionally weak CSP and missing HSTS / Permissions-Policy / COOP for real detection
    'content-security-policy': "default-src 'self' 'unsafe-inline' http://cdn.practice-shop.sentinel-lab.internal",
  };

  if (origin) {
    // Intentionally permissive CORS reflection for assessment testing
    baseHeaders['access-control-allow-origin'] = origin;
    baseHeaders['access-control-allow-credentials'] = 'true';
  }

  // HTTP -> HTTPS check
  if (parsed.protocol === 'http:') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: '<html><body>Practice Shop served over plain HTTP without TLS redirect</body></html>',
      redirectChain: [],
      durationMs: 14,
    };
  }

  if (upperMethod === 'OPTIONS') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 204,
      headers: {
        ...baseHeaders,
        allow: 'GET, POST, PUT, DELETE, TRACE, OPTIONS',
      },
      setCookies: [],
      bodyText: '',
      redirectChain: [],
      durationMs: 9,
    };
  }

  if (path === '/' || path === '') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [
        'session_id=prac_83920192; Path=/; SameSite=Lax', // Missing HttpOnly and Secure
      ],
      bodyText: `<!doctype html>
<html>
  <head><title>Practice Shop Lab</title></head>
  <body>
    <header><h1>Practice Shop</h1></header>
    <nav>
      <a href="/login">Sign In</a>
      <a href="/catalog">Catalog</a>
      <a href="/api/v1/users">API Users</a>
    </nav>
    <script src="http://cdn.practice-shop.sentinel-lab.internal/legacy.js"></script>
    <script>
      const q = new URLSearchParams(location.search).get('q');
      if (q) document.getElementById('search-echo').innerHTML = q;
    </script>
    <form action="/login" method="POST">
      <input type="email" name="email" />
      <input type="password" name="password" />
      <button type="submit">Login</button>
    </form>
  </body>
</html>`,
      redirectChain: [],
      durationMs: 18,
    };
  }

  if (path === '/login') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'cache-control': 'no-store' },
      setCookies: ['session_id=prac_login_991; Path=/'],
      bodyText: '<form action="/login" method="POST"><input name="email"/><input type="password" name="password"/></form>',
      redirectChain: [],
      durationMs: 12,
    };
  }

  if (path === '/robots.txt') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'text/plain' },
      setCookies: [],
      bodyText: 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n',
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/.well-known/security.txt') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 404,
      headers: { ...baseHeaders, 'content-type': 'text/plain' },
      setCookies: [],
      bodyText: 'Not Found',
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/.env') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'text/plain' },
      setCookies: [],
      bodyText: 'APP_ENV=staging\nDB_HOST=10.0.4.12\nAPP_DEBUG=true\n# Practice Lab Simulated Exposure',
      redirectChain: [],
      durationMs: 7,
    };
  }

  if (path === '/admin/' || path === '/admin') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: '<html><title>Index of /admin/</title><body><h1>Index of /admin/</h1><a href="config.bak">config.bak</a></body></html>',
      redirectChain: [],
      durationMs: 10,
    };
  }

  if (path === '/openapi.json' || path === '/swagger.json') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: PRACTICE_OPENAPI_SAMPLE,
      redirectChain: [],
      durationMs: 11,
    };
  }

  if (path === '/graphql') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ data: { __schema: { types: [{ name: 'User' }, { name: 'Order' }] } } }),
      redirectChain: [],
      durationMs: 11,
    };
  }

  if (path === '/api/v1/users') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ users: [{ id: 101, role: 'customer', email: 'alice@example.test' }] }),
      redirectChain: [],
      durationMs: 9,
    };
  }

  if (path === '/api/v1/admin/settings') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: hasAuth ? 200 : 401,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: hasAuth ? JSON.stringify({ maintenanceMode: false }) : JSON.stringify({ error: 'Unauthorized' }),
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/catalog') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: '<html><body><h2>Catalog</h2><p>SQLSTATE[42000]: Syntax error warning indicator in debug template</p></body></html>',
      redirectChain: [],
      durationMs: 9,
    };
  }

  return {
    url: rawUrl,
    finalUrl: rawUrl,
    status: 404,
    headers: baseHeaders,
    setCookies: [],
    bodyText: 'Not Found',
    redirectChain: [],
    durationMs: 5,
  };
}
