import type { HttpResponseSnapshot } from './types.ts';

/**
 * Isolated, intentionally misconfigured in-memory practice target
 * (`https://practice-shop.sentinel-lab.internal`).
 * Never opens network sockets and never touches localhost or production systems.
 * Includes BOTH intentionally vulnerable routes AND hardened safe routes
 * so tests can verify true positives AND zero false positives.
 */
export const PRACTICE_OPENAPI_SAMPLE = JSON.stringify(
  {
    openapi: '3.0.3',
    info: { title: 'Practice Shop API', version: '1.5.0-lab' },
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
      '/api/v1/admin/audit-export': {
        get: {
          summary: 'Export internal audit ledger',
          security: [{ bearerAuth: [] }],
          responses: { '200': { description: 'OK' } },
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

function htmlEscape(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function simulatePracticeHttp(
  rawUrl: string,
  method = 'GET',
  requestHeaders: Record<string, string> = {},
  body = ''
): HttpResponseSnapshot {
  const parsed = new URL(rawUrl);
  const path = parsed.pathname;
  const upperMethod = method.toUpperCase();
  const origin = requestHeaders['Origin'] || requestHeaders['origin'] || '';
  const authHeader = requestHeaders['Authorization'] || requestHeaders['authorization'] || '';
  const cookieHeader = requestHeaders['Cookie'] || requestHeaders['cookie'] || '';
  const hasAnyAuth = Boolean(authHeader || cookieHeader);
  const isAdminAuth =
    /admin/i.test(authHeader) || /role=admin|prac_admin_session/i.test(cookieHeader);
  const isCustomerAuth = hasAnyAuth && !isAdminAuth;

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
      <a href="/catalog?q=laptop">Catalog</a>
      <a href="/search?filter=featured">Product Search</a>
      <a href="/safe-search?q=laptop">Safe Search</a>
      <a href="/redirect?next=/catalog">Partner Redirect</a>
      <a href="/safe-redirect?next=/catalog">Safe Redirect</a>
      <a href="/download?file=guide.pdf">User Guide</a>
      <a href="/preview?url=https://practice-shop.sentinel-lab.internal/catalog">Link Preview</a>
      <a href="/upload">Upload Avatar</a>
      <a href="/api/v1/orders/1001">My Order #1001</a>
      <a href="/api/v1/users">API Users</a>
    </nav>
    <script src="http://cdn.practice-shop.sentinel-lab.internal/legacy.js"></script>
    <script src="/app.js"></script>
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

  if (path === '/app.js') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/javascript; charset=utf-8' },
      setCookies: [],
      bodyText: `
// Practice Shop Frontend Bundle
async function loadOrder(id) {
  return fetch('/api/v1/orders/' + id);
}
async function syncProfile() {
  return fetch('/api/v1/profile');
}
async function sendXml(xmlBody) {
  return fetch('/api/v1/xml/parse', { method: 'POST', body: xmlBody });
}
function mountPromo() {
  const promo = new URLSearchParams(window.location.search).get('promo');
  if (promo) {
    document.querySelector('#promo').innerHTML = promo;
  }
}
`,
      redirectChain: [],
      durationMs: 7,
    };
  }

  if (path === '/sitemap.xml') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/xml' },
      setCookies: [],
      bodyText: `<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://practice-shop.sentinel-lab.internal/catalog?q=shoes</loc></url>
  <url><loc>https://practice-shop.sentinel-lab.internal/upload</loc></url>
  <url><loc>https://practice-shop.sentinel-lab.internal/api/v1/orders/1001</loc></url>
</urlset>`,
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/login') {
    if (upperMethod === 'POST') {
      const isAdminCred = /admin/i.test(body);
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: { ...baseHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' },
        setCookies: [
          isAdminCred
            ? 'prac_admin_session=adm_tok_9021; Path=/; HttpOnly'
            : 'prac_user_session=usr_tok_4412; Path=/',
        ],
        bodyText: JSON.stringify({
          authenticated: true,
          role: isAdminCred ? 'administrator' : 'customer',
          // Simulated unsigned/weak JWT in response for JWT analyzer
          token:
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDAxIiwicm9sZSI6ImN1c3RvbWVyIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLnRlc3QifQ.',
        }),
        redirectChain: [],
        durationMs: 12,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'cache-control': 'no-store' },
      setCookies: ['session_id=prac_login_991; Path=/'],
      bodyText:
        '<html><body><h1>Sign In</h1><form action="/login" method="POST"><input name="email"/><input type="password" name="password"/></form></body></html>',
      redirectChain: [],
      durationMs: 12,
    };
  }

  if (path === '/catalog') {
    const q = parsed.searchParams.get('q') || '';
    if (/['"]/.test(q) && !/OR\s+'1'='1'|AND\s+'1'='2'/i.test(q)) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 500,
        headers: baseHeaders,
        setCookies: [],
        bodyText: `<html><body><h2>Catalog</h2><p>SQLSTATE[42000]: You have an error in your SQL syntax near '${q}'</p></body></html>`,
        redirectChain: [],
        durationMs: 11,
      };
    }
    if (/OR\s+'1'='1'/i.test(q)) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: baseHeaders,
        setCookies: [],
        bodyText:
          '<html><body><h2>Catalog</h2><ul><li>Laptop Pro ($1299)</li><li>Mechanical Keyboard ($149)</li><li>Monitor 4K ($499)</li><li>USB-C Dock ($89)</li></ul></body></html>',
        redirectChain: [],
        durationMs: 10,
      };
    }
    if (/AND\s+'1'='2'/i.test(q)) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: baseHeaders,
        setCookies: [],
        bodyText: '<html><body><h2>Catalog</h2><p>0 products matched.</p></body></html>',
        redirectChain: [],
        durationMs: 10,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: `<html><body><h2>Catalog</h2><div class="results">Results for: ${q}</div><ul><li>Laptop Pro ($1299)</li><li>Mechanical Keyboard ($149)</li></ul></body></html>`,
      redirectChain: [],
      durationMs: 9,
    };
  }

  if (path === '/safe-search') {
    const q = parsed.searchParams.get('q') || '';
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: `<html><body><h2>Safe Search</h2><div>Query: ${htmlEscape(q)}</div></body></html>`,
      redirectChain: [],
      durationMs: 7,
    };
  }

  if (path === '/search') {
    const neFilter = parsed.searchParams.get('filter[$ne]');
    if (neFilter !== null) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({
          warning: 'MongoError: $ne operator accepted in unvalidated query filter',
          items: [
            { sku: 'PRD-1', name: 'Laptop Pro', hidden: false },
            { sku: 'PRD-99', name: 'Internal Staff Discount SKU', hidden: true },
          ],
        }),
        redirectChain: [],
        durationMs: 9,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ items: [{ sku: 'PRD-1', name: 'Laptop Pro' }] }),
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/redirect') {
    const next = parsed.searchParams.get('next') || '/';
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 302,
      headers: { ...baseHeaders, location: next },
      setCookies: [],
      bodyText: `Redirecting to ${next}`,
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/safe-redirect') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 302,
      headers: { ...baseHeaders, location: '/catalog' },
      setCookies: [],
      bodyText: 'Redirecting safely to /catalog',
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/download') {
    const file = parsed.searchParams.get('file') || 'guide.pdf';
    if (file.includes('..')) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: { ...baseHeaders, 'content-type': 'text/plain' },
        setCookies: [],
        bodyText: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n',
        redirectChain: [],
        durationMs: 8,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'text/plain' },
      setCookies: [],
      bodyText: 'Practice Shop User Guide v1.5',
      redirectChain: [],
      durationMs: 6,
    };
  }

  if (path === '/preview') {
    const target = parsed.searchParams.get('url') || '';
    if (/sentinel-invalid\.example/i.test(target)) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 502,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({
          error: `Server-side HTTP client error: getaddrinfo ENOTFOUND ${new URL(target).hostname}`,
        }),
        redirectChain: [],
        durationMs: 12,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: '<html><body>Preview loaded</body></html>',
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/api/v1/xml/parse' && upperMethod === 'POST') {
    const pingMatch = body.match(/<sentinelPing>([^<]+)<\/sentinelPing>/i);
    if (pingMatch) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 200,
        headers: { ...baseHeaders, 'content-type': 'application/xml' },
        setCookies: [],
        bodyText: `<xmlResult><echo>${pingMatch[1]}</echo><parser>libxml2</parser></xmlResult>`,
        redirectChain: [],
        durationMs: 9,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 400,
      headers: { ...baseHeaders, 'content-type': 'application/xml' },
      setCookies: [],
      bodyText: '<error>XMLSyntaxError: malformed XML payload</error>',
      redirectChain: [],
      durationMs: 7,
    };
  }

  if (path === '/upload') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: `<!doctype html><html><body><h1>Upload Avatar</h1>
        <form action="/upload" method="POST" enctype="multipart/form-data">
          <input type="file" name="avatar" />
          <button type="submit">Upload</button>
        </form>
        <a href="/uploads/">View uploaded files</a>
      </body></html>`,
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/uploads/' || path === '/uploads') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      bodyText: '<html><title>Index of /uploads/</title><body><h1>Index of /uploads/</h1><a href="invoice.pdf">invoice.pdf</a></body></html>',
      redirectChain: [],
      durationMs: 7,
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
    if (body.includes('__schema')) {
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
    if (body.includes('__typoSentinel')) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 400,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({
          errors: [{ message: 'Cannot query field "__typoSentinel" on type "Query". Did you mean "users" or "orders"?' }],
        }),
        redirectChain: [],
        durationMs: 8,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ data: [{ data: { ok: true } }, { data: { ok: true } }] }),
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/api/v1/users') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({
        users: [{ id: 101, role: 'customer', email: 'alice@example.test', passwordHash: '$2b$10$demoHashValue' }],
        sampleJwt: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDEiLCJyb2xlIjoiY3VzdG9tZXIifQ.',
      }),
      redirectChain: [],
      durationMs: 9,
    };
  }

  if (path === '/api/v1/orders/1001' || path === '/api/v1/orders/1002') {
    const orderId = path.endsWith('1002') ? '1002' : '1001';
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({
        orderId,
        owner: orderId === '1002' ? 'bob@example.test' : 'alice@example.test',
        totalUsd: orderId === '1002' ? 842.5 : 129.0,
      }),
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/api/v1/profile') {
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: hasAnyAuth ? 200 : 401,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: hasAnyAuth
        ? JSON.stringify({ email: isAdminAuth ? 'admin@practice.test' : 'alice@example.test' })
        : JSON.stringify({ error: 'Unauthorized' }),
      redirectChain: [],
      durationMs: 7,
    };
  }

  if (path === '/api/v1/admin/settings') {
    if (!hasAnyAuth) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 401,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({ error: 'Unauthorized' }),
        redirectChain: [],
        durationMs: 8,
      };
    }
    if (isCustomerAuth) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 403,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({ error: 'Forbidden: administrator role required' }),
        redirectChain: [],
        durationMs: 8,
      };
    }
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ maintenanceMode: false, adminScope: true }),
      redirectChain: [],
      durationMs: 8,
    };
  }

  if (path === '/api/v1/admin/audit-export') {
    if (!hasAnyAuth) {
      return {
        url: rawUrl,
        finalUrl: rawUrl,
        status: 401,
        headers: { ...baseHeaders, 'content-type': 'application/json' },
        setCookies: [],
        bodyText: JSON.stringify({ error: 'Unauthorized' }),
        redirectChain: [],
        durationMs: 8,
      };
    }
    // Intentionally missing role check: even customer role gets HTTP 200 -> real BFLA detection!
    return {
      url: rawUrl,
      finalUrl: rawUrl,
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'application/json' },
      setCookies: [],
      bodyText: JSON.stringify({ auditRows: [{ event: 'admin.rotateKey', actor: 'root@practice.test' }] }),
      redirectChain: [],
      durationMs: 8,
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
