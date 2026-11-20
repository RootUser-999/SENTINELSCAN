import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { getDb } from './server/db/database.ts';
import { syncScannerModuleRegistry } from './server/scanner/engine.ts';
import authRoutes from './server/routes/auth.ts';
import assetRoutes from './server/routes/assets.ts';
import scanRoutes from './server/routes/scans.ts';
import findingRoutes from './server/routes/findings.ts';
import complianceReportRoutes from './server/routes/complianceReports.ts';
import vaultAuditRoutes from './server/routes/vaultAudit.ts';

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Initialize SQLite database & scanner plugin registry
  getDb();
  syncScannerModuleRegistry();

  app.set('trust proxy', 1);
  app.use(express.json({ limit: '2mb' }));

  // Defensive baseline security headers (iframe-compatible for preview)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  // Versioned REST API v1
  app.get('/api/v1/health', (_req, res) => {
    res.json({ status: 'ok', service: 'SentinelScan', timestamp: new Date().toISOString() });
  });

  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/assets', assetRoutes);
  app.use('/api/v1/scans', scanRoutes);
  app.use('/api/v1/findings', findingRoutes);
  app.use('/api/v1', complianceReportRoutes);
  app.use('/api/v1', vaultAuditRoutes);

  // Explicit 404 for unknown API routes
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelScan running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start SentinelScan server:', err);
  process.exit(1);
});
