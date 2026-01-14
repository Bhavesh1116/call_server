/**
 * server.js - improved
 *
 * - dotenv for environment config
 * - helmet for security headers (adjust CSP for API)
 * - cors with env-configurable allowed origins
 * - request id for traceability
 * - pino-http for structured logs (morgan preserved for simple usage)
 * - express-rate-limit (in-memory by default) with a note for Redis-backed store in prod
 * - express-async-errors to let thrown async errors hit the central handler
 * - centralized error handler with consistent error shape
 * - graceful shutdown handling for DB/queues
 * - timeout + compression + basic metrics endpoint
 *
 * Notes:
 * - Install suggested deps for full behavior: express, helmet, cors, pino-http, express-request-id,
 *   express-rate-limit, express-validator, dotenv, compression, express-async-errors, libphonenumber-js
 * - Replace placeholders (call sending, DB disconnect) with your app's implementations.
 */

require('dotenv').config();
require('express-async-errors'); // allow async route errors to bubble to error handler

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const pinoHttp = require('pino-http');
const requestId = require('express-request-id')();
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
// const RedisStore = require('rate-limit-redis'); // uncomment for distributed rate limiting
// const Redis = require('ioredis');
const timeout = require('connect-timeout');

const app = express();

// Basic env validation (fail fast for critical vars)
const requiredEnvs = ['NODE_ENV'];
requiredEnvs.forEach((k) => {
  if (!process.env[k]) {
    console.warn(`Warning: ${k} not set`);
  }
});

// If behind a proxy (k8s / nginx / cloud), enable trust proxy
if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', true);
}

// Structured logging
const logger = pinoHttp({
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
  customLogLevel: (res, err) => {
    if (res.statusCode >= 500 || err) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
});
app.use(logger);

// Add a request id to allow tracing
app.use(requestId);

// Compression for responses
app.use(compression());

// Basic security headers. For JSON APIs it's often safe to disable CSP or supply a minimal one.
app.use(helmet({
  contentSecurityPolicy: false, // APIs usually don't serve HTML; set a CSP if you do
  referrerPolicy: { policy: "no-referrer" }
}));

// JSON body limits and urlencoded parsing
const jsonLimit = process.env.JSON_LIMIT || '1mb';
app.use(express.json({ limit: jsonLimit }));
app.use(express.urlencoded({ extended: false }));

// Timeout middleware to avoid hanging requests (adjust as needed)
const requestTimeout = process.env.REQUEST_TIMEOUT || '15s'; // connect-timeout needs ms or '15s'
app.use(timeout(requestTimeout));

// Simple health + readiness + metrics endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    node_env: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

// Minimal /metrics endpoint for Prometheus scraping — extend with client metrics lib
app.get('/metrics', (req, res) => {
  // return real prometheus metrics in production
  res.type('text/plain').send('# metrics placeholder\n');
});

// CORS: support a comma-separated list in env, or single origin, fallback to deny (recommended)
const rawOrigins = process.env.CORS_ORIGINS || '';
let allowedOrigins = [];
if (rawOrigins) {
  allowedOrigins = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);
}
const corsOptions = {
  origin: (origin, callback) => {
    // allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) {
      // If no list defined, allow same-origin or deny depending on env. Here we allow all by default for convenience.
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS not allowed'));
  },
  optionsSuccessStatus: 204,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
};
app.use(cors(corsOptions));

// Rate limiting: keep in-memory limiter for single instance; use Redis in clustered/prod env
const rateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX || '60', 10),
  standardHeaders: true,
  legacyHeaders: false,
  // store: new RedisStore({ client: new Redis(process.env.REDIS_URL) }), // uncomment + install for redis
});
app.use(rateLimiter);

// Basic request logger for dev: still useful
if (process.env.NODE_ENV !== 'production') {
  // Keep morgan if you like human-readable logs in dev; or omit
  const morgan = require('morgan');
  app.use(morgan('dev'));
}

// Example validation helper - validate phone format using libphonenumber-js
const { parsePhoneNumberFromString } = (() => {
  try {
    return require('libphonenumber-js');
  } catch (e) {
    return { parsePhoneNumberFromString: () => null };
  }
})();

// Simple middleware to catch timeouts
function haltOnTimedout(req, res, next) {
  if (!req.timedout) next();
}

// Example route (move routes to their own module in larger apps)
app.post('/api/v1/call',
  body('phone').isString().notEmpty().withMessage('phone is required'),
  body('message').isString().isLength({ min: 1 }).withMessage('message is required'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'validation_error', details: errors.array() });
      }

      const { phone, message } = req.body;

      // optional: validate phone number shape
      const phoneNumber = parsePhoneNumberFromString(phone || '');
      if (parsePhoneNumberFromString && (!phoneNumber || !phoneNumber.isValid())) {
        return res.status(400).json({ error: 'validation_error', details: [{ msg: 'phone is invalid', param: 'phone' }] });
      }

      // Example: replace with your actual call service (async)
      // await callService.send({ to: phoneNumber ? phoneNumber.number : phone, message });
      // For demo, return a safe response
      return res.json({ ok: true, to: phone, message });
    } catch (err) {
      return next(err);
    }
  },
  haltOnTimedout
);

// 404 handler - keep last among routes
app.use((req, res) => {
  res.status(404).json({ error: 'not_found', path: req.originalUrl });
});

// central error handler
app.use((err, req, res, next) => {
  // Respect timeout - do not try to send after timeout
  if (req.timedout) {
    req.log && req.log.warn('Request timed out');
    return;
  }

  // Log error with request id
  const reqId = req.id || req.headers['x-request-id'] || '-';
  // pino-http attaches logger to req.log
  if (req.log) {
    req.log.error({ err, reqId }, err && err.message ? err.message : 'Unhandled error');
  } else {
    console.error(err && err.stack ? err.stack : err);
  }

  const status = err.status && Number.isInteger(err.status) ? err.status : 500;
  const isProd = process.env.NODE_ENV === 'production';

  res.status(status).json({
    error: isProd ? 'internal_error' : (err.message || 'Internal Server Error'),
    code: status,
    requestId: reqId,
    // in non-prod include details (don't leak in prod)
    details: isProd ? undefined : (err.details || err.stack)
  });
});

// Graceful shutdown helpers
const port = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

// track open connections if you need to force close
const connections = new Set();
server.on('connection', (conn) => {
  connections.add(conn);
  conn.on('close', () => connections.delete(conn));
});

function closeAllConnections() {
  for (const conn of connections) {
    try { conn.destroy(); } catch (e) { /* ignore */ }
  }
}

async function shutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);

  // stop accepting new connections
  server.close(async (err) => {
    if (err) {
      console.error('Error closing server', err);
      process.exit(1);
    }

    // close DB / queues / external clients here
    try {
      // await db.shutdown();
      // await queue.shutdown();
      console.log('Closed out remaining connections.');
      process.exit(0);
    } catch (e) {
      console.error('Error during shutdown cleanup', e);
      process.exit(1);
    }
  });

  // Force close after 30s
  setTimeout(() => {
    console.error('Forcing shutdown after timeout.');
    closeAllConnections();
    process.exit(1);
  }, parseInt(process.env.SHUTDOWN_TIMEOUT_MS || '30000', 10));
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// catch unhandled errors to try to log and exit (allow process manager to restart)
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection at:', reason);
  // optionally capture with Sentry / log aggregator
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
  // It's often safest to exit after uncaughtException
  process.exit(1);
});

module.exports = app;
