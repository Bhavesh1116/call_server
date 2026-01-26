/**
 * server.js - improved (patched)
 *
 * See original file in repo. Changes:
 * - Use Redis-backed rate limiter when REDIS_URL supplied
 * - Fix libphonenumber-js import + validation logic
 * - Harden error handler to avoid leaking stack unless DEBUG=true
 * - Better graceful shutdown (await server.close, close redis client)
 * - Handle timed out requests and headers-sent in error handler
 * - Small logging / env clarifications
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
const timeout = require('connect-timeout');

const { body, validationResult } = require('express-validator');

let Redis;
let RedisStore;
let redisClient;

try {
  // only attempt to load these if REDIS_URL is provided (optional dependency)
  if (process.env.REDIS_URL) {
    Redis = require('ioredis');
    RedisStore = require('rate-limit-redis');
    redisClient = new Redis(process.env.REDIS_URL);
    // handle redis client events
    redisClient.on('error', (err) => {
      console.error('Redis client error', err);
    });
  }
} catch (e) {
  console.warn('Redis modules not available; falling back to in-memory rate limiter. Install ioredis and rate-limit-redis for distributed limiting.');
  Redis = null;
  RedisStore = null;
  redisClient = null;
}

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
  // include request id in logs
  genReqId: (req) => req.id || req.headers['x-request-id'] || undefined,
});
app.use(logger);

// Add a request id to allow tracing
app.use(requestId);

// Compression for responses
app.use(compression());

// Basic security headers. For JSON APIs it's often safe to disable CSP or supply a minimal one.
app.use(helmet({
  contentSecurityPolicy: false, // set CSP if serving HTML
  referrerPolicy: { policy: "no-referrer" },
  crossOriginResourcePolicy: false
}));

// JSON body limits and urlencoded parsing
const jsonLimit = process.env.JSON_LIMIT || '1mb';
app.use(express.json({ limit: jsonLimit }));
app.use(express.urlencoded({ extended: false }));

// Timeout middleware (set early so long-running requests are aborted)
const requestTimeout = process.env.REQUEST_TIMEOUT || '15s';
app.use(timeout(requestTimeout));

// Simple middleware to catch timeouts in all routes
function haltOnTimedout(req, res, next) {
  if (!req.timedout) return next();
  // if timed out, log and do not continue
  req.log && req.log.warn({ reqId: req.id || req.headers['x-request-id'] }, 'Request already timed out');
  // Try to end response if possible
  try { if (!res.headersSent) res.status(503).json({ error: 'timeout' }); } catch (e) { /* ignore */ }
}

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

// CORS: support a comma-separated list in env, or single origin, fallback to allow-all (explicit)
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
      // If no list defined, allow all origins by default for convenience, but log warning for prod
      if (process.env.NODE_ENV === 'production') {
        console.warn('CORS_ORIGINS not set; defaulting to allow-all in production is not recommended!');
      }
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS not allowed'));
  },
  optionsSuccessStatus: 204,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
};
app.use(cors(corsOptions));

if (process.env.NODE_ENV !== 'production') {
  const morgan = require('morgan');
  app.use(morgan('dev'));
}

// Rate limiting: use Redis store if available (recommended for production)
const rateLimiterOptions = {
  windowMs: 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX || '60', 10),
  standardHeaders: true,
  legacyHeaders: false,
};

if (redisClient && RedisStore) {
  rateLimiterOptions.store = new RedisStore({
    sendCommand: (...args) => redisClient.call(...args) // rate-limit-redis v2 expects sendCommand or client depending on versions
  });
  app.use(rateLimit(rateLimiterOptions));
} else {
  app.use(rateLimit(rateLimiterOptions));
}

// Example: safe optional phone number validation import
let parsePhoneNumberFromString = null;
let hasPhoneLib = false;
try {
  const lib = require('libphonenumber-js');
  // libphonenumber-js exports parsePhoneNumberFromString
  parsePhoneNumberFromString = lib.parsePhoneNumberFromString || lib.parsePhoneNumber;
  hasPhoneLib = typeof parsePhoneNumberFromString === 'function';
} catch (e) {
  // library not installed - phone validation will be skipped
  parsePhoneNumberFromString = () => null;
  hasPhoneLib = false;
  if (process.env.NODE_ENV !== 'production') {
    console.warn('libphonenumber-js not installed — phone format validation disabled. Install libphonenumber-js to enable stricter validation.');
  }
}

// Example route (move routes to their own module in larger apps)
app.post('/api/v1/call',
  body('phone').isString().notEmpty().withMessage('phone is required'),
  body('message').isString().isLength({ min: 1 }).withMessage('message is required'),
  async (req, res, next) => {
    try {
      if (req.timedout) return next(); // bail if already timed out

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'validation_error', details: errors.array() });
      }

      const { phone, message } = req.body;

      // optional: validate phone number shape if lib available
      const phoneNumber = hasPhoneLib ? parsePhoneNumberFromString(phone || '') : null;
      if (hasPhoneLib && (!phoneNumber || !phoneNumber.isValid())) {
        return res.status(400).json({ error: 'validation_error', details: [{ msg: 'phone is invalid', param: 'phone' }] });
      }

      // Example: replace with your actual call service (async)
      // await callService.send({ to: phoneNumber ? phoneNumber.number : phone, message });
      return res.json({ ok: true, to: phone, message });
    } catch (err) {
      return next(err);
    }
  },
  haltOnTimedout
);

// 404 handler - keep last among routes
app.use((req, res) => {
  if (req.timedout) return; // don't respond if already timed out
  res.status(404).json({ error: 'not_found', path: req.originalUrl });
});

// central error handler
app.use((err, req, res, next) => {
  // If headers already sent, delegate to default handler
  if (res.headersSent) {
    return next(err);
  }

  // Respect timeout - do not try to send after timeout
  if (req.timedout) {
    req.log && req.log.warn('Request timed out before error handler');
    return;
  }

  // Log error with request id
  const reqId = req.id || req.headers['x-request-id'] || '-';
  if (req.log) {
    req.log.error({ err, reqId }, err && err.message ? err.message : 'Unhandled error');
  } else {
    console.error('Error', { reqId, err });
  }

  const status = err && Number.isInteger(err.status) ? err.status : 500;
  const isProd = process.env.NODE_ENV === 'production';
  const debugAllowed = process.env.DEBUG === 'true' && !isProd; // only show stack if DEBUG=true and not production

  res.status(status).json({
    error: isProd ? 'internal_error' : (err.message || 'Internal Server Error'),
    code: status,
    requestId: reqId,
    details: debugAllowed ? (err.details || err.stack) : undefined
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

function closeServerGracefully(timeoutMs = parseInt(process.env.SHUTDOWN_TIMEOUT_MS || '30000', 10)) {
  return new Promise((resolve) => {
    let closed = false;
    const t = setTimeout(() => {
      if (!closed) {
        console.error('Forcing shutdown after timeout.');
        closeAllConnections();
        closed = true;
        resolve();
      }
    }, timeoutMs);

    server.close((err) => {
      if (err) {
        console.error('Error closing server', err);
      } else {
        console.log('Stopped accepting new connections.');
      }
      if (redisClient && typeof redisClient.quit === 'function') {
        try {
          redisClient.quit().catch(e => console.error('Error closing redis client', e));
        } catch (e) {
          // ignore
        }
      }
      closed = true;
      clearTimeout(t);
      resolve();
    });
  });
}

async function shutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  try {
    await closeServerGracefully();
    console.log('Closed out remaining connections.');
    process.exit(0);
  } catch (e) {
    console.error('Error during shutdown cleanup', e);
    process.exit(1);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// catch unhandled errors to try to log and exit (allow process manager to restart)
process.on('unhandledRejection', async (reason) => {
  console.error('Unhandled Rejection at:', reason);
  // try graceful shutdown then exit
  try {
    await closeServerGracefully(5000);
  } catch (e) {
    console.error('Error during shutdown after unhandledRejection', e);
  } finally {
    process.exit(1);
  }
});
process.on('uncaughtException', async (err) => {
  console.error('Uncaught Exception thrown:', err);
  // attempt graceful shutdown then exit
  try {
    await closeServerGracefully(5000);
  } catch (e) {
    console.error('Error during shutdown after uncaughtException', e);
  } finally {
    process.exit(1);
  }
});

module.exports = app;
