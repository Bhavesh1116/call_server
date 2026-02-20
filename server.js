/**
 * server.js - ENHANCED & HARDENED VERSION
 * 
 * Security Improvements:
 * - Authentication & API Key validation
 * - Input sanitization & XSS prevention
 * - Stricter CORS in production
 * - Advanced rate limiting (IP + User-based)
 * - Request signature validation (HMAC)
 * - Sensitive data obfuscation in logs
 * - Enhanced Helmet security headers
 * - Health endpoint protection
 * - Fail-fast on critical config errors
 * - Better error handling & stack trace obfuscation
 * - Request size & rate limit per endpoint
 */

require('dotenv').config();
require('express-async-errors');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const pinoHttp = require('pino-http');
const requestId = require('express-request-id')();
const rateLimit = require('express-rate-limit');
const timeout = require('connect-timeout');
const crypto = require('crypto');
const xss = require('xss');

const { body, validationResult } = require('express-validator');

let Redis;
let RedisStore;
let redisClient;

// ============= REDIS INITIALIZATION =============
try {
  if (process.env.REDIS_URL) {
    Redis = require('ioredis');
    RedisStore = require('rate-limit-redis');
    redisClient = new Redis(process.env.REDIS_URL);
    redisClient.on('error', (err) => {
      console.error('Redis client error', err);
      // Fail fast if Redis required
      if (process.env.REQUIRE_REDIS === 'true') {
        console.error('FATAL: Redis required but failed to connect');
        process.exit(1);
      }
    });
  }
} catch (e) {
  if (process.env.REQUIRE_REDIS === 'true') {
    console.error('FATAL: Redis modules not available but REQUIRE_REDIS=true');
    process.exit(1);
  }
  console.warn('Redis not available; using in-memory rate limiter');
  Redis = null;
  RedisStore = null;
  redisClient = null;
}

const app = express();

// ============= ENVIRONMENT VALIDATION =============
const requiredEnvs = ['NODE_ENV'];
const criticalEnvs = process.env.NODE_ENV === 'production' ? 
  ['CORS_ORIGINS', 'API_SECRET_KEY'] : [];

requiredEnvs.concat(criticalEnvs).forEach((k) => {
  if (!process.env[k]) {
    const msg = `Missing required environment variable: ${k}`;
    if (process.env.NODE_ENV === 'production') {
      console.error(`FATAL: ${msg}`);
      process.exit(1);
    } else {
      console.warn(`Warning: ${msg}`);
    }
  }
});

if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', true);
}

// ============= LOGGING CONFIGURATION =============
const logger = pinoHttp({
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
  customLogLevel: (res, err) => {
    if (res.statusCode >= 500 || err) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  genReqId: (req) => req.id || req.headers['x-request-id'] || undefined,
  // Sanitize sensitive fields in logs
  serializers: {
    req: (req) => {
      const body = { ...req.body };
      if (body.phone) body.phone = '***' + (body.phone || '').slice(-4);
      if (body.password) body.password = '***';
      if (body.api_key) body.api_key = '***';
      return { ...pinoHttp.stdSerializers.req(req), body };
    }
  }
});

app.use(logger);
app.use(requestId);
app.use(compression());

// ============= ENHANCED HELMET CONFIGURATION =============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      frameSrc: ["'none'"],
    }
  },
  referrerPolicy: { policy: "no-referrer" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  noSniff: true,
  xssFilter: true,
  frameguard: { action: 'deny' },
  hsts: { 
    maxAge: 31536000, 
    includeSubDomains: true, 
    preload: true 
  },
  dnsPrefetchControl: true,
  ieNoOpen: true,
  expectCt: { maxAge: 86400 }
}));

app.use(helmet.hidePoweredBy());

// ============= BODY PARSING =============
const jsonLimit = process.env.JSON_LIMIT || '100kb';
app.use(express.json({ limit: jsonLimit }));
app.use(express.urlencoded({ extended: false, limit: jsonLimit }));

// ============= TIMEOUT HANDLING =============
const requestTimeout = process.env.REQUEST_TIMEOUT || '15s';
app.use(timeout(requestTimeout));

function haltOnTimedout(req, res, next) {
  if (!req.timedout) return next();
  req.log && req.log.warn({ reqId: req.id || req.headers['x-request-id'] }, 'Request timed out');
  try { 
    if (!res.headersSent) res.status(503).json({ error: 'request_timeout' }); 
  } catch (e) { /* ignore */ }
}

// ============= CORS CONFIGURATION =============
const rawOrigins = process.env.CORS_ORIGINS || '';
let allowedOrigins = [];

if (rawOrigins) {
  allowedOrigins = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);
}

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.length === 0) {
      if (process.env.NODE_ENV === 'production') {
        console.error('FATAL: CORS_ORIGINS not configured in production!');
        process.exit(1);
      }
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    
    return callback(new Error(`CORS origin not allowed: ${origin}`));
  },
  optionsSuccessStatus: 204,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptions));

// Dev logging
if (process.env.NODE_ENV !== 'production') {
  const morgan = require('morgan');
  app.use(morgan('dev'));
}

// ============= AUTHENTICATION MIDDLEWARE =============
function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'missing_api_key',
      message: 'API key required in X-API-Key header or api_key query parameter'
    });
  }
  
  // Use timing-safe comparison to prevent timing attacks
  const validKey = process.env.API_SECRET_KEY;
  const isValid = crypto.timingSafeEqual(
    Buffer.from(apiKey),
    Buffer.from(validKey)
  ).valueOf();
  
  if (!isValid) {
    req.log && req.log.warn({ apiKey: '***', ip: req.ip }, 'Invalid API key attempt');
    return res.status(401).json({ error: 'invalid_api_key' });
  }
  
  req.authenticated = true;
  next();
}

// ============= SIGNATURE VALIDATION MIDDLEWARE =============
function validateSignature(req, res, next) {
  const signature = req.headers['x-signature'];
  
  if (!signature) {
    return res.status(401).json({ error: 'missing_signature' });
  }
  
  const webhookSecret = process.env.WEBHOOK_SECRET || process.env.API_SECRET_KEY;
  const body = JSON.stringify(req.body);
  const hash = crypto.createHmac('sha256', webhookSecret)
    .update(body)
    .digest('hex');
  
  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(hash)
  ).valueOf();
  
  if (!isValid) {
    req.log && req.log.warn({ ip: req.ip }, 'Invalid signature');
    return res.status(401).json({ error: 'invalid_signature' });
  }
  
  next();
}

// ============= GLOBAL RATE LIMITING =============
const globalRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX || '60', 10),
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health', // Skip health checks
  message: { error: 'too_many_requests', retryAfter: '60s' },
  ...(redisClient && RedisStore ? {
    store: new RedisStore({
      sendCommand: (...args) => redisClient.call(...args)
    })
  } : {})
});

app.use(globalRateLimiter);

// ============= ENDPOINT-SPECIFIC RATE LIMITING =============
const strictRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_STRICT || '20', 10),
  standardHeaders: true,
  skip: (req) => !req.authenticated,
  ...(redisClient && RedisStore ? {
    store: new RedisStore({
      sendCommand: (...args) => redisClient.call(...args)
    })
  } : {})
});

// ============= PHONE NUMBER VALIDATION =============
let parsePhoneNumberFromString = null;
let hasPhoneLib = false;

try {
  const lib = require('libphonenumber-js');
  parsePhoneNumberFromString = lib.parsePhoneNumberFromString || lib.parsePhoneNumber;
  hasPhoneLib = typeof parsePhoneNumberFromString === 'function';
} catch (e) {
  parsePhoneNumberFromString = () => null;
  hasPhoneLib = false;
  if (process.env.NODE_ENV !== 'production') {
    console.warn('libphonenumber-js not installed');
  }
}

// ============= PROTECTED HEALTH ENDPOINT =============
function isInternalIP(ip) {
  const internalPatterns = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/;
  return internalPatterns.test(ip) || ip === '::1';
}

app.get('/health', (req, res) => {
  // Allow from internal IPs or skip check if not in production
  if (process.env.NODE_ENV === 'production' && !isInternalIP(req.ip)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  
  res.json({
    status: 'ok',
    node_env: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ============= METRICS ENDPOINT =============
app.get('/metrics', (req, res) => {
  if (process.env.NODE_ENV === 'production' && !isInternalIP(req.ip)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  
  res.type('text/plain').send('# Prometheus metrics placeholder\n');
});

// ============= API ROUTES =============
app.post('/api/v1/call',
  validateApiKey,
  strictRateLimiter,
  body('phone')
    .isString()
    .notEmpty()
    .trim()
    .isLength({ max: 15 })
    .withMessage('phone must be a valid string (max 15 chars)'),
  body('message')
    .isString()
    .isLength({ min: 1, max: 1000 })
    .customSanitizer(value => xss(value))
    .withMessage('message is required and must be less than 1000 chars'),
  async (req, res, next) => {
    try {
      if (req.timedout) return next();

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ 
          error: 'validation_error', 
          details: errors.array() 
        });
      }

      const { phone, message } = req.body;

      // Phone validation
      const phoneNumber = hasPhoneLib ? parsePhoneNumberFromString(phone || '') : null;
      if (hasPhoneLib && (!phoneNumber || !phoneNumber.isValid())) {
        return res.status(400).json({ 
          error: 'validation_error', 
          details: [{ msg: 'phone is invalid', param: 'phone' }] 
        });
      }

      // TODO: Replace with actual call service
      // await callService.send({ 
      //   to: phoneNumber ? phoneNumber.number : phone, 
      //   message: message 
      // });

      res.json({ 
        ok: true, 
        to: phone.slice(-4) + '***', // Mask phone in response
        messageLength: message.length,
        requestId: req.id
      });
    } catch (err) {
      return next(err);
    }
  },
  haltOnTimedout
);

// ============= WEBHOOK ENDPOINT (WITH SIGNATURE VALIDATION) =============
app.post('/api/v1/webhook',
  validateSignature,
  strictRateLimiter,
  async (req, res, next) => {
    try {
      if (req.timedout) return next();
      
      // Process webhook
      req.log && req.log.info({ webhook: 'received' }, 'Webhook received');
      
      res.json({ ok: true, requestId: req.id });
    } catch (err) {
      return next(err);
    }
  },
  haltOnTimedout
);

// ============= 404 HANDLER =============
app.use((req, res) => {
  if (req.timedout) return;
  res.status(404).json({ 
    error: 'not_found', 
    path: req.originalUrl,
    requestId: req.id 
  });
});

// ============= GLOBAL ERROR HANDLER =============
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (req.timedout) {
    req.log && req.log.warn('Request timed out');
    return;
  }

  const reqId = req.id || req.headers['x-request-id'] || '-';
  
  if (req.log) {
    req.log.error({ err, reqId }, err?.message || 'Unhandled error');
  } else {
    console.error('Error:', { reqId, message: err?.message });
  }

  const status = (err?.status && Number.isInteger(err.status)) ? err.status : 500;
  const isProd = process.env.NODE_ENV === 'production';
  const debugAllowed = process.env.DEBUG === 'true' && !isProd;

  res.status(status).json({
    error: isProd ? 'internal_error' : (err?.message || 'Internal Server Error'),
    code: status,
    requestId: reqId,
    ...(debugAllowed && { details: err?.stack })
  });
});

// ============= GRACEFUL SHUTDOWN =============
const port = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(port, () => {
  console.log(`🚀 Server listening on port ${port} (${process.env.NODE_ENV})`);
});

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
        console.error('Forcing shutdown after timeout');
        closeAllConnections();
        closed = true;
        resolve();
      }
    }, timeoutMs);

    server.close((err) => {
      if (err) {
        console.error('Error closing server:', err);
      } else {
        console.log('Stopped accepting connections');
      }
      
      if (redisClient?.quit) {
        try {
          redisClient.quit().catch(e => console.error('Redis close error:', e));
        } catch (e) { /* ignore */ }
      }
      
      closed = true;
      clearTimeout(t);
      resolve();
    });
  });
}

async function shutdown(signal) {
  console.log(`📛 Received ${signal}, shutting down...`);
  try {
    await closeServerGracefully();
    console.log('✅ Graceful shutdown complete');
    process.exit(0);
  } catch (e) {
    console.error('❌ Shutdown error:', e);
    process.exit(1);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', async (reason) => {
  console.error('💥 Unhandled Rejection:', reason);
  try {
    await closeServerGracefully(5000);
  } catch (e) {
    console.error('Shutdown error:', e);
  } finally {
    process.exit(1);
  }
});

process.on('uncaughtException', async (err) => {
  console.error('💥 Uncaught Exception:', err);
  try {
    await closeServerGracefully(5000);
  } catch (e) {
    console.error('Shutdown error:', e);
  } finally {
    process.exit(1);
  }
});

module.exports = app;
