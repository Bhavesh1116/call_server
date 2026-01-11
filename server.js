/**
 * Improved server.js
 * - dotenv for environment config
 * - helmet for basic security headers
 * - cors with configurable origin
 * - express-rate-limit to reduce abuse
 * - morgan for request logging
 * - centralized error handling
 * - graceful shutdown
 * - basic input validation example
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// Basic middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' })); // parse JSON bodies
app.use(express.urlencoded({ extended: false }));

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// CORS (configure allowed origins via env)
const allowedOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({
  origin: allowedOrigin,
  optionsSuccessStatus: 204
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX || '60', 10), // limit each IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Simple healthcheck
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// Example route with validation
app.post('/api/call',
  body('phone').isString().notEmpty().withMessage('phone is required'),
  body('message').isString().isLength({ min: 1 }).withMessage('message is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Replace this with your actual call logic
    const { phone, message } = req.body;
    // example: callService.send({ phone, message })
    return res.json({ ok: true, to: phone, message });
  }
);

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'Not Found' });
});

// central error handler
app.use((err, req, res, next) => {
  // Log error (could integrate with winston/Sentry)
  console.error(err && err.stack ? err.stack : err);
  const status = err.status || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message;
  res.status(status).json({ error: message });
});

// Start server with graceful shutdown
const port = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  server.close(() => {
    console.log('Closed out remaining connections.');
    process.exit(0);
  });

  // Force shut down after 10s
  setTimeout(() => {
    console.error('Forcing shutdown after 10s.');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
