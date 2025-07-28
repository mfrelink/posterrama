/**
 * posterrama.app - Server-side logic for multiple media sources
 *
 * Author: Mark Frelink
 * Last Modified: 2025-07-27
 * License: GPL-3.0-or-later - This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

const logger = require('./logger');

// Handle uncaught exceptions and unhandled promise rejections
process.on('uncaughtException', (error) => {
    logger.fatal('Uncaught Exception:', error);
    // Give the logger time to write before exiting
    setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.fatal('Unhandled Promise Rejection:', reason);
});

// Track memory usage
const MEMORY_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
    const used = process.memoryUsage();
    logger.debug('Memory Usage:', {
        rss: `${Math.round(used.rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(used.heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(used.heapUsed / 1024 / 1024)}MB`,
        external: `${Math.round(used.external / 1024 / 1024)}MB`
    });
}, MEMORY_CHECK_INTERVAL);

// Override console methods to use the logger
const originalConsoleLog = console.log;
console.log = (...args) => { logger.info(...args); originalConsoleLog.apply(console, args); };
const originalConsoleError = console.error;
console.error = (...args) => { logger.error(...args); originalConsoleError.apply(console, args); };
const originalConsoleWarn = console.warn;
console.warn = (...args) => { logger.warn(...args); originalConsoleWarn.apply(console, args); };

const path = require('path');
const fs = require('fs');
require('dotenv').config();
const crypto = require('crypto');
const { PassThrough } = require('stream');
const fsp = fs.promises;

// --- Environment Initialization ---
// Automatically create and configure the .env file on first run.
(function initializeEnvironment() {
    const envPath = path.join(__dirname, '.env');
    const exampleEnvPath = path.join(__dirname, 'config.example.env');
    const sessionsPath = path.join(__dirname, 'sessions');
    const imageCacheDir = path.join(__dirname, 'image_cache');

    try {
        // Ensure the sessions directory exists before the session store tries to use it.
        // Using sync methods here prevents a race condition with session middleware initialization.
        fs.mkdirSync(sessionsPath, { recursive: true });
        fs.mkdirSync(imageCacheDir, { recursive: true });
    } catch (error) {
        console.error('FATAL ERROR: Could not create sessions directory.', error);
        process.exit(1);
    }

    try {
        // Check if .env file exists
        fs.accessSync(envPath);
    } catch (error) {
        // If .env doesn't exist, copy from config.example.env
        if (error.code === 'ENOENT') {
            console.log('.env file not found, creating from config.example.env...');
            fs.copyFileSync(exampleEnvPath, envPath);
            console.log('.env file created successfully.');
            // Reload dotenv to pick up the new file
            require('dotenv').config({ override: true });
        } else {
            console.error('Error checking .env file:', error);
            process.exit(1);
        }
    }

    // Validate SESSION_SECRET
    if (!process.env.SESSION_SECRET) {
        console.log('SESSION_SECRET is missing, generating a new one...');
        const newSecret = require('crypto').randomBytes(32).toString('hex');
        // Read the .env file
        const envContent = fs.readFileSync(envPath, 'utf8');
        // Append the new secret to the .env file
        const newEnvContent = envContent + `\nSESSION_SECRET="${newSecret}"\n`;
        // Write the updated content back to the .env file
        fs.writeFileSync(envPath, newEnvContent, 'utf8');
        console.log('New SESSION_SECRET generated and saved to .env.');

        // If running under PM2, trigger a restart. The current process will likely crash
        // due to the missing session secret, and PM2 will restart it. The new process
        // will then load the secret correctly from the .env file.
        if (process.env.PM2_HOME) {
            console.log('Running under PM2. Triggering a restart to apply the new SESSION_SECRET...');
            const { exec } = require('child_process');
            const ecosystemConfig = require('./ecosystem.config.js');
            const appName = ecosystemConfig.apps[0].name || 'posterrama';

            exec(`pm2 restart ${appName}`, (error) => {
                if (error) console.error(`[Initial Setup] PM2 restart command failed: ${error.message}`);
            });
        } else {
            console.warn('SESSION_SECRET was generated, but the app does not appear to be running under PM2. A manual restart is recommended.');
            // If not under PM2, we can update the current process's env and continue.
            process.env.SESSION_SECRET = newSecret;
        }
    }
})();
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcrypt');
const { exec } = require('child_process');
const PlexAPI = require('plex-api');
const fetch = require('node-fetch');
const config = require('./config.json');
const swaggerUi = require('swagger-ui-express');
const swaggerSpecs = require('./swagger.js');
const pkg = require('./package.json');
const ecosystemConfig = require('./ecosystem.config.js');
const { shuffleArray } = require('./utils.js');

const PlexSource = require('./sources/plex');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const rateLimit = require('express-rate-limit');
const app = express();
const { ApiError, NotFoundError } = require('./errors.js');

// Use process.env with a fallback to config.json
const port = process.env.SERVER_PORT || config.serverPort || 4000;
const isDebug = process.env.DEBUG === 'true';

// Caching system
const { cacheManager, cacheMiddleware, initializeCache } = require('./utils/cache');
initializeCache(logger);

// Metrics system
const metricsManager = require('./utils/metrics');
const { metricsMiddleware } = require('./middleware/metrics');

// Authentication system
const authManager = require('./utils/auth');
const { 
    authenticate, 
    jwtAuth, 
    apiKeyAuth, 
    requireRole, 
    requirePermission, 
    requireTwoFactor,
    checkAccountLockout,
    sessionAuth
} = require('./middleware/auth');

// Performance and security logging middleware
app.use((req, res, next) => {
    // Add request ID for tracking
    req.id = crypto.randomBytes(16).toString('hex');
    
    // Log start of request processing
    const start = process.hrtime();
    const requestLog = {
        id: req.id,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent')
    };

    // Security logging for admin endpoints - only log truly suspicious activity
    if (req.path.startsWith('/api/admin/')) {
        if (!req.session?.user) {
            // Only warn for POST/PUT/DELETE requests without auth (these are more serious)
            if (req.method !== 'GET') {
                logger.warn('Unauthorized admin API modification attempt', {
                    method: req.method,
                    path: req.path,
                    ip: req.ip,
                    userAgent: (req.get('user-agent') || '').substring(0, 100)
                });
            }
            // GET requests without auth are normal (frontend loading data before login)
        }
        // Don't log successful authenticated requests to reduce noise
    }

    // Log request completion and performance metrics
    res.on('finish', () => {
        const [seconds, nanoseconds] = process.hrtime(start);
        const duration = seconds * 1000 + nanoseconds / 1000000;
        
        const logLevel = res.statusCode >= 500 ? 'error' :
                        res.statusCode >= 400 ? 'warn' : 
                        'debug';
        
        logger[logLevel]('Request completed', {
            ...requestLog,
            status: res.statusCode,
            duration: `${duration.toFixed(2)}ms`,
            contentLength: res.get('content-length')
        });

        // Log slow requests
        if (duration > 1000) { // 1 second threshold
            logger.warn('Slow request detected', {
                ...requestLog,
                duration: `${duration.toFixed(2)}ms`,
                status: res.statusCode
            });
        }
    });

    next();
});

// API Versioning Middleware
app.use('/api', (req, res, next) => {
    const currentVersion = pkg.version;
    const acceptedVersion = req.headers['accept-version'];
    
    // Always add current API version to response headers
    res.setHeader('X-API-Version', currentVersion);
    
    // Check if client requests specific version
    if (acceptedVersion) {
        const supportedVersions = ['1.2.0', '1.2.1', '1.2.2', '1.2.3', '1.2.4', '1.2.5'];
        
        if (!supportedVersions.includes(acceptedVersion)) {
            return res.status(400).json({
                error: `Unsupported API version: ${acceptedVersion}. Supported versions: ${supportedVersions.join(', ')}`
            });
        }
    }
    
    next();
});

// Version-specific route aliases - redirect to actual endpoints
app.get('/api/v1/config', (req, res) => {
    req.url = '/get-config';
    req.originalUrl = '/get-config';
    app._router.handle(req, res);
});

app.get('/api/v1/media', (req, res) => {
    req.url = '/get-media';
    req.originalUrl = '/get-media';
    app._router.handle(req, res);
});

if (isDebug) console.log('--- DEBUG MODE IS ACTIVE ---');

// Trust the first proxy in front of the app (e.g., Nginx, Cloudflare).
// This is necessary for express-rate-limit to work correctly when behind a proxy,
// as it allows the app to correctly identify the client's IP address.
app.set('trust proxy', 1);

// Rate Limiting
const { createRateLimiter } = require('./middleware/rateLimiter');

// General API Rate Limiting
const apiLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    100, // Max requests
    'Too many requests from this IP, please try again later.'
);

// Admin API Rate Limiting (more restrictive)

const adminApiLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    50, // Max requests
    'Too many admin API requests from this IP, please try again later.'
);

// Apply rate limiting
app.use('/api/admin/', adminApiLimiter);
app.use('/api/', apiLimiter);
app.use('/get-config', apiLimiter);
app.use('/get-media', apiLimiter);
app.use('/get-media-by-key', apiLimiter);
app.use('/image', apiLimiter);

// Add metrics collection middleware
app.use(metricsMiddleware);

// Input Validation Middleware and Endpoints
const { createValidationMiddleware, validateQueryParams, sanitizeInput, schemas } = require('./middleware/validate');

/**
 * @swagger
 * /api/v1/admin/config/validate:
 *   post:
 *     summary: Validate configuration data
 *     description: Validates configuration object against schema and returns sanitized data
 *     tags: [Validation]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             description: Configuration object to validate
 *     responses:
 *       200:
 *         description: Configuration is valid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Configuration is valid"
 *                 sanitized:
 *                   type: object
 *                   description: Sanitized configuration data
 *       400:
 *         description: Validation error
 */
app.post('/api/v1/admin/config/validate', 
    express.json(),
    createValidationMiddleware(schemas.config, 'body'), 
    (req, res) => {
        res.json({
            success: true,
            message: 'Configuration is valid',
            sanitized: req.body
        });
    }
);

/**
 * @swagger
 * /api/v1/admin/plex/validate-connection:
 *   post:
 *     summary: Validate Plex connection data
 *     description: Validates Plex server connection parameters against schema
 *     tags: [Validation]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               hostname:
 *                 type: string
 *                 description: Plex server hostname or IP
 *               port:
 *                 type: number
 *                 description: Plex server port
 *               token:
 *                 type: string
 *                 description: Plex authentication token
 *     responses:
 *       200:
 *         description: Plex connection data is valid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Plex connection data is valid"
 *                 sanitized:
 *                   type: object
 *                   description: Sanitized connection data
 *       400:
 *         description: Validation error
 */
app.post('/api/v1/admin/plex/validate-connection',
    express.json(),
    createValidationMiddleware(schemas.plexConnection, 'body'),
    (req, res) => {
        res.json({
            success: true,
            message: 'Plex connection data is valid',
            sanitized: req.body
        });
    }
);

// Apply query parameter validation to media endpoints
app.use('/api/v1/get-media', validateQueryParams);

/**
 * @swagger
 * /api/v1/test-error:
 *   get:
 *     summary: Test error handling (Development only)
 *     description: Throws a test error to verify error handling middleware works correctly
 *     tags: [Testing]
 *     responses:
 *       500:
 *         description: Test error thrown successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "This is a test error"
 */
app.get('/api/v1/test-error', (req, res, next) => {
    const error = new Error('This is a test error');
    next(error);
});

/**
 * @swagger
 * /api/v1/test-async-error:
 *   get:
 *     summary: Test async error handling (Development only)
 *     description: Throws a test async error to verify async error handling middleware works correctly
 *     tags: [Testing]
 *     responses:
 *       500:
 *         description: Test async error thrown successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "This is a test async error"
 */
app.get('/api/v1/test-async-error', async (req, res, next) => {
    try {
        throw new Error('This is a test async error');
    } catch (error) {
        next(error);
    }
});

// Metrics Dashboard API Endpoints

/**
 * @swagger
 * /api/v1/metrics/performance:
 *   get:
 *     summary: Get performance metrics
 *     description: Returns current performance metrics including response times, throughput, and resource usage
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Performance metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 responseTime:
 *                   type: object
 *                   description: Average response times
 *                 throughput:
 *                   type: object
 *                   description: Requests per second metrics
 *                 resourceUsage:
 *                   type: object
 *                   description: CPU and memory usage
 */
app.get('/api/v1/metrics/performance', (req, res) => {
    const metrics = metricsManager.getPerformanceMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/endpoints:
 *   get:
 *     summary: Get endpoint metrics
 *     description: Returns metrics for individual API endpoints including request counts and response times
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Endpoint metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 endpoints:
 *                   type: object
 *                   description: Per-endpoint metrics
 */
app.get('/api/v1/metrics/endpoints', (req, res) => {
    const metrics = metricsManager.getEndpointMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/errors:
 *   get:
 *     summary: Get error metrics
 *     description: Returns error statistics including error rates, error types, and recent errors
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Error metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 errorRate:
 *                   type: number
 *                   description: Current error rate percentage
 *                 errorTypes:
 *                   type: object
 *                   description: Breakdown by error type
 *                 recentErrors:
 *                   type: array
 *                   description: Recent error occurrences
 */
app.get('/api/v1/metrics/errors', (req, res) => {
    const metrics = metricsManager.getErrorMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/cache:
 *   get:
 *     summary: Get cache metrics
 *     description: Returns cache performance metrics including hit rates, miss rates, and cache sizes
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Cache metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hitRate:
 *                   type: number
 *                   description: Cache hit rate percentage
 *                 missRate:
 *                   type: number
 *                   description: Cache miss rate percentage
 *                 size:
 *                   type: object
 *                   description: Cache size information
 */
app.get('/api/v1/metrics/cache', (req, res) => {
    const metrics = metricsManager.getCacheMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/system:
 *   get:
 *     summary: Get system metrics
 *     description: Returns system-level metrics including memory usage, CPU usage, and uptime
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: System metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 memory:
 *                   type: object
 *                   description: Memory usage statistics
 *                 cpu:
 *                   type: object
 *                   description: CPU usage statistics
 *                 uptime:
 *                   type: number
 *                   description: Process uptime in seconds
 */
app.get('/api/v1/metrics/system', (req, res) => {
    const metrics = metricsManager.getSystemMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/realtime:
 *   get:
 *     summary: Get real-time metrics
 *     description: Returns current real-time metrics for live monitoring dashboards
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Real-time metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: Current timestamp
 *                 metrics:
 *                   type: object
 *                   description: Current metric values
 */
app.get('/api/v1/metrics/realtime', (req, res) => {
    const metrics = metricsManager.getRealTimeMetrics();
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/history:
 *   get:
 *     summary: Get historical metrics
 *     description: Returns historical metrics data for the specified time period
 *     tags: [Metrics]
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [1h, 6h, 24h, 7d, 30d]
 *           default: 1h
 *         description: Time period for historical data
 *     responses:
 *       200:
 *         description: Historical metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 period:
 *                   type: string
 *                   description: Requested time period
 *                 data:
 *                   type: array
 *                   description: Time-series metric data
 */
app.get('/api/v1/metrics/history', (req, res) => {
    const period = req.query.period || '1h';
    const metrics = metricsManager.getHistoricalMetrics(period);
    res.json(metrics);
});

/**
 * @swagger
 * /api/v1/metrics/dashboard:
 *   get:
 *     summary: Get dashboard summary metrics
 *     description: Returns a summary of key metrics suitable for dashboard display
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Dashboard metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 summary:
 *                   type: object
 *                   description: Key metric summaries
 *                 alerts:
 *                   type: array
 *                   description: Active alerts or warnings
 */
app.get('/api/v1/metrics/dashboard', (req, res) => {
    const summary = metricsManager.getDashboardSummary();
    res.json(summary);
});

/**
 * @swagger
 * /metrics:
 *   get:
 *     summary: Prometheus metrics endpoint
 *     description: Returns metrics in Prometheus format for monitoring systems
 *     tags: [Metrics]
 *     responses:
 *       200:
 *         description: Prometheus metrics data
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               description: Metrics in Prometheus text format
 */
app.get('/metrics', (req, res) => {
    const prometheusMetrics = metricsManager.exportMetrics('prometheus');
    res.set('Content-Type', 'text/plain');
    res.send(prometheusMetrics);
});

/**
 * @swagger
 * /api/v1/metrics/export:
 *   get:
 *     summary: Export metrics in various formats
 *     description: Exports all metrics data in the specified format (JSON or Prometheus)
 *     tags: [Metrics]
 *     parameters:
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json, prometheus]
 *           default: json
 *         description: Export format
 *     responses:
 *       200:
 *         description: Metrics exported successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               description: Metrics data in JSON format
 *           text/plain:
 *             schema:
 *               type: string
 *               description: Metrics data in Prometheus format
 */
app.get('/api/v1/metrics/export', (req, res) => {
    const format = req.query.format || 'json';
    const metrics = metricsManager.exportMetrics(format);
    
    if (format === 'prometheus') {
        res.set('Content-Type', 'text/plain');
        res.send(metrics);
    } else {
        res.json(metrics);
    }
});

/**
 * @swagger
 * /api/v1/admin/metrics/config:
 *   post:
 *     summary: Update metrics configuration
 *     description: Updates the metrics collection configuration
 *     tags: [Metrics, Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               enabled:
 *                 type: boolean
 *                 description: Enable or disable metrics collection
 *               collectInterval:
 *                 type: number
 *                 description: Metrics collection interval in milliseconds
 *               retentionPeriod:
 *                 type: number
 *                 description: How long to retain metrics data in milliseconds
 *               endpoints:
 *                 type: object
 *                 description: Per-endpoint configuration
 *     responses:
 *       200:
 *         description: Configuration updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 config:
 *                   type: object
 *                   description: Updated configuration
 *       400:
 *         description: Invalid configuration
 */
app.post('/api/v1/admin/metrics/config', express.json(), (req, res) => {
    try {
        const { enabled, collectInterval, retentionPeriod, endpoints } = req.body;
        
        // Validate configuration
        const config = {};
        if (typeof enabled === 'boolean') config.enabled = enabled;
        if (typeof collectInterval === 'number' && collectInterval > 0) config.collectInterval = collectInterval;
        if (typeof retentionPeriod === 'number' && retentionPeriod > 0) config.retentionPeriod = retentionPeriod;
        if (endpoints && typeof endpoints === 'object') config.endpoints = endpoints;
        
        metricsManager.updateConfig(config);
        res.json({ success: true, config });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Authentication API Endpoints

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: User login
 *     description: Authenticate user with username and password, returns JWT token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: User's username
 *               password:
 *                 type: string
 *                 format: password
 *                 description: User's password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT access token
 *                 refreshToken:
 *                   type: string
 *                   description: Refresh token for token renewal
 *                 user:
 *                   type: object
 *                   description: User information
 *       400:
 *         description: Missing username or password
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Too many login attempts
 */
app.post('/api/v1/auth/login', express.json(), checkAccountLockout, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const result = await authManager.authenticateUser(username, password);
        res.json(result);
    } catch (error) {
        logger.warn('Login attempt failed:', error.message);
        res.status(401).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     description: Generate new access token using refresh token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Valid refresh token
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: New JWT access token
 *                 refreshToken:
 *                   type: string
 *                   description: New refresh token
 *       400:
 *         description: Refresh token required
 *       401:
 *         description: Invalid refresh token
 */
app.post('/api/v1/auth/refresh', express.json(), async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token required' });
        }

        const result = authManager.refreshToken(refreshToken);
        res.json(result);
    } catch (error) {
        logger.warn('Token refresh failed:', error.message);
        res.status(401).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: User logout
 *     description: Logout user and invalidate current session
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logged out successfully"
 *       401:
 *         description: Unauthorized - invalid token
 *       500:
 *         description: Logout failed
 */
app.post('/api/v1/auth/logout', jwtAuth, async (req, res) => {
    try {
        // Invalidate session if exists
        const sessionId = req.headers['x-session-id'];
        if (sessionId) {
            authManager.invalidateSession(sessionId);
        }

        // In a real implementation, you'd also blacklist the JWT token
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

/**
 * @swagger
 * /api/v1/auth/logout-all:
 *   post:
 *     summary: Logout from all sessions
 *     description: Logout user from all active sessions
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all sessions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logged out from 3 sessions"
 *       401:
 *         description: Unauthorized - invalid token
 *       500:
 *         description: Logout failed
 */
app.post('/api/v1/auth/logout-all', jwtAuth, async (req, res) => {
    try {
        const count = authManager.invalidateAllSessions(req.user.userId);
        res.json({ message: `Logged out from ${count} sessions` });
    } catch (error) {
        logger.error('Logout all error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

/**
 * @swagger
 * /api/v1/auth/sessions:
 *   get:
 *     summary: Get user sessions
 *     description: Retrieve all active sessions for the current user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sessions retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                     description: Session ID
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                   lastActivity:
 *                     type: string
 *                     format: date-time
 *                   userAgent:
 *                     type: string
 *                     description: Browser/client information
 *       401:
 *         description: Unauthorized - invalid token
 *       500:
 *         description: Failed to retrieve sessions
 */
app.get('/api/v1/auth/sessions', jwtAuth, async (req, res) => {
    try {
        const sessions = authManager.getUserSessions(req.user.userId);
        res.json(sessions);
    } catch (error) {
        logger.error('Get sessions error:', error);
        res.status(500).json({ error: 'Failed to retrieve sessions' });
    }
});

/**
 * @swagger
 * /api/v1/admin/api-keys:
 *   post:
 *     summary: Create API key
 *     description: Create a new API key with specified permissions (Admin only)
 *     tags: [API Keys, Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - permissions
 *             properties:
 *               name:
 *                 type: string
 *                 description: Descriptive name for the API key
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of permissions for this API key
 *     responses:
 *       201:
 *         description: API key created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   description: API key ID
 *                 key:
 *                   type: string
 *                   description: The actual API key (shown only once)
 *                 name:
 *                   type: string
 *                   description: API key name
 *                 permissions:
 *                   type: array
 *                   items:
 *                     type: string
 *       400:
 *         description: Missing name or permissions
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 */
app.post('/api/v1/admin/api-keys', jwtAuth, requireRole('admin'), express.json(), async (req, res) => {
    try {
        const { name, permissions } = req.body;
        
        if (!name || !permissions) {
            return res.status(400).json({ error: 'Name and permissions required' });
        }

        const apiKey = authManager.createApiKey(name, permissions, req.user.userId);
        res.status(201).json(apiKey);
    } catch (error) {
        logger.error('Create API key error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/admin/api-keys:
 *   get:
 *     summary: List API keys
 *     description: Get all API keys created by the current admin user
 *     tags: [API Keys, Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: API keys retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                     description: API key ID
 *                   name:
 *                     type: string
 *                     description: API key name
 *                   permissions:
 *                     type: array
 *                     items:
 *                       type: string
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                   lastUsed:
 *                     type: string
 *                     format: date-time
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 */
app.get('/api/v1/admin/api-keys', jwtAuth, requireRole('admin'), async (req, res) => {
    try {
        const apiKeys = authManager.listApiKeys(req.user.userId);
        res.json(apiKeys);
    } catch (error) {
        logger.error('List API keys error:', error);
        res.status(500).json({ error: 'Failed to retrieve API keys' });
    }
});

/**
 * @swagger
 * /api/v1/admin/api-keys/{keyId}:
 *   delete:
 *     summary: Revoke API key
 *     description: Revoke/delete an API key by ID (Admin only)
 *     tags: [API Keys, Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: keyId
 *         required: true
 *         schema:
 *           type: string
 *         description: API key ID to revoke
 *     responses:
 *       200:
 *         description: API key revoked successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "API key revoked successfully"
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 *       404:
 *         description: API key not found
 */
app.delete('/api/v1/admin/api-keys/:keyId', jwtAuth, requireRole('admin'), async (req, res) => {
    try {
        const { keyId } = req.params;
        const revoked = authManager.revokeApiKey(keyId, req.user.userId);
        
        if (revoked) {
            res.json({ message: 'API key revoked successfully' });
        } else {
            res.status(404).json({ error: 'API key not found' });
        }
    } catch (error) {
        logger.error('Revoke API key error:', error);
        res.status(500).json({ error: 'Failed to revoke API key' });
    }
});

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: Get all users
 *     description: Retrieve list of all users (Admin only)
 *     tags: [User Management, Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                     description: User ID
 *                   username:
 *                     type: string
 *                     description: Username
 *                   email:
 *                     type: string
 *                     format: email
 *                     description: User email
 *                   role:
 *                     type: string
 *                     description: User role
 *                   locked:
 *                     type: boolean
 *                     description: Whether account is locked
 *                   lastLogin:
 *                     type: string
 *                     format: date-time
 *                     description: Last login timestamp
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                     description: Account creation timestamp
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 */
app.get('/api/v1/admin/users', jwtAuth, requireRole('admin'), async (req, res) => {
    try {
        const users = Array.from(authManager.users.values()).map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            locked: user.locked,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt
        }));
        res.json(users);
    } catch (error) {
        logger.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to retrieve users' });
    }
});

/**
 * @swagger
 * /api/v1/admin/users/{userId}:
 *   delete:
 *     summary: Delete user
 *     description: Delete a user account (Admin only, requires 2FA)
 *     tags: [User Management, Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID to delete
 *     responses:
 *       200:
 *         description: User deletion status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User deletion requires database implementation"
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required or 2FA required
 *       500:
 *         description: Failed to delete user
 */
app.delete('/api/v1/admin/users/:userId', jwtAuth, requireRole('admin'), requireTwoFactor, async (req, res) => {
    try {
        const { userId } = req.params;
        // In a real implementation, you'd delete from database
        res.json({ message: 'User deletion requires database implementation' });
    } catch (error) {
        logger.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

/**
 * @swagger
 * /api/v1/auth/2fa/setup:
 *   post:
 *     summary: Setup Two-Factor Authentication
 *     description: Generate 2FA secret and QR code for user setup
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA setup data generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 secret:
 *                   type: string
 *                   description: 2FA secret key for manual entry
 *                 qrCode:
 *                   type: string
 *                   description: Base64 encoded QR code image for easy setup
 *       401:
 *         description: Unauthorized - invalid token
 *       500:
 *         description: Failed to setup 2FA
 */
app.post('/api/v1/auth/2fa/setup', jwtAuth, express.json(), async (req, res) => {
    try {
        const result = authManager.setupTwoFactor(req.user.userId);
        const qrCode = await authManager.generateQRCode(result.qrCode);
        
        res.json({
            secret: result.secret,
            qrCode: qrCode
        });
    } catch (error) {
        logger.error('2FA setup error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/2fa/verify:
 *   post:
 *     summary: Verify and enable Two-Factor Authentication
 *     description: Verify 2FA token and enable 2FA for the user account
 *     tags: [Two-Factor Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *                 description: 6-digit 2FA token from authenticator app
 *                 pattern: '^[0-9]{6}$'
 *     responses:
 *       200:
 *         description: 2FA verified and enabled successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "2FA verified and enabled successfully"
 *       400:
 *         description: Invalid or missing 2FA token
 *       401:
 *         description: Unauthorized - invalid token
 */
app.post('/api/v1/auth/2fa/verify', jwtAuth, express.json(), async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: '2FA token required' });
        }

        const verified = authManager.verifyTwoFactor(req.user.userId, token);
        
        if (verified) {
            res.json({ message: '2FA verified and enabled successfully' });
        } else {
            res.status(400).json({ error: 'Invalid 2FA token' });
        }
    } catch (error) {
        logger.error('2FA verify error:', error);
        res.status(400).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/admin/roles:
 *   post:
 *     summary: Create new role
 *     description: Create a new user role with specified permissions (Admin only)
 *     tags: [Role Management, Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - permissions
 *             properties:
 *               name:
 *                 type: string
 *                 description: Role name
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of permissions for this role
 *     responses:
 *       201:
 *         description: Role created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   description: Role ID
 *                 name:
 *                   type: string
 *                   description: Role name
 *                 permissions:
 *                   type: array
 *                   items:
 *                     type: string
 *       400:
 *         description: Missing name or permissions, or role already exists
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 */
app.post('/api/v1/admin/roles', jwtAuth, requireRole('admin'), express.json(), async (req, res) => {
    try {
        const { name, permissions } = req.body;
        
        if (!name || !permissions) {
            return res.status(400).json({ error: 'Name and permissions required' });
        }

        const role = authManager.createRole(name, permissions);
        res.status(201).json(role);
    } catch (error) {
        logger.error('Create role error:', error);
        res.status(400).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/change-password:
 *   post:
 *     summary: Change user password
 *     description: Change the current user's password
 *     tags: [Password Management]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *                 description: Current password for verification
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 description: New password
 *     responses:
 *       200:
 *         description: Password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password changed successfully"
 *       400:
 *         description: Missing passwords or invalid current password
 *       401:
 *         description: Unauthorized - invalid token
 */
app.post('/api/v1/auth/change-password', jwtAuth, express.json(), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new passwords required' });
        }

        await authManager.changePassword(req.user.userId, currentPassword, newPassword);
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        logger.error('Change password error:', error);
        res.status(400).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/reset-password:
 *   post:
 *     summary: Request password reset
 *     description: Request a password reset token for the specified email
 *     tags: [Password Management]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email address for password reset
 *     responses:
 *       200:
 *         description: Password reset email sent (token included in demo)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password reset email sent"
 *                 token:
 *                   type: string
 *                   description: Reset token (only in demo mode)
 *       400:
 *         description: Email required
 *       404:
 *         description: User not found
 */
app.post('/api/v1/auth/reset-password', express.json(), async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email required' });
        }

        const result = authManager.generatePasswordResetToken(email);
        // In production, you'd send an email instead of returning the token
        res.json({ message: 'Password reset email sent', token: result.token });
    } catch (error) {
        logger.error('Password reset request error:', error);
        res.status(404).json({ error: 'User not found' });
    }
});

/**
 * @swagger
 * /api/v1/auth/reset-password/confirm:
 *   post:
 *     summary: Confirm password reset
 *     description: Reset password using the provided reset token
 *     tags: [Password Management]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - newPassword
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 description: New password
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password reset successfully"
 *       400:
 *         description: Invalid or expired token, or missing parameters
 */
app.post('/api/v1/auth/reset-password/confirm', express.json(), async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password required' });
        }

        await authManager.resetPassword(token, newPassword);
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        logger.error('Password reset confirm error:', error);
        res.status(400).json({ error: error.message });
    }
});

/**
 * @swagger
 * /api/v1/auth/oauth/google:
 *   get:
 *     summary: Google OAuth login (Not implemented)
 *     description: Initiate Google OAuth login flow (placeholder endpoint)
 *     tags: [OAuth]
 *     responses:
 *       404:
 *         description: OAuth not implemented in this demo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "OAuth not implemented in this demo"
 */
app.get('/api/v1/auth/oauth/google', async (req, res) => {
    // In production, redirect to Google OAuth
    res.status(404).json({ error: 'OAuth not implemented in this demo' });
});

/**
 * @swagger
 * /api/v1/auth/oauth/callback:
 *   get:
 *     summary: OAuth callback handler (Not implemented)
 *     description: Handle OAuth callback from provider (placeholder endpoint)
 *     tags: [OAuth]
 *     responses:
 *       404:
 *         description: OAuth not implemented in this demo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "OAuth not implemented in this demo"
 */
app.get('/api/v1/auth/oauth/callback', async (req, res) => {
    // In production, handle OAuth callback
    res.status(404).json({ error: 'OAuth not implemented in this demo' });
});

/**
 * @swagger
 * /api/v1/auth/oauth/link:
 *   post:
 *     summary: Link OAuth account (Not implemented)
 *     description: Link an OAuth account to existing user account (placeholder endpoint)
 *     tags: [OAuth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       404:
 *         description: OAuth not implemented in this demo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "OAuth not implemented in this demo"
 */
app.post('/api/v1/auth/oauth/link', jwtAuth, express.json(), async (req, res) => {
    // In production, link OAuth account to existing user
    res.status(404).json({ error: 'OAuth not implemented in this demo' });
});

/**
 * @swagger
 * /api/v1/admin/auth-logs:
 *   get:
 *     summary: Get authentication logs
 *     description: Retrieve recent authentication logs (Admin only)
 *     tags: [Authentication, Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Authentication logs retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   timestamp:
 *                     type: string
 *                     format: date-time
 *                     description: Log entry timestamp
 *                   type:
 *                     type: string
 *                     enum: [login, logout, failed_login, token_refresh]
 *                     description: Authentication event type
 *                   userId:
 *                     type: string
 *                     description: User ID (if applicable)
 *                   ip:
 *                     type: string
 *                     description: Client IP address
 *                   userAgent:
 *                     type: string
 *                     description: Client user agent
 *                   success:
 *                     type: boolean
 *                     description: Whether the authentication was successful
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Admin access required
 */
app.get('/api/v1/admin/auth-logs', jwtAuth, requireRole('admin'), async (req, res) => {
    try {
        const logs = authManager.getAuthLogs(100);
        res.json(logs);
    } catch (error) {
        logger.error('Get auth logs error:', error);
        res.status(500).json({ error: 'Failed to retrieve authentication logs' });
    }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); // For parsing form data

// Swagger API documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

// General request logger for debugging
if (isDebug) {
    app.use((req, res, next) => {
        console.log(`[Request Logger] Received: ${req.method} ${req.originalUrl}`);
        next();
    });
}

// Session middleware setup
app.use(session({
    store: new FileStore({
        path: './sessions', // Sessions will be stored in a 'sessions' directory
        logFn: isDebug ? console.log : () => {},
        ttl: 86400 * 7, // Session TTL in seconds (7 days)
        reapInterval: 86400, // Clean up expired sessions once a day
        retries: 3 // Retry file operations up to 3 times
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true, // Extend session lifetime on each request
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Wrapper for async routes to catch errors and pass them to the error handler
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};



/**
 * Returns the standard options for a PlexAPI client instance to ensure consistent identification.
 * These options include application identifier, name, version and platform details for Plex server
 * identification and analytics.
 * @returns {object} An object containing the Plex client options with identifier and app metadata.
 */
function getPlexClientOptions() {
    // Default options ensure the app identifies itself correctly.
    // These can be overridden by setting a "plexClientOptions" object in config.json.
    const defaultOptions = {
        identifier: 'c8a5f7d1-b8e9-4f0a-9c6d-3e1f2a5b6c7d', // Static UUID for this app instance
        product: 'posterrama.app',
        version: pkg.version,
        deviceName: 'posterrama.app',
        platform: 'Node.js'
    };

    const finalOptions = { ...defaultOptions, ...(config.plexClientOptions || {}) };

    return {
        // These options must be nested inside an 'options' object per plex-api documentation.
        options: finalOptions
    };
}
/**
 * Fetches detailed metadata for a single Plex item and transforms it into the application's format.
 * Handles movies, TV shows, and their child items (seasons, episodes). For TV content,
 * fetches the parent show's metadata to ensure consistent background art.
 * 
 * @param {object} itemSummary - The summary object of the media item from Plex.
 * @param {object} serverConfig - The configuration for the Plex server.
 * @param {PlexAPI} plex - An active PlexAPI client instance.
 * @returns {Promise<object|null>} A processed media item object containing metadata, URLs, and ratings,
 *                                or null if the item cannot be processed or is missing required data.
 * @throws {Error} If there are network errors or invalid responses from the Plex server.
 * @example
 * const mediaItem = await processPlexItem(
 *   { key: "/library/metadata/12345" },
 *   serverConfig,
 *   plexClient
 * );
 * if (mediaItem) {
 *   console.log('Processed:', mediaItem.title, mediaItem.rottenTomatoes?.score);
 * }
 */
async function processPlexItem(itemSummary, serverConfig, plex) {
    const getImdbUrl = (guids) => {
        if (guids && Array.isArray(guids)) {
            const imdbGuid = guids.find(guid => guid.id.startsWith('imdb://'));
            if (imdbGuid) {
                const imdbId = imdbGuid.id.replace('imdb://', '');
                return `https://www.imdb.com/title/${imdbId}/`;
            }
        }
        return null;
    };

    const getClearLogoPath = (images) => {
        if (images && Array.isArray(images)) {
            const logoObject = images.find(img => img.type === 'clearLogo');
            return logoObject ? logoObject.url : null;
        }
        return null;
    };

    const getRottenTomatoesData = (ratings, titleForDebug = 'Unknown') => {
        if (!ratings || !Array.isArray(ratings)) {
            return null;
        }

        const rtRating = ratings.find(r => r.image && r.image.includes('rottentomatoes'));

        if (!rtRating || typeof rtRating.value === 'undefined') {
            return null;
        }

        // --- START ENHANCED DEBUG LOGGING ---
        if (isDebug) {
            console.log(`[RT Debug] Processing rating for "${titleForDebug}". Raw rtRating object:`, JSON.stringify(rtRating));
        }
        // --- END ENHANCED DEBUG LOGGING ---

        const score = parseFloat(rtRating.value);
        if (isNaN(score)) {
            return null;
        }

        // The score from Plex is on a 10-point scale, so we multiply by 10 for a percentage.
        const finalScore = Math.round(score * 10);

        const imageIdentifier = rtRating.image || '';
        const isCriticRating = rtRating.type === 'critic';
        let icon = 'rotten';

        // Heuristic for "Certified Fresh": We assume a high critic score (>= 85) indicates
        // this status, as the identifier from Plex ('ripe') doesn't distinguish it from regular "Fresh".
        if (isCriticRating && finalScore >= 85) {
            icon = 'certified-fresh';
        } else if (imageIdentifier.includes('ripe') || imageIdentifier.includes('upright') || finalScore >= 60) {
            // 'ripe' is for critic fresh, 'upright' is for audience fresh. The score is a fallback.
            icon = 'fresh';
        }

        if (isDebug) {
            console.log(`[RT Debug] -> For "${titleForDebug}": Identifier: "${imageIdentifier}", Score: ${finalScore}, Determined Icon: "${icon}"`);
        }

        return {
            score: finalScore, // The 0-100 score for display
            icon: icon,
            originalScore: score // The original 0-10 score for filtering
        };
    };

    try {
        if (!itemSummary.key) return null;
        const detailResponse = await plex.query(itemSummary.key);
        const item = detailResponse?.MediaContainer?.Metadata?.[0];
        if (!item) return null;

        let sourceItem = item; // This will be the movie or the show
        let backgroundArt = item.art; // Default to item's art

        if ((item.type === 'season' || item.type === 'episode') && item.parentKey) {
            const showDetails = await plex.query(item.parentKey).catch(() => null);
            if (showDetails?.MediaContainer?.Metadata?.[0]) {
                sourceItem = showDetails.MediaContainer.Metadata[0];
                backgroundArt = sourceItem.art; // Use the show's art for the background
            }
        }

        if (!backgroundArt || !sourceItem.thumb) return null;

        const imdbUrl = getImdbUrl(sourceItem.Guid);
        const clearLogoPath = getClearLogoPath(sourceItem.Image);
        const uniqueKey = `${serverConfig.type}-${serverConfig.name}-${sourceItem.ratingKey}`;
        const rottenTomatoesData = getRottenTomatoesData(sourceItem.Rating, sourceItem.title);

        if (isDebug) {
            if (rottenTomatoesData) {
                console.log(`[Plex Debug] Found Rotten Tomatoes data for "${sourceItem.title}": Score ${rottenTomatoesData.score}%, Icon ${rottenTomatoesData.icon}`);
            } else if (sourceItem.Rating) {
                // Only log if the Rating array exists but we couldn't parse RT data from it.
                console.log(`[Plex Debug] Could not parse Rotten Tomatoes data for "${sourceItem.title}" from rating array:`, JSON.stringify(sourceItem.Rating));
            }
        }

        return {
            key: uniqueKey,
            title: sourceItem.title,
            backgroundUrl: `/image?server=${encodeURIComponent(serverConfig.name)}&path=${encodeURIComponent(backgroundArt)}`,
            posterUrl: `/image?server=${encodeURIComponent(serverConfig.name)}&path=${encodeURIComponent(sourceItem.thumb)}`,
            clearLogoUrl: clearLogoPath ? `/image?server=${encodeURIComponent(serverConfig.name)}&path=${encodeURIComponent(clearLogoPath)}` : null,
            tagline: sourceItem.tagline,
            rating: sourceItem.rating,
            year: sourceItem.year,
            imdbUrl: imdbUrl,
            rottenTomatoes: rottenTomatoesData,
            _raw: isDebug ? item : undefined
        };
    } catch (e) {
        if (isDebug) console.log(`[Debug] Skipping item due to error fetching details for key ${itemSummary.key}: ${e.message}`);
        return null;
    }
}

// --- Client Management ---

/**
 * Creates a new PlexAPI client instance with the given options.
 * Sanitizes and validates the input parameters before creating the client.
 * 
 * @param {object} options - The connection options.
 * @param {string} options.hostname - The Plex server hostname or IP. Will be sanitized to remove http/https prefixes.
 * @param {string|number} options.port - The Plex server port.
 * @param {string} options.token - The Plex authentication token (X-Plex-Token).
 * @param {number} [options.timeout] - Optional request timeout in milliseconds. Defaults to no timeout.
 * @returns {PlexAPI} A new PlexAPI client instance configured with the sanitized options.
 * @throws {ApiError} If required parameters are missing or if the hostname format is invalid.
 * @example
 * const plexClient = createPlexClient({
 *   hostname: '192.168.1.100',
 *   port: 32400,
 *   token: 'xyz123',
 *   timeout: 5000
 * });
 */
function createPlexClient({ hostname, port, token, timeout }) {
    if (!hostname || !port || !token) {
        throw new ApiError(500, 'Plex client creation failed: missing hostname, port, or token.');
    }

    // Sanitize hostname to prevent crashes if the user includes the protocol.
    let sanitizedHostname = hostname.trim();
    try {
        // The URL constructor needs a protocol to work.
        const fullUrl = sanitizedHostname.includes('://') ? sanitizedHostname : `http://${sanitizedHostname}`;
        const url = new URL(fullUrl);
        sanitizedHostname = url.hostname; // This extracts just the hostname/IP
        if (isDebug) console.log(`[Plex Client] Sanitized hostname to: "${sanitizedHostname}"`);
    } catch (e) {
        // Fallback for invalid URL formats that might still be valid hostnames (though unlikely)
        sanitizedHostname = sanitizedHostname.replace(/^https?:\/\//, '');
        if (isDebug) console.log(`[Plex Client] Could not parse hostname as URL, falling back to simple sanitization: "${sanitizedHostname}"`);
    }

    const clientOptions = {
        hostname: sanitizedHostname,
        port,
        token,
        ...getPlexClientOptions()
    };

    if (timeout) clientOptions.timeout = timeout;
    return new PlexAPI(clientOptions);
}

/**
 * Performs a lightweight connection test for a given media server configuration.
 * @param {object} serverConfig The configuration object for the server from config.json.
 * @returns {Promise<{status: ('ok'|'error'), message: string}>} The result of the connection test.
 */
async function testServerConnection(serverConfig) {
    if (serverConfig.type === 'plex') {
        const startTime = process.hrtime();
        
        logger.debug('Testing Plex server connection', {
            action: 'plex_connection_test',
            server: {
                name: serverConfig.name,
                hostnameVar: serverConfig.hostnameEnvVar,
                portVar: serverConfig.portEnvVar
            }
        });

        try {
            const hostname = process.env[serverConfig.hostnameEnvVar];
            const port = process.env[serverConfig.portEnvVar];
            const token = process.env[serverConfig.tokenEnvVar];

            if (!hostname || !port || !token) {
                throw new Error('Missing required environment variables (hostname, port, or token) for this server.');
            }

            const testClient = createPlexClient({
                hostname,
                port,
                token,
                timeout: 5000 // 5-second timeout for health checks
            });

            // A lightweight query to check reachability and authentication
            await testClient.query('/');

            // Calculate response time
            const [seconds, nanoseconds] = process.hrtime(startTime);
            const responseTime = seconds * 1000 + nanoseconds / 1000000;

            // Log success with metrics
            logger.info('Plex server connection test successful', {
                action: 'plex_connection_success',
                server: {
                    name: serverConfig.name,
                    hostname: hostname,
                    port: port
                },
                metrics: {
                    responseTime: `${responseTime.toFixed(2)}ms`
                }
            });

            // Log warning if connection was slow
            if (responseTime > 1000) { // 1 second threshold
                logger.warn('Slow Plex server response detected', {
                    action: 'plex_connection_slow',
                    server: {
                        name: serverConfig.name,
                        hostname: hostname,
                        port: port
                    },
                    responseTime: `${responseTime.toFixed(2)}ms`
                });
            }

            return { status: 'ok', message: 'Connection successful.' };
        } catch (error) {
            let errorMessage = error.message;
            if (error.code === 'ECONNREFUSED') {
                errorMessage = 'Connection refused. Check hostname and port.';
                
                logger.error('Plex server connection refused', {
                    action: 'plex_connection_refused',
                    server: {
                        name: serverConfig.name,
                        hostname: process.env[serverConfig.hostnameEnvVar],
                        port: process.env[serverConfig.portEnvVar]
                    },
                    error: {
                        code: error.code,
                        message: error.message
                    }
                });
            } else if (error.message.includes('401 Unauthorized')) {
                errorMessage = 'Unauthorized. Check token.';
            } else if (error.code === 'ETIMEDOUT') {
                errorMessage = 'Connection timed out.';
            }
            return { status: 'error', message: `Plex connection failed: ${errorMessage}` };
        }
    }
    // Future server types can be added here
    return { status: 'error', message: `Unsupported server type for health check: ${serverConfig.type}` };
}

/**
 * Caches PlexAPI clients to avoid re-instantiating for every request.
 * @type {Object.<string, PlexAPI>}
 */
const plexClients = {};
function getPlexClient(serverConfig) {
    if (!plexClients[serverConfig.name]) {
        const hostname = process.env[serverConfig.hostnameEnvVar];
        const port = process.env[serverConfig.portEnvVar];
        const token = process.env[serverConfig.tokenEnvVar];

        // The createPlexClient function will throw an error if details are missing.
        // This replaces the explicit token check that was here before.
        plexClients[serverConfig.name] = createPlexClient({ hostname, port, token });
    }
    return plexClients[serverConfig.name];
}

/**
 * Fetches all library sections from a Plex server and returns them as a Map.
 * @param {object} serverConfig - The configuration for the Plex server including connection details and options.
 * @returns {Promise<Map<string, object>>} A map of library titles to library objects containing metadata about each library section.
 * @throws {ApiError} If the server connection fails or the server returns an error response.
 * @example
 * const libraries = await getPlexLibraries(serverConfig);
 * for (const [title, library] of libraries) {
 *   console.log(`Found library: ${title}, type: ${library.type}`);
 * }
 */
async function getPlexLibraries(serverConfig) {
    const plex = getPlexClient(serverConfig);
    const sectionsResponse = await plex.query('/library/sections');
    const allSections = sectionsResponse?.MediaContainer?.Directory || [];
    const libraries = new Map();
    allSections.forEach(dir => libraries.set(dir.title, dir));
    return libraries;
}

// --- Main Data Aggregation ---

async function getPlaylistMedia() {
    let allMedia = [];
    const enabledServers = config.mediaServers.filter(s => s.enabled);
 
    for (const server of enabledServers) {
        if (isDebug) console.log(`[Debug] Fetching from server: ${server.name} (${server.type})`);
 
        let source;
        if (server.type === 'plex') {
            source = new PlexSource(server, getPlexClient, processPlexItem, getPlexLibraries, shuffleArray, config.rottenTomatoesMinimumScore, isDebug);
        } else {
            if (isDebug) console.log(`[Debug] Skipping server ${server.name} due to unsupported type ${server.type}`);
            continue;
        }
 
        const [movies, shows] = await Promise.all([
            source.fetchMedia(server.movieLibraryNames || [], 'movie', server.movieCount || 0),
            source.fetchMedia(server.showLibraryNames || [], 'show', server.showCount || 0)
        ]);
        const mediaFromServer = movies.concat(shows);
 
        if (isDebug) console.log(`[Debug] Fetched ${mediaFromServer.length} items from ${server.name}.`);
        allMedia = allMedia.concat(mediaFromServer);
    }
 
    return allMedia;
}

let playlistCache = null;
let cacheTimestamp = 0;
let isRefreshing = false; // Lock to prevent concurrent refreshes

/**
 * Fetches media from all enabled servers and refreshes the in-memory cache.
 * Uses a locking mechanism to prevent concurrent refreshes.
 * Maintains the old cache in case of errors to prevent service interruption.
 * Logs performance metrics and memory usage.
 * 
 * @returns {Promise<void>} Resolves when the refresh is complete.
 * @throws {Error} If media fetching fails. Errors are caught and logged but won't crash the server.
 * @example
 * await refreshPlaylistCache();
 * console.log(`Cache now contains ${playlistCache.length} items`);
 */
async function refreshPlaylistCache() {
    if (isRefreshing) {
        logger.debug('Playlist refresh skipped - already in progress');
        return;
    }

    const startTime = process.hrtime();
    isRefreshing = true;
    logger.info('Starting playlist refresh', {
        action: 'playlist_refresh_start',
        timestamp: new Date().toISOString()
    });

    try {
        // Track memory usage before fetch
        const memBefore = process.memoryUsage();
        
        const allMedia = await getPlaylistMedia();
        playlistCache = shuffleArray(allMedia);
        cacheTimestamp = Date.now();
        
        // Track memory usage after fetch
        const memAfter = process.memoryUsage();
        const [seconds, nanoseconds] = process.hrtime(startTime);
        const duration = seconds * 1000 + nanoseconds / 1000000;

        // Log success with performance metrics
        logger.info('Playlist refresh completed', {
            action: 'playlist_refresh_complete',
            metrics: {
                duration: `${duration.toFixed(2)}ms`,
                itemCount: playlistCache.length,
                memoryDelta: {
                    heapUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`,
                    rss: `${Math.round((memAfter.rss - memBefore.rss) / 1024 / 1024)}MB`
                }
            }
        });

        // Log warning if refresh was slow
        if (duration > 5000) { // 5 seconds threshold
            logger.warn('Slow playlist refresh detected', {
                action: 'playlist_refresh_slow',
                duration: `${duration.toFixed(2)}ms`,
                itemCount: playlistCache.length
            });
        }
    } catch (error) {
        logger.error('Playlist refresh failed', {
            action: 'playlist_refresh_error',
            error: error.message,
            stack: error.stack
        });
        // We keep the old cache in case of an error
    } finally {
        isRefreshing = false;
    }
}

// --- Admin Panel Logic ---

/**
 * Middleware to check if the user is authenticated.
 */
function isAuthenticated(req, res, next) {    
    // 1. Check for session-based authentication (for browser users)
    if (req.session && req.session.user) {
        if (isDebug) console.log(`[Auth] Authenticated via session for user: ${req.session.user.username}`);
        return next();
    }

    // 2. Check for API key authentication (for scripts, Swagger, etc.)
    const apiToken = process.env.API_ACCESS_TOKEN;
    const authHeader = req.headers.authorization;

    if (apiToken && authHeader && authHeader.startsWith('Bearer ')) {
        const providedToken = authHeader.substring(7, authHeader.length);
        
        // Use timing-safe comparison to prevent timing attacks
        const storedTokenBuffer = Buffer.from(apiToken);
        const providedTokenBuffer = Buffer.from(providedToken);

        if (storedTokenBuffer.length === providedTokenBuffer.length && crypto.timingSafeEqual(storedTokenBuffer, providedTokenBuffer)) {
            if (isDebug) console.log('[Auth] Authenticated via API Key.');
            // Attach a user object for consistency in downstream middleware/routes.
            req.user = { username: 'api_user', authMethod: 'apiKey' };
            return next();
        }
    }

    // 3. If neither method works, deny access.
    if (isDebug) {
        const reason = authHeader ? 'Invalid token' : 'No session or token';
        console.log(`[Auth] Authentication failed. Reason: ${reason}`);
    }

    // For API requests, send a 401 JSON error.
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Authentication required. Your session may have expired or your API token is invalid.' });
    }

    // For regular page navigations, redirect to the login page.
    return res.redirect('/admin/login');
}

/**
 * Reads the .env file and returns its content as a string.
 */
async function readEnvFile() {
    try {
        return await fsp.readFile('.env', 'utf-8');
    } catch (error) {
        if (error.code === 'ENOENT') return ''; // File doesn't exist yet
        throw error;
    }
}

/**
 * Writes new values to the .env file while preserving existing content.
 * Creates a backup of the current .env file before making changes.
 * Updates both the file and process.env for immediate effect.
 * 
 * @param {Object} newValues - An object with key-value pairs to write.
 * @throws {Error} If file operations fail or if backup creation fails.
 * @example
 * await writeEnvFile({
 *   SERVER_PORT: '4000',
 *   DEBUG: 'true'
 * });
 */
async function writeEnvFile(newValues) {
    // Log environment update attempt
    logger.info('Environment update initiated', {
        action: 'env_update',
        keys: Object.keys(newValues).map(key => {
            // Mask sensitive values in logs
            const isSensitive = key.toLowerCase().includes('token') || 
                              key.toLowerCase().includes('password') || 
                              key.toLowerCase().includes('secret') ||
                              key.toLowerCase().includes('apikey');
            return {
                key,
                type: isSensitive ? 'sensitive' : 'regular'
            };
        })
    });

    try {
        let content = await readEnvFile();
        const lines = content.split('\n');
        const updatedKeys = new Set(Object.keys(newValues));
        const previousEnv = { ...process.env };

        const newLines = lines.map(line => {
            if (line.trim() === '' || line.trim().startsWith('#')) {
                return line;
            }
            const [key] = line.split('=');
            if (updatedKeys.has(key)) {
                updatedKeys.delete(key);
                return `${key}="${newValues[key]}"`;
            }
            return line;
        });

        // Add any new keys that weren't in the file
        updatedKeys.forEach(key => {
            newLines.push(`${key}="${newValues[key]}"`);
        });

        const newContent = newLines.join('\n');

        // Create a backup of the current .env file
        const backupPath = '.env.backup';
        await fsp.writeFile(backupPath, content, 'utf-8');
        logger.debug('Created .env backup file', {
            action: 'env_backup',
            path: backupPath
        });

        // Write the new content
        await fsp.writeFile('.env', newContent, 'utf-8');

        // Update process.env for the current running instance
        Object.assign(process.env, newValues);

        // Log successful environment update with changes
        logger.info('Environment updated successfully', {
            action: 'env_update_success',
            changes: Object.keys(newValues).map(key => {
                const isSensitive = key.toLowerCase().includes('token') || 
                                  key.toLowerCase().includes('password') || 
                                  key.toLowerCase().includes('secret') ||
                                  key.toLowerCase().includes('apikey');
                return {
                    key,
                    type: isSensitive ? 'sensitive' : 'regular',
                    changed: previousEnv[key] !== newValues[key]
                };
            })
        });
    } catch (error) {
        logger.error('Failed to update environment', {
            action: 'env_update_error',
            error: error.message,
            stack: error.stack
        });
        throw error;
    }
}

/**
 * Reads the config.json file.
 */
async function readConfig() {
    const content = await fsp.readFile('./config.json', 'utf-8');
    return JSON.parse(content);
}

/**
 * Writes to the config.json file using a safe, atomic write process.
 * Creates a temporary file and renames it to avoid partial writes.
 * Updates the in-memory config object after successful write.
 * 
 * @param {object} newConfig - The new configuration object to write.
 * @throws {Error} If file operations fail or if JSON serialization fails.
 * @example
 * await writeConfig({
 *   mediaServers: [{
 *     name: 'MainPlex',
 *     type: 'plex',
 *     enabled: true
 *   }],
 *   clockWidget: true
 * });
 */
async function writeConfig(newConfig) {
    // Log configuration change attempt
    logger.info('Configuration update initiated', {
        action: 'config_update',
        changes: Object.keys(newConfig).filter(key => !key.startsWith('_'))
    });

    // Remove metadata before writing
    delete newConfig._metadata;
    const newContent = JSON.stringify(newConfig, null, 2);
    const tempPath = './config.json.tmp';
    const finalPath = './config.json';

    try {
        // Write to a temporary file first
        await fsp.writeFile(tempPath, newContent, 'utf-8');
        
        // Log backup creation
        logger.debug('Created temporary config backup', {
            action: 'config_backup',
            tempPath
        });

        // Atomically rename the temp file to the final file
        await fsp.rename(tempPath, finalPath);
        
        // Update the in-memory config for the current running instance
        const previousConfig = { ...config };
        Object.assign(config, newConfig);

        // Log successful configuration change with detailed diff
        logger.info('Configuration updated successfully', {
            action: 'config_update_success',
            changes: Object.keys(newConfig).reduce((acc, key) => {
                if (!key.startsWith('_') && JSON.stringify(newConfig[key]) !== JSON.stringify(previousConfig[key])) {
                    acc[key] = {
                        previous: previousConfig[key],
                        new: newConfig[key]
                    };
                }
                return acc;
            }, {})
        });
    } catch (error) {
        logger.error('Failed to update configuration', {
            action: 'config_update_error',
            error: error.message,
            stack: error.stack
        });

        // Attempt to clean up the temporary file on error
        try {
            await fsp.unlink(tempPath);
            logger.debug('Cleaned up temporary config file after error', {
                action: 'config_cleanup',
                tempPath
            });
        } catch (cleanupError) {
            logger.warn('Failed to clean up temporary config file', {
                action: 'config_cleanup_error',
                error: cleanupError.message
            });
        }
        throw error; // Re-throw the original error
    }
}

/**
 * Checks if the admin user has been set up.
 */
function isAdminSetup() {
    return !!process.env.ADMIN_USERNAME && !!process.env.ADMIN_PASSWORD_HASH;
}

// --- Admin Panel Routes ---

/**
 * @swagger
 * /admin:
 *   get:
 *     summary: Admin panel homepage
 *     description: Serves the main admin panel interface. Redirects to setup if not configured, requires authentication.
 *     tags: [Admin Panel]
 *     responses:
 *       200:
 *         description: Admin panel served successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *       302:
 *         description: Redirects to setup page if admin not configured
 *       401:
 *         description: Authentication required
 */
app.get('/admin', (req, res) => {
    if (!isAdminSetup()) {
        return res.redirect('/admin/setup');
    }
    // If setup is done, the isAuthenticated middleware will handle the rest
    isAuthenticated(req, res, () => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
});

/**
 * @swagger
 * /admin/logs:
 *   get:
 *     summary: Admin logs viewer
 *     description: Serves the live log viewer page for administrators
 *     tags: [Admin Panel]
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Logs viewer page served successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *       401:
 *         description: Authentication required
 */
app.get('/admin/logs', isAuthenticated, (req, res) => {
    // This route serves the dedicated live log viewer page.
    res.sendFile(path.join(__dirname, 'public', 'logs.html'));
});

// --- API Endpoints ---

/**
 * @swagger
 * components:
 *   schemas:
 *     HealthCheckResult:
 *       type: object
 *       properties:
 *         name:
 *           type: string
 *           description: The name of the check performed
 *           example: "Connection: Plex Server (plex)"
 *         status:
 *           type: string
 *           enum: [ok, warn, error]
 *           description: The status of the check
 *           example: "ok"
 *         message:
 *           type: string
 *           description: A descriptive message about the check result
 *           example: "Connection successful"
 *     HealthCheckResponse:
 *       type: object
 *       required: [status, timestamp, checks]
 *       properties:
 *         status:
 *           type: string
 *           enum: [ok, error]
 *           description: Overall health status of the application
 *           example: "ok"
 *         timestamp:
 *           type: string
 *           format: date-time
 *           description: Timestamp when the health check was performed
 *           example: "2025-07-27T12:00:00Z"
 *         checks:
 *           type: array
 *           description: List of individual health check results
 *           items:
 *             $ref: '#/components/schemas/HealthCheckResult'
 * /api/health:
 *   get:
 *     summary: Application Health Check
 *     description: >
 *       Performs comprehensive health checks of the application, including configuration validation
 *       and connectivity tests for all configured media servers. The response includes detailed
 *       status information for each component. Returns a 200 OK status if all critical checks pass,
 *       and a 503 Service Unavailable if any critical check fails. Some non-critical warnings
 *       (like having no media servers enabled) will not cause a 503 status.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: All systems are operational.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthCheckResponse'
 *       503:
 *         description: One or more systems are not operational.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthCheckResponse'
 */
// Import health check utilities
const { getBasicHealth, getDetailedHealth } = require('./utils/healthCheck');

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Basic Health Check
 *     description: >
 *       Simple health check endpoint for basic monitoring and load balancers.
 *       Always returns 200 OK if the service is running, along with basic
 *       service information like version and uptime.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: Service is running
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/BasicHealthResponse'
 */
app.get('/health', (req, res) => {
    const health = getBasicHealth();
    res.json(health);
});

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Detailed Health Check
 *     description: >
 *       Comprehensive health check that validates configuration, filesystem access,
 *       media cache status, and connectivity to configured media servers. This endpoint
 *       performs actual connectivity tests and may take longer to respond. Results are
 *       cached for 30 seconds to improve performance.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: Health check completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthCheckResponse'
 */
app.get('/api/health', asyncHandler(async (req, res) => {
    const health = await getDetailedHealth();
    
    // Always return 200 for health checks - let the consumer decide based on status
    res.status(200).json(health);
}));

/**
 * @swagger
 * /health/detailed:
 *   get:
 *     summary: Detailed Health Check (Alternative endpoint)
 *     description: >
 *       Alternative endpoint for comprehensive health check that validates configuration, 
 *       filesystem access, media cache status, and connectivity to configured media servers. 
 *       This endpoint provides the same functionality as /api/health but is available at 
 *       /health/detailed for compatibility purposes.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: Health check completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthCheckResponse'
 */
app.get('/health/detailed', asyncHandler(async (req, res) => {
    const health = await getDetailedHealth();
    
    // Always return 200 for health checks - let the consumer decide based on status
    res.status(200).json(health);
}));

/**
 * @swagger
 * /get-config:
 *   get:
 *     summary: Retrieve the public application configuration
 *     description: >
 *       Fetches the non-sensitive configuration needed by the frontend for display logic.
 *       This endpoint is also accessible via the versioned API at /api/v1/config.
 *       The response is cached for 10 minutes to improve performance.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: The public configuration object.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Config'
 */
app.get('/get-config', 
    cacheMiddleware({
        ttl: 600000, // 10 minutes
        cacheControl: 'public, max-age=600',
        varyHeaders: ['Accept-Encoding']
    }),
    (req, res) => {
        res.json({
            clockWidget: config.clockWidget !== false,
            transitionIntervalSeconds: config.transitionIntervalSeconds || 15,
            backgroundRefreshMinutes: config.backgroundRefreshMinutes || 30,
            showClearLogo: config.showClearLogo !== false,
            showPoster: config.showPoster !== false,
            showMetadata: config.showMetadata === true,
            showRottenTomatoes: config.showRottenTomatoes !== false,
            rottenTomatoesMinimumScore: config.rottenTomatoesMinimumScore || 0,
            kenBurnsEffect: config.kenBurnsEffect || { enabled: true, durationSeconds: 20 }
        });
    });

/**
 * @swagger
 * /get-media:
 *   get:
 *     summary: Retrieve the shuffled media playlist
 *     description: >
 *       Returns an array of media items from all configured and enabled media servers.
 *       This endpoint is also accessible via the versioned API at /api/v1/media.
 *       The response is served from an in-memory cache that is periodically refreshed
 *       in the background. If the cache is empty (e.g., on first startup), returns
 *       a 202 Accepted response while the playlist is being built. If no media servers
 *       are configured or the initial fetch fails, returns a 503 Service Unavailable.
 *       The playlist is shuffled to ensure random playback order.
 *     tags: [Public API]
 *     responses:
 *       200:
 *         description: An array of media items.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/MediaItem'
 *       202:
 *         description: The playlist is being built, please try again.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiMessage'
 *       503:
 *         description: Service unavailable. The initial media fetch may have failed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiMessage'
 */
app.get('/get-media', 
    cacheMiddleware({
        ttl: 300000, // 5 minutes
        cacheControl: 'public, max-age=300',
        varyHeaders: ['Accept-Encoding']
    }),
    asyncHandler(async (req, res) => {
        // Skip caching if nocache param is present (for admin invalidation)
        if (req.query.nocache === '1') {
            res.setHeader('Cache-Control', 'no-store');
        }

        // If the cache is not null, it means the initial fetch has completed (even if it found no items).
        // An empty array is a valid state if no servers are configured or no media is found.
        if (playlistCache !== null) {
            const itemCount = playlistCache.length;
            if (isDebug) console.log(`[Debug] Serving ${itemCount} items from cache. Cache is ${itemCount > 0 ? 'populated' : 'empty'}.`);
            return res.json(playlistCache);
        }

        if (isRefreshing) {
            // The full cache is being built. Tell the client to wait and try again.
            if (isDebug) console.log('[Debug] Cache is empty but refreshing. Sending 202 Accepted.');
            // 202 Accepted is appropriate here: the request is accepted, but processing is not complete.
            return res.status(202).json({
                status: 'building',
                message: 'Playlist is being built. Please try again in a few seconds.',
                retryIn: 2000 // Suggest a 2-second polling interval
        });
    }

    // If we get here, the cache is empty and we are not refreshing, which means the initial fetch failed.
    if (isDebug) console.log('[Debug] Cache is empty and not refreshing. Sending 503 Service Unavailable.');
    return res.status(503).json({
        status: 'failed',
        error: "Media playlist is currently unavailable. The initial fetch may have failed. Check server logs."
    });
}));

/**
 * @swagger
 * /get-media-by-key/{key}:
 *   get:
 *     summary: Retrieve a single media item by its unique key
 *     description: Fetches the full details for a specific media item, typically used when a user clicks on a 'recently added' item that isn't in the main playlist.
 *     tags: [Public API]
 *     parameters:
 *       - in: path
 *         name: key
 *         required: true
 *         schema:
 *           type: string
 *         description: The unique key of the media item (e.g., plex-MyPlex-12345).
 *     responses:
 *       200:
 *         description: The requested media item.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/MediaItem'
 *       404:
 *         description: Media item not found.
 */
app.get('/get-media-by-key/:key', asyncHandler(async (req, res) => {
    const keyParts = req.params.key.split('-'); // e.g., ['plex', 'My', 'Server', '12345']
    if (keyParts.length < 3) { // Must have at least type, name, and key
        throw new ApiError(400, 'Invalid media key format.');
    }
    const type = keyParts.shift();
    const originalKey = keyParts.pop();
    const serverName = keyParts.join('-'); // Re-join the middle parts
    const serverConfig = config.mediaServers.find(s => s.name === serverName && s.type === type && s.enabled === true);

    if (!serverConfig) {
        throw new NotFoundError('Server configuration not found for this item.');
    }

    let mediaItem = null;
    if (type === 'plex') {
        const plex = getPlexClient(serverConfig);
        mediaItem = await processPlexItem({ key: `/library/metadata/${originalKey}` }, serverConfig, plex);
    }
    if (mediaItem) {
        res.json(mediaItem);
    } else {
        throw new NotFoundError('Media not found or could not be processed.');
    }
}));

/**
 * @swagger
 * /image:
 *   get:
 *     summary: Image proxy
 *     description: Proxies image requests to the media server (Plex/Jellyfin) to avoid exposing server details and tokens to the client.
 *     tags: [Public API]
 *     parameters:
 *       - in: query
 *         name: server
 *         required: true
 *         schema:
 *           type: string
 *         description: The name of the server config from config.json.
 *       - in: query
 *         name: path
 *         required: true
 *         schema:
 *           type: string
 *         description: The image path from the media item object (e.g., /library/metadata/12345/art/...).
 *     responses:
 *       200:
 *         description: The requested image.
 *         content:
 *           image/*: {}
 *       400:
 *         description: Bad request, missing parameters.
 *       302:
 *         description: Redirects to a fallback image on error.
 */
app.get('/image', 
    cacheMiddleware({
        ttl: 86400000, // 24 hours
        cacheControl: 'public, max-age=86400',
        varyHeaders: ['Accept-Encoding'],
        keyGenerator: (req) => `image:${req.query.server}-${req.query.path}`
    }),
    asyncHandler(async (req, res) => {
    const imageCacheDir = path.join(__dirname, 'image_cache');
    const { server: serverName, path: imagePath } = req.query;

    if (isDebug) {
        console.log(`[Image Proxy] Request for image received. Server: "${serverName}", Path: "${imagePath}"`);
    }

    if (!serverName || !imagePath) {
        if (isDebug) console.log('[Image Proxy] Bad request: server name or image path is missing.');
        return res.status(400).send('Server name or image path is missing');
    }

    // Create a unique and safe filename for the cache
    const cacheKey = `${serverName}-${imagePath}`;
    const cacheHash = crypto.createHash('sha256').update(cacheKey).digest('hex');
    const fileExtension = path.extname(imagePath) || '.jpg'; // Fallback extension
    const cachedFilePath = path.join(imageCacheDir, `${cacheHash}${fileExtension}`);

    // 1. Check if file exists in cache
    try {
        await fsp.access(cachedFilePath);
        if (isDebug) console.log(`[Image Cache] HIT: Serving "${imagePath}" from cache file: ${cachedFilePath}`);
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 24 hours
        return res.sendFile(cachedFilePath);
    } catch (e) {
        // File does not exist, proceed to fetch
        if (isDebug) console.log(`[Image Cache] MISS: "${imagePath}". Fetching from origin.`);
    }

    // 2. Fetch from origin if not in cache
    const serverConfig = config.mediaServers.find(s => s.name === serverName);
    if (!serverConfig) {
        console.error(`[Image Proxy] Server configuration for "${serverName}" not found. Cannot process image request.`);
        return res.redirect('/fallback-poster.png');
    }

    let imageUrl, fetchOptions = { method: 'GET', headers: {} };

    if (serverConfig.type === 'plex') {
        const token = process.env[serverConfig.tokenEnvVar];
        if (!token) {
            console.error(`[Image Proxy] Plex token not configured for server "${serverName}" (env var: ${serverConfig.tokenEnvVar}).`);
            return res.redirect('/fallback-poster.png');
        }
        const hostname = process.env[serverConfig.hostnameEnvVar];
        const port = process.env[serverConfig.portEnvVar];
        imageUrl = `http://${hostname}:${port}${imagePath}`;
        fetchOptions.headers['X-Plex-Token'] = token;
    } else {
        console.error(`[Image Proxy] Unsupported server type "${serverConfig.type}" for server "${serverName}".`);
        return res.redirect('/fallback-poster.png');
    }

    if (isDebug) console.log(`[Image Proxy] Fetching from origin URL: ${imageUrl}`);

    try {
        const mediaServerResponse = await fetch(imageUrl, fetchOptions);

        if (!mediaServerResponse.ok) {
            console.warn(`[Image Proxy] Media server "${serverName}" returned status ${mediaServerResponse.status} for path "${imagePath}".`);
            console.warn(`[Image Proxy] Serving fallback image for "${imagePath}".`);
            return res.redirect('/fallback-poster.png');
        }

        // Set headers on the client response
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 86400 seconds = 24 hours
        const contentType = mediaServerResponse.headers.get('content-type');
        res.setHeader('Content-Type', contentType || 'image/jpeg');

        // 3. Pipe the response to both the client and the cache file
        const passthrough = new PassThrough();
        mediaServerResponse.body.pipe(passthrough);

        const fileStream = fs.createWriteStream(cachedFilePath);
        passthrough.pipe(fileStream);
        passthrough.pipe(res);

        fileStream.on('finish', () => {
            if (isDebug) console.log(`[Image Cache] SUCCESS: Saved "${imagePath}" to cache: ${cachedFilePath}`);
        });

        fileStream.on('error', (err) => {
            console.error(`[Image Cache] ERROR: Failed to write to cache file ${cachedFilePath}:`, err);
            // If caching fails, the user still gets the image, so we just log the error.
            // We should also clean up the potentially partial file.
            fsp.unlink(cachedFilePath).catch(unlinkErr => {
                console.error(`[Image Cache] Failed to clean up partial cache file ${cachedFilePath}:`, unlinkErr);
            });
        });

    } catch (error) {
        console.error(`[Image Proxy] Network or fetch error for path "${imagePath}" on server "${serverName}".`);

        if (error.name === 'AbortError') {
             console.error(`[Image Proxy] Fetch aborted, possibly due to timeout.`);
        } else if (error.message.startsWith('read ECONNRESET')) {
            console.error(`[Image Proxy] Connection reset by peer. The media server may have closed the connection unexpectedly.`);
        }

        console.error(`[Image Proxy] Error: ${error.message}`);
        if (error.cause) console.error(`[Image Proxy] Cause: ${error.cause}`);
        console.warn(`[Image Proxy] Serving fallback image for "${imagePath}".`);
        res.redirect('/fallback-poster.png');
    }
}));

/**
 * @swagger
 * /admin/setup:
 *   get:
 *     summary: Admin setup page
 *     description: Serves the initial admin setup page if no admin user exists, otherwise redirects to admin panel
 *     tags: [Admin Setup]
 *     responses:
 *       200:
 *         description: Setup page served successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *       302:
 *         description: Redirects to admin panel if setup is already complete
 */
app.get('/admin/setup', (req, res) => {
    if (isAdminSetup()) {
        return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

/**
 * @swagger
 * /admin/setup:
 *   post:
 *     summary: Complete admin setup
 *     description: Creates the initial admin user account with username and password
 *     tags: [Admin Setup]
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: Admin username
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Admin password
 *     responses:
 *       200:
 *         description: Admin setup completed successfully
 *       400:
 *         description: Missing username or password
 *       403:
 *         description: Admin user already configured
 */
app.post('/admin/setup', express.urlencoded({ extended: true }), asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin Setup] Received setup request.');
    if (isAdminSetup()) {
        if (isDebug) console.log('[Admin Setup] Aborted: Admin user is already configured.');
        throw new ApiError(403, 'Admin user is already configured.');
    }
    
    const { username, password } = req.body;
    if (!username || !password) {
        if (isDebug) console.log('[Admin Setup] Aborted: Username or password missing.');
        throw new ApiError(400, 'Username and password are required.');
    }
    
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const sessionSecret = require('crypto').randomBytes(32).toString('hex');
    
    // 2FA can be enabled from the admin panel after the first login.
    await writeEnvFile({
        ADMIN_USERNAME: username,
        ADMIN_PASSWORD_HASH: passwordHash,
        SESSION_SECRET: sessionSecret,
        ADMIN_2FA_SECRET: '' // Explicitly set to empty to ensure 2FA is off by default
    });
    
    if (isDebug) console.log(`[Admin Setup] Successfully created admin user "${username}". 2FA is not enabled by default.`);
    
    res.send('Setup complete! You can now log in. You will be redirected shortly. <script>setTimeout(() => window.location.href="/admin/login", 3000);</script>');
}));

/**
 * @swagger
 * /admin/login:
 *   get:
 *     summary: Admin login page
 *     description: Serves the admin login page, redirects to setup if admin not configured, or to admin panel if already logged in
 *     tags: [Admin Authentication]
 *     responses:
 *       200:
 *         description: Login page served successfully
 *         content:
 *           text/html:
 *             schema:
 *               type: string
 *       302:
 *         description: Redirects to setup page or admin panel as appropriate
 */
app.get('/admin/login', (req, res) => {
    if (!isAdminSetup()) {
        return res.redirect('/admin/setup');
    }
    if (req.session.user) {
        return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Apply rate limiting to protect against brute-force password attacks.
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // Limit each IP to 10 login requests per windowMs
	standardHeaders: true,
	legacyHeaders: false,
    message: (req, res) => {
        // This ensures we still send a user-friendly HTML error page
        throw new ApiError(429, 'Too many login attempts from this IP, please try again after 15 minutes. <a href="/admin/login">Try again</a>.');
    },
});

/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Admin login authentication
 *     description: Authenticate admin user with username and password. May require 2FA verification if enabled.
 *     tags: [Admin Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: Admin username
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Admin password
 *     responses:
 *       200:
 *         description: Login successful (may redirect to 2FA verification)
 *       401:
 *         description: Invalid username or password
 *       429:
 *         description: Too many login attempts
 */
app.post('/admin/login', loginLimiter, express.urlencoded({ extended: true }), asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    if (isDebug) console.log(`[Admin Login] Attempting login for user "${username}".`);

    const isValidUser = (username === process.env.ADMIN_USERNAME);
    if (!isValidUser) {
        if (isDebug) console.log(`[Admin Login] Login failed for user "${username}". Invalid username.`);
        throw new ApiError(401, 'Invalid username or password. <a href="/admin/login">Try again</a>.');
    }

    const isValidPassword = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!isValidPassword) {
        if (isDebug) console.log(`[Admin Login] Login failed for user "${username}". Invalid credentials.`);
        throw new ApiError(401, 'Invalid username or password. <a href="/admin/login">Try again</a>.');
    }

    // --- Check if 2FA is enabled ---
    const secret = process.env.ADMIN_2FA_SECRET || '';
    const is2FAEnabled = secret.trim() !== '';

    if (is2FAEnabled) {
        // User is valid, but needs to provide a 2FA code.
        // Set a temporary flag in the session.
        req.session.tfa_required = true;
        req.session.tfa_user = { username: username }; // Store user info temporarily
        if (isDebug) console.log(`[Admin Login] Credentials valid for "${username}". Redirecting to 2FA verification.`);
        res.redirect('/admin/2fa-verify');
    } else {
        // No 2FA, log the user in directly.
        req.session.user = { username: username };
        if (isDebug) console.log(`[Admin Login] Login successful for user "${username}". Redirecting to admin panel.`);
        res.redirect('/admin');
    }
}));

app.get('/admin/2fa-verify', (req, res) => {
    // Only show this page if the user has passed the first step of login.
    if (!req.session.tfa_required) {
        return res.redirect('/admin/login');
    }
    res.sendFile(path.join(__dirname, 'public', '2fa-verify.html'));
});

// Apply a stricter rate limit for 2FA code attempts.
const twoFaLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 5, // Limit each IP to 5 verification requests per windowMs
	standardHeaders: true,
	legacyHeaders: false,
    message: (req, res) => {
        // Redirecting with an error is better UX for this form.
        res.redirect('/admin/2fa-verify?error=rate_limited');
    },
});


app.post('/admin/2fa-verify', twoFaLimiter, express.urlencoded({ extended: true }), asyncHandler(async (req, res) => {
    const { totp_code } = req.body;

    if (!req.session.tfa_required || !req.session.tfa_user) {
        if (isDebug) console.log('[Admin 2FA Verify] 2FA verification attempted without prior password validation. Redirecting to login.');
        return res.redirect('/admin/login');
    }

    const secret = process.env.ADMIN_2FA_SECRET || '';
    const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token: totp_code, window: 1 });

    if (verified) {
        req.session.user = { username: req.session.tfa_user.username };
        delete req.session.tfa_required;
        delete req.session.tfa_user;
        if (isDebug) console.log(`[Admin 2FA Verify] 2FA verification successful for user "${req.session.user.username}".`);
        res.redirect('/admin');
    } else {
        if (isDebug) console.log(`[Admin 2FA Verify] Invalid 2FA code for user "${req.session.tfa_user.username}".`);
        // Redirect back to the verification page with an error query parameter
        // for a better user experience than a generic error page.
        res.redirect('/admin/2fa-verify?error=invalid_code');
    }
}));

/**
 * @swagger
 * /admin/logout:
 *   get:
 *     summary: Admin logout
 *     description: Logs out the admin user by destroying their session and redirects to login page
 *     tags: [Admin Authentication]
 *     responses:
 *       302:
 *         description: Session destroyed, redirects to login page
 *       500:
 *         description: Error destroying session
 */
app.get('/admin/logout', (req, res, next) => {
    if (isDebug) console.log(`[Admin Logout] User "${req.session.user?.username}" logging out.`);
    req.session.destroy(err => {
        if (err) {
            if (isDebug) console.error('[Admin Logout] Error destroying session:', err);
            return next(new ApiError(500, 'Could not log out.'));
        }
        if (isDebug) console.log('[Admin Logout] Session destroyed successfully.');
        res.redirect('/admin/login');
    });
});

/**
 * @swagger
 * /api/admin/2fa/generate:
 *   post:
 *     summary: Generate a new 2FA secret
 *     description: >
 *       Generates a new secret for Two-Factor Authentication (2FA) and returns a QR code
 *       that the user can scan with an authenticator app. The secret is temporarily stored in the session
 *       and only becomes permanent after successful verification.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: QR code and secret successfully generated.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Generate2FAResponse'
 *       400:
 *         description: 2FA is already enabled.
 *       401:
 *         description: Unauthorized.
 */
app.post('/api/admin/2fa/generate', isAuthenticated, asyncHandler(async (req, res) => {
    const secret = process.env.ADMIN_2FA_SECRET || '';
    const isEnabled = secret.trim() !== '';
    // Prevent generating a new secret if one is already active
    if (isEnabled) {
        throw new ApiError(400, '2FA is already enabled.');
    }

    const newSecret = speakeasy.generateSecret({
        length: 20,
        name: `posterrama.app (${req.session.user.username})`
    });

    // Store the new secret in the session, waiting for verification.
    // This is crucial so we don't lock the user out if they fail to verify.
    req.session.tfa_pending_secret = newSecret.base32;

    const qrCodeDataUrl = await qrcode.toDataURL(newSecret.otpauth_url);
    res.json({ qrCodeDataUrl });
}));

/**
 * @swagger
 * /api/admin/2fa/verify:
 *   post:
 *     summary: Verify and enable 2FA
 *     description: >
 *       Verifies the TOTP code entered by the user against the temporary secret in the session.
 *       Upon success, the 2FA secret is permanently stored in the .env file and 2FA is activated.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Verify2FARequest'
 *     responses:
 *       200:
 *         description: 2FA successfully enabled.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       400:
 *         description: Invalid verification code or no 2FA process pending.
 *       401:
 *         description: Niet geautoriseerd.
 */
app.post('/api/admin/2fa/verify', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    const { token } = req.body;
    const pendingSecret = req.session.tfa_pending_secret;

    if (!pendingSecret) {
        throw new ApiError(400, 'No 2FA setup process is pending. Please try again.');
    }

    const verified = speakeasy.totp.verify({
        secret: pendingSecret,
        encoding: 'base32',
        token: token,
        window: 1
    });

    if (verified) {
        // Verification successful, save the secret to the .env file
        await writeEnvFile({ ADMIN_2FA_SECRET: pendingSecret });
        
        // Clear the pending secret from the session
        delete req.session.tfa_pending_secret;

        if (isDebug) console.log(`[Admin 2FA] 2FA enabled successfully for user "${req.session.user.username}".`);
        res.json({ success: true, message: '2FA enabled successfully.' });
    } else {
        if (isDebug) console.log(`[Admin 2FA] 2FA verification failed for user "${req.session.user.username}".`);
        throw new ApiError(400, 'Invalid verification code. Please try again.');
    }
}));

/**
 * @swagger
 * /api/admin/2fa/disable:
 *   post:
 *     summary: Disable 2FA
 *     description: >
 *       Disables Two-Factor Authentication for the admin account.
 *       The user must provide their current password for confirmation.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Disable2FARequest'
 *     responses:
 *       200:
 *         description: 2FA successfully disabled.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       400:
 *         description: Password is required.
 *       401:
 *         description: Invalid password or unauthorized.
 */
app.post('/api/admin/2fa/disable', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    const { password } = req.body;
    if (!password) throw new ApiError(400, 'Password is required to disable 2FA.');
    const isValidPassword = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!isValidPassword) throw new ApiError(401, 'Incorrect password.');
    await writeEnvFile({ ADMIN_2FA_SECRET: '' });
    if (isDebug) console.log(`[Admin 2FA] 2FA disabled successfully for user "${req.session.user.username}".`);
    res.json({ success: true, message: '2FA disabled successfully.' });
}));

/**
 * @swagger
 * /api/admin/config:
 *   get:
 *     summary: Retrieve complete admin configuration
 *     description: >
 *       Retrieves the complete `config.json` along with relevant environment variables
 *       and security status (like 2FA) needed for the admin panel.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The configuration objects.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminConfigResponse'
 *       401:
 *         description: Unauthorized.
 */
app.get('/api/admin/config', isAuthenticated, asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Request received for /api/admin/config.');
    const currentConfig = await readConfig();
    if (isDebug) console.log('[Admin API] Successfully read config.json.');

    // WARNING: Exposing environment variables to the client can be a security risk.
    // This is done based on an explicit user request.
    const envVarsToExpose = {
        SERVER_PORT: process.env.SERVER_PORT,
        DEBUG: process.env.DEBUG
    };

    if (Array.isArray(currentConfig.mediaServers)) {
        currentConfig.mediaServers.forEach(server => {
            // Ensure server is a valid object before processing to prevent crashes
            if (server && typeof server === 'object') {
                // Find all keys ending in 'EnvVar' and get their values from process.env
                Object.keys(server).forEach(key => {
                    if (key.endsWith('EnvVar')) {
                        const envVarName = server[key];
                        if (envVarName) {
                            const isSensitive = key.toLowerCase().includes('token') || key.toLowerCase().includes('password') || key.toLowerCase().includes('apikey');
                            if (isSensitive) {
                                // For sensitive fields, just indicate if they are set or not.
                                envVarsToExpose[envVarName] = !!process.env[envVarName];
                            } else if (process.env[envVarName]) {
                                envVarsToExpose[envVarName] = process.env[envVarName];
                            }
                        }
                    }
                });
            }
        });
    }

    if (isDebug) console.log('[Admin API] Sending config and selected environment variables to client.');
    res.json({
        config: currentConfig,
        env: envVarsToExpose,
        security: { is2FAEnabled: !!(process.env.ADMIN_2FA_SECRET || '').trim() }
    });
}))

/**
 * @swagger
 * /api/admin/test-plex:
 *   post:
 *     summary: Test connection to a Plex server
 *     description: >
 *       Checks if the application can connect to a Plex server with the provided
 *       hostname, port, and token. This is a lightweight check that queries the server root.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/PlexConnectionRequest'
 *     responses:
 *       200:
 *         description: Connection successful.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       400:
 *         description: Connection error (e.g., incorrect credentials, timeout).
 */
app.post('/api/admin/test-plex', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to test Plex connection.');
    let { hostname, port, token } = req.body; // token is now optional

    if (!hostname || !port) {
        throw new ApiError(400, 'Hostname and port are required for the test.');
    }

    // Sanitize hostname to remove http(s):// prefix
    if (hostname) {
        hostname = hostname.trim().replace(/^https?:\/\//, '');
    }

    // If no token is provided in the request, use the one from the server's config.
    if (!token) {
        if (isDebug) console.log('[Plex Test] No token provided in request, attempting to use existing server token.');
        // Find the first enabled Plex server config. This assumes a single Plex server setup for now.
        const plexServerConfig = config.mediaServers.find(s => s.type === 'plex' && s.enabled);

        if (plexServerConfig && plexServerConfig.tokenEnvVar) {
            token = process.env[plexServerConfig.tokenEnvVar];
            if (!token) {
                throw new ApiError(400, 'Connection test failed: No new token was provided, and no token is configured on the server.');
            }
        } else {
            throw new ApiError(500, 'Connection test failed: Could not find Plex server configuration on the server.');
        }
    }

    try {
        const testClient = createPlexClient({
            hostname,
            port,
            token,
            timeout: 5000
        });
        // Querying the root is a lightweight way to check credentials and reachability.
        const result = await testClient.query('/');
        const serverName = result?.MediaContainer?.friendlyName;

        if (serverName) {
            res.json({ success: true, message: `Successfully connected to Plex server: ${serverName}` });
        } else {
            // This case is unlikely if the query succeeds, but good to handle.
            res.json({ success: true, message: 'Connection successful, but could not retrieve the server name.' });
        }
    } catch (error) {
        if (isDebug) console.error('[Plex Test] Connection failed:', error.message);
        let userMessage = 'Connection failed. Please check the hostname, port, and token.';
        if (error.code === 'ECONNREFUSED' || error.message.includes('ECONNREFUSED')) {
            userMessage = 'Connection refused. Is the hostname and port correct and is the server running?';
        } else if (error.message.includes('401 Unauthorized')) {
            userMessage = 'Connection failed: Unauthorized. Is the Plex token correct?';
        } else if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
            userMessage = 'Connection timed out. Is the server reachable? Check firewall settings.';
        }
        throw new ApiError(400, userMessage);
    }
}));



/**
 * @swagger
 * /api/admin/plex-libraries:
 *   post:
 *     summary: Retrieve Plex libraries
 *     description: >
 *       Retrieves a list of all available libraries (such as 'Movies', 'TV Shows')
 *       from the configured Plex server.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       description: Optional connection details. If not provided, the configured values will be used.
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/PlexConnectionRequest'
 *     responses:
 *       200:
 *         description: A list of found libraries.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PlexLibrariesResponse'
 *       400:
 *         description: Could not fetch libraries (e.g., incorrect credentials).
 */
app.post('/api/admin/plex-libraries', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to fetch Plex libraries.');
    let { hostname, port, token } = req.body;

    // Sanitize hostname
    if (hostname) {
        hostname = hostname.trim().replace(/^https?:\/\//, '');
    }

    // Fallback to configured values if not provided in the request
    const plexServerConfig = config.mediaServers.find(s => s.type === 'plex');
    if (!plexServerConfig) {
        throw new ApiError(500, 'Plex server is not configured in config.json.');
    }

    if (!hostname) {
        const envHostname = process.env[plexServerConfig.hostnameEnvVar];
        if (envHostname) hostname = envHostname.trim().replace(/^https?:\/\//, '');
    }
    port = port || process.env[plexServerConfig.portEnvVar];
    token = token || process.env[plexServerConfig.tokenEnvVar];

    if (!hostname || !port || !token) {
        throw new ApiError(400, 'Plex connection details (hostname, port, token) are missing.');
    }

    try {
        const client = createPlexClient({
            hostname,
            port,
            token,
            timeout: 10000
        });
        const sectionsResponse = await client.query('/library/sections');
        const allSections = sectionsResponse?.MediaContainer?.Directory || [];

        const libraries = allSections.map(dir => ({
            key: dir.key,
            name: dir.title,
            type: dir.type // 'movie', 'show', etc.
        }));

        res.json({ success: true, libraries });

    } catch (error) {
        if (isDebug) console.error('[Plex Lib Fetch] Failed:', error.message);
        let userMessage = 'Could not fetch libraries. Please check the connection details.';
        if (error.message.includes('401 Unauthorized')) {
            userMessage = 'Unauthorized. Is the Plex token correct?';
        } else if (error.code === 'ECONNREFUSED' || error.message.includes('ECONNREFUSED')) {
            userMessage = 'Connection refused. Is the hostname and port correct?';
        } else if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
            userMessage = 'Connection timeout. Is the server reachable?';
        } else if (error.message.includes('The string did not match the expected pattern')) {
            userMessage = 'Invalid hostname format. Use an IP address or hostname without http:// or https://.';
        }
        throw new ApiError(400, userMessage);
    }
}));

/**
 * @swagger
 * /api/admin/config:
 *   post:
 *     summary: Save the admin configuration
 *     description: >
 *       Saves the changes to both `config.json` and the `.env` file.
 *       After a successful save, the application caches and clients are cleared
 *       and a background refresh of the playlist is initiated.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SaveConfigRequest'
 *     responses:
 *       200:
 *         description: Configuration successfully saved.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       400:
 *         description: Invalid request body.
 *       401:
 *         description: Niet geautoriseerd.
 */
app.post('/api/admin/config', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    if (isDebug) {
        console.log('[Admin API] Received POST request to /api/admin/config to save settings. Body:', JSON.stringify(req.body, null, 2));
    }
    const { config: newConfig, env: newEnv } = req.body;

    if (!newConfig || !newEnv) {
        if (isDebug) console.log('[Admin API] Invalid request body. Missing "config" or "env".');
        throw new ApiError(400, 'Invalid request body. "config" and "env" properties are required.');
    }

    // Write to config.json and .env
    await writeConfig(newConfig);
    if (isDebug) console.log('[Admin API] Successfully wrote to config.json.');
    await writeEnvFile(newEnv);
    if (isDebug) console.log('[Admin API] Successfully wrote to .env file.');

    // Clear caches to reflect changes without a full restart
    playlistCache = null;
    Object.keys(plexClients).forEach(key => delete plexClients[key]);

    // Trigger a background refresh of the playlist with the new settings.
    // We don't await this, so the admin UI gets a fast response.
    refreshPlaylistCache();

    if (isDebug) {
        console.log('[Admin] Configuration saved successfully. Caches and clients have been cleared. Triggered background playlist refresh.');
    }

    res.json({ message: 'Configuration saved successfully. Some changes may require an application restart.' });
}));

/**
 * @swagger
 * /api/admin/change-password:
 *   post:
 *     summary: Change the admin password
 *     description: Allows the user to change their own admin password.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ChangePasswordRequest'
 *     responses:
 *       200:
 *         description: Password successfully changed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       400:
 *         description: Required fields missing or new passwords do not match.
 *       401:
 *         description: Current password is incorrect.
 */
app.post('/api/admin/change-password', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to change password.');
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
        if (isDebug) console.log('[Admin API] Password change failed: missing fields.');
        throw new ApiError(400, 'All password fields are required.');
    }

    if (newPassword !== confirmPassword) {
        if (isDebug) console.log('[Admin API] Password change failed: new passwords do not match.');
        throw new ApiError(400, 'New password and confirmation do not match.');
    }

    const isValidPassword = await bcrypt.compare(currentPassword, process.env.ADMIN_PASSWORD_HASH);
    if (!isValidPassword) {
        if (isDebug) console.log('[Admin API] Password change failed: incorrect current password.');
        throw new ApiError(401, 'Incorrect current password.');
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await writeEnvFile({ ADMIN_PASSWORD_HASH: newPasswordHash });

    if (isDebug) console.log('[Admin API] Password changed successfully. Invalidating current session for security.');

    // For security, destroy the current session after a password change,
    // forcing the user to log in again with their new credentials.
    req.session.destroy(err => {
        if (err) {
            if (isDebug) console.error('[Admin API] Error destroying session after password change:', err);
            // Even if session destruction fails, the password change was successful.
            // We proceed but log the error.
        }
        res.json({ message: 'Password changed successfully. You have been logged out for security and will need to log in again.' });
    });
}));

/**
 * @swagger
 * /api/admin/restart-app:
 *   post:
 *     summary: Restart the application
 *     description: >
 *       Sends a command to PM2 to restart the application.
 *       This is useful after modifying critical settings such as the port.
 *       The API responds immediately with a 202 Accepted status.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       202:
 *         description: Restart command received and is being processed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 */
app.post('/api/admin/restart-app', isAuthenticated, asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to restart the application.');

    const appName = ecosystemConfig.apps[0].name || 'posterrama';
    if (isDebug) console.log(`[Admin API] Determined app name for PM2: "${appName}"`);

    // Immediately send a response to the client to avoid a race condition.
    // We use 202 Accepted, as the server has accepted the request but the action is pending.
    res.status(202).json({ success: true, message: 'Restart command received. The application is now restarting.' });

    // Execute the restart command after a short delay to ensure the HTTP response has been sent.
    setTimeout(() => {
        if (isDebug) console.log(`[Admin API] Executing command: "pm2 restart ${appName}"`);
        exec(`pm2 restart ${appName}`, (error, stdout, stderr) => {
            // We can't send a response here, but we can log the outcome for debugging.
            if (error) {
                console.error(`[Admin API] PM2 restart command failed after response was sent.`);
                console.error(`[Admin API] Error: ${error.message}`);
                if (stderr) console.error(`[Admin API] PM2 stderr: ${stderr}`);
                return;
            }
            if (isDebug) console.log(`[Admin API] PM2 restart command issued successfully for '${appName}'.`);
        });
    }, 100); // 100ms delay should be sufficient.
}));

/**
 * @swagger
 * /api/admin/refresh-media:
 *   post:
 *     summary: Force an immediate refresh of the media playlist
 *     description: >
 *       Manually starts the process to fetch media from all configured servers.
 *       This is an asynchronous operation. The API responds when the refresh is complete.
 *       This endpoint is secured and requires an active admin session.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The playlist has been successfully refreshed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RefreshMediaResponse'
 */
app.post('/api/admin/refresh-media', isAuthenticated, asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to force-refresh media playlist.');

    // Clear media cache before refreshing
    const cleared = cacheManager.clear('media');
    logger.info('Media cache cleared before refresh', { cleared });

    // The refreshPlaylistCache function already has a lock (isRefreshing)
    // so we can call it directly. We'll await it to give feedback to the user.
    await refreshPlaylistCache();

    const itemCount = playlistCache ? playlistCache.length : 0;
    const message = `Media playlist successfully refreshed. ${itemCount} items found. Cache cleared: ${cleared} entries.`;
    if (isDebug) console.log(`[Admin API] ${message}`);

    res.json({ success: true, message: message, itemCount: itemCount, cacheCleared: cleared });
}));

/**
 * @swagger
 * /api/admin/clear-image-cache:
 *   post:
 *     summary: Clear the server-side image cache
 *     description: >
 *       Deletes all cached images from the `image_cache` directory on the server.
 *       This forces the application to re-fetch all images from the origin media servers.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The image cache was successfully cleared.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 */
app.post('/api/admin/clear-image-cache', isAuthenticated, asyncHandler(async (req, res) => {
    if (isDebug) console.log('[Admin API] Received request to clear image cache.');
    const imageCacheDir = path.join(__dirname, 'image_cache');
    let clearedCount = 0;

    try {
        const files = await fsp.readdir(imageCacheDir);
        const unlinkPromises = files.map(file =>
            fsp.unlink(path.join(imageCacheDir, file))
        );
        await Promise.all(unlinkPromises);
        clearedCount = files.length;
        if (isDebug) console.log(`[Admin API] Successfully cleared ${clearedCount} files from the image cache.`);
        res.json({ success: true, message: `Successfully cleared ${clearedCount} cached images.` });
    } catch (error) {
        console.error('[Admin API] Error clearing image cache:', error);
        throw new ApiError(500, 'Failed to clear image cache. Check server logs for details.');
    }
}));

/**
 * @swagger
 * /api/v1/admin/cache/clear:
 *   post:
 *     summary: Clear application cache
 *     description: Clears the application cache, optionally for specific types of content
 *     tags: [Admin API]
 *     security:
 *       - sessionAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [media, config, image, all]
 *                 description: The type of cache to clear (defaults to 'all')
 *     responses:
 *       200:
 *         description: Cache cleared successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 */
app.post('/api/v1/admin/cache/clear', isAuthenticated, express.json(), asyncHandler(async (req, res) => {
    const { type = 'all' } = req.body;
    
    if (isDebug) console.log('[Admin API] Received request to clear cache', { type });
    
    let cleared = 0;
    let message = '';

    try {
        switch (type) {
            case 'media':
                cleared = cacheManager.clear('media');
                message = `Cleared ${cleared} media cache entries`;
                break;
            case 'config':
                cleared = cacheManager.clear('config');
                message = `Cleared ${cleared} config cache entries`;
                break;
            case 'image':
                cleared = cacheManager.clear('image');
                // Also clear filesystem image cache
                const imageCacheDir = path.join(__dirname, 'image_cache');
                try {
                    const files = await fsp.readdir(imageCacheDir);
                    const unlinkPromises = files.map(file =>
                        fsp.unlink(path.join(imageCacheDir, file))
                    );
                    await Promise.all(unlinkPromises);
                    message = `Cleared ${cleared} image cache entries and ${files.length} cached image files`;
                } catch (err) {
                    logger.warn('Could not clear filesystem image cache', { error: err.message });
                    message = `Cleared ${cleared} image cache entries (filesystem cache unchanged)`;
                }
                break;
            case 'all':
            default:
                cleared = cacheManager.clear();
                message = `Cleared all ${cleared} cache entries`;
                break;
        }

        logger.info('Cache cleared by admin', { type, cleared });
        
        res.json({ 
            success: true, 
            message,
            cleared,
            type 
        });
    } catch (error) {
        logger.error('Failed to clear cache', { type, error: error.message });
        throw new ApiError(500, 'Failed to clear cache. Check server logs for details.');
    }
}));

/**
 * @swagger
 * /api/admin/api-key:
 *   get:
 *     summary: Get the current API key
 *     description: Retrieves the currently configured API access key. This is only returned to an authenticated admin session.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The API key.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 apiKey:
 *                   type: string
 *                   nullable: true
 */
app.get('/api/admin/api-key', isAuthenticated, (req, res) => {
    const apiKey = process.env.API_ACCESS_TOKEN || null;
    res.json({ apiKey });
});
/**
 * @swagger
 * /api/admin/api-key/status:
 *   get:
 *     summary: Check the API key status
 *     description: Indicates whether an API access key is currently configured in the application.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The API key status.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hasKey:
 *                   type: boolean
 *                   description: Whether an API key is currently configured.
 *                   example: true
 */
app.get('/api/admin/api-key/status', isAuthenticated, (req, res) => {
    const hasKey = !!(process.env.API_ACCESS_TOKEN || '').trim();
    res.json({ hasKey });
});

/**
 * @swagger
 * /api/admin/api-key/generate:
 *   post:
 *     summary: Generate a new API key
 *     description: >
 *       Generates a new, cryptographically secure API access token and stores it in the .env file
 *       and overwrites any existing key. The new key is returned ONCE ONLY.
 *       Store it securely, as it cannot be retrieved again.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The newly generated API key.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiKeyResponse'
 */
app.post('/api/admin/api-key/generate', isAuthenticated, asyncHandler(async (req, res) => {
    const newApiKey = crypto.randomBytes(32).toString('hex');
    await writeEnvFile({ API_ACCESS_TOKEN: newApiKey });
    if (isDebug) console.log('[Admin API] New API Access Token generated and saved.');
    res.json({ apiKey: newApiKey, message: 'New API key generated. This is the only time it will be shown. Please save it securely.' });
}));

/**
 * @swagger
 * /api/admin/api-key/revoke:
 *   post:
 *     summary: Revoke current API key
 *     description: Removes the current API access token from the configuration, making it unusable.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Confirmation that the key has been revoked.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminApiResponse'
 */
app.post('/api/admin/api-key/revoke', isAuthenticated, asyncHandler(async (req, res) => {
    await writeEnvFile({ API_ACCESS_TOKEN: '' });
    if (isDebug) console.log('[Admin API] API Access Token has been revoked.');
    res.json({ success: true, message: 'API key has been revoked.' });
}));

/**
 * @swagger
 * /api/admin/logs:
 *   get:
 *     summary: Get the most recent application logs
 *     description: >
 *       Retrieves a list of the most recent log entries stored in memory.
 *       This is useful for debugging from the admin panel without direct server access.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: An array of log objects.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/LogEntry'
 */
app.get('/api/admin/logs', isAuthenticated, (req, res) => {
    const { level, limit } = req.query;
    res.setHeader('Cache-Control', 'no-store'); // Prevent browser caching of log data
    res.json(logger.getRecentLogs(level, parseInt(limit) || 200));
});

/**
 * @swagger
 * /admin/debug:
 *   get:
 *     summary: Retrieve debug information
 *     description: >
 *       Returns the raw data of all items in the current *cached* playlist.
 *       This endpoint is only available when debug mode is enabled in the .env file.
 *     tags: [Admin API]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The raw data from the playlist.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DebugResponse'
 *       404:
 *         description: Not found (if debug mode is disabled).
 */
app.get('/admin/debug', isAuthenticated, asyncHandler(async (req, res) => {
    if (!isDebug) {
        throw new NotFoundError('Debug endpoint is only available when debug mode is enabled.');
    }
    // Use the existing cache to inspect the current state, which is more useful for debugging.
    // Calling getPlaylistMedia() would fetch new data every time, which is not what the note implies.
    const allMedia = playlistCache || [];

    res.json({
        note: "This endpoint returns the raw data for all media items currently in the *cached* playlist. This reflects what the front-end is using.",
        playlist_item_count: allMedia.length,
        playlist_items_raw: allMedia.map(m => m?._raw).filter(Boolean) // Filter out items without raw data
    });
}));

// Start the server only if this script is run directly (e.g., `node server.js`)
// and not when it's imported by another script (like our tests).
if (require.main === module) {
    app.listen(port, async () => {
        console.log(`posterrama.app is listening on http://localhost:${port}`);
        if(isDebug) console.log(`Debug endpoint is available at http://localhost:${port}/admin/debug`);

        // Start the server immediately and perform the first media fetch in the background.
        // This prevents the server start from being blocked if the media server is slow.
        console.log('Performing initial playlist fetch...');
        refreshPlaylistCache().then(() => {
            if (playlistCache && playlistCache.length > 0) {
                console.log(`Initial playlist fetch complete. ${playlistCache.length} items loaded.`);
            } else {
                // Use console.warn here, as this is not a fatal error for the server itself.
                console.warn('Initial playlist fetch did not populate any media. The application will run but will not display any media until a refresh succeeds. Check server configurations and logs for errors during fetch.');
            }
        }).catch(err => console.error('An error occurred during the initial background fetch:', err));

        const refreshInterval = (config.backgroundRefreshMinutes || 30) * 60 * 1000;
        if (refreshInterval > 0) {
            setInterval(refreshPlaylistCache, refreshInterval);
            console.log(`Playlist will be refreshed in the background every ${config.backgroundRefreshMinutes} minutes.`);
        }
    });

    // --- Conditional Site Server ---
    // This server runs on a separate port and is controlled by config.json.
    // It's intended for public viewing without exposing the main application's admin panel.
    if (config.siteServer && config.siteServer.enabled) {
        const siteApp = express();
        const sitePort = config.siteServer.port || 4001;
        const mainAppUrl = `http://localhost:${port}`; // 'port' is the main app's port

        // A simple proxy for API requests to the main application.
        // This ensures that the public site can fetch data without exposing admin endpoints.
        const proxyApiRequest = async (req, res) => {
            const targetUrl = `${mainAppUrl}${req.originalUrl}`;
            try {
                if (isDebug) console.log(`[Site Server Proxy] Forwarding request to: ${targetUrl}`);
                const response = await fetch(targetUrl);

                // Intercept /get-config to add a flag indicating this is the public site.
                // The client-side script can use this flag to show specific elements, like a promo box.
                if (req.originalUrl === '/get-config' && response.ok) {
                    if (isDebug) console.log(`[Site Server Proxy] Modifying response for /get-config`);
                    const originalConfig = await response.json();
                    const modifiedConfig = { ...originalConfig, isPublicSite: true };
                    // We send the modified JSON and stop further processing for this request.
                    return res.json(modifiedConfig);
                }

                // Forward the status code from the main app
                res.status(response.status);

                // Forward all headers from the main app's response
                response.headers.forEach((value, name) => {
                    res.setHeader(name, value);
                });

                // Pipe the response body
                response.body.pipe(res);
            } catch (error) {
                console.error(`[Site Server Proxy] Error forwarding request to ${targetUrl}:`, error);
                res.status(502).json({ error: 'Bad Gateway', message: 'The site server could not connect to the main application.' });
            }
        };

        // Define the public API routes that need to be proxied
        siteApp.get('/get-config', proxyApiRequest);
        siteApp.get('/get-media', proxyApiRequest);
        siteApp.get('/get-media-by-key/:key', proxyApiRequest);
        siteApp.get('/image', proxyApiRequest);

        // Serve static files (CSS, JS, etc.) from the 'public' directory
        siteApp.use(express.static(path.join(__dirname, 'public')));

        // A catch-all route to serve the main index.html for any other GET request.
        // This is crucial for single-page applications (SPAs) to handle client-side routing.
        siteApp.get('*', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });

        siteApp.listen(sitePort, () => {
            console.log(`Public site server is enabled and running on http://localhost:${sitePort}`);
        });
    }
}

// Error handling middleware (must be last)
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

// Handle 404 for unmatched routes
app.use(notFoundHandler);

// Centralized error handler
app.use(errorHandler);

// Export the app instance so that it can be imported and used by Supertest in our tests.
module.exports = app;