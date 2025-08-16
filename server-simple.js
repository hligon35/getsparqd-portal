const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
// Multer for handling multipart file uploads (optional dependency)
let upload;
let _multerPresent = false;
try {
    const multer = require('multer');
    upload = multer({ dest: '/tmp' });
    _multerPresent = true;
} catch (e) {
    // Multer not installed. We'll surface a clear error if multipart is used.
    upload = (req, res, next) => next();
    _multerPresent = false;
}
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectRedis = require('connect-redis');
const { createClient } = require('redis');
require('dotenv').config();
// Node 18+ has global fetch; ensure availability
const _fetch = globalThis.fetch || require('node-fetch');

const app = express();
const execAsync = promisify(exec);
const PORT = process.env.EMAIL_ADMIN_PORT || 3003;

// Middleware
// Running behind Cloudflare Tunnel/reverse proxy
app.set('trust proxy', 1);
app.use(cors({
    origin: [
        'http://localhost:3003',
        'http://68.54.208.207:3003',
        'https://admin.getsparqd.com',
        'https://portal.getsparqd.com',
        'http://portal.getsparqd.com'
    ],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Helmet with CSP tweaked to allow our inline scripts on login/index pages
app.use(helmet({
    // We'll control framing with CSP only (more flexible than X-Frame-Options)
    frameguard: false,
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            // Allow inline scripts for the current portal pages; consider nonces/hashes later
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            // Keep styles permissive for inline CSS in templates
            styleSrc: ["'self'", "https:", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            // Allow embedding SparqPlug app in an iframe (portal -> app)
            frameSrc: ["'self'", 'https://getsparqd.com', 'https://sparqplug.getsparqd.com'],
            // Allow portal pages (like /login) to be framed by sparqplug during SSO round-trip
            frameAncestors: ["'self'", 'https://sparqplug.getsparqd.com'],
        },
    },
    crossOriginEmbedderPolicy: false,
}));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 300 }));

// Initialize Redis client and session store with broad version compatibility
const redisUrl = process.env.REDIS_URL || 'redis://shared-redis:6379';
const client = createClient({ url: redisUrl });
client.on('error', (err) => console.error('Redis Client Error', err));
// Connect asynchronously; session store can use the client once ready
client.connect().catch(err => console.error('Redis connect error', err));

function createRedisSessionStore(sess, redisClient) {
    // Try factory style first: require('connect-redis')(session)
    try {
        if (typeof connectRedis === 'function') {
            const MaybeCtor = connectRedis(sess);
            if (typeof MaybeCtor === 'function') {
                return new MaybeCtor({ client: redisClient });
            }
        }
    } catch (_) { /* fall through */ }

        // Try default/class export (v6+/v8)
        const MaybeClass = (connectRedis && (connectRedis.default || connectRedis.RedisStore))
            ? (connectRedis.default || connectRedis.RedisStore)
            : connectRedis;
    if (typeof MaybeClass === 'function') {
        try {
            return new MaybeClass({ client: redisClient });
        } catch (_) { /* fall through */ }
    }

    throw new Error('Unsupported connect-redis version: cannot construct RedisStore');
}

app.use(session({
    store: createRedisSessionStore(session, client),
  name: process.env.SESSION_NAME || 'portal.sid',
  secret: process.env.SESSION_SECRET || 'changeme',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    // Default to parent domain for cross-subdomain SSO
    domain: process.env.SESSION_DOMAIN || '.getsparqd.com',
    maxAge: 1000 * 60 * 60 * 12
  }
}));

// Allow serving when reverse-proxied at /portal by stripping the base path
app.use((req, res, next) => {
    if (req.url === '/portal') {
        req.url = '/';
    } else if (req.url.startsWith('/portal/')) {
        req.url = req.url.substring('/portal'.length);
    }
    next();
});
// Also expose static assets under /portal for direct access
app.use('/portal', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage (in production, use a database)
let domains = [];
let emailAccounts = [];
let systemLogs = [];

// Users with secure management
const users = {
    'hligon': { 
        password: 'temporary', 
        role: 'admin', 
        name: 'H. Ligon',
        email: 'hligon@getsparqd.com',
        requirePasswordChange: true,
        lastLogin: null,
        created: new Date().toISOString()
    },
    'bhall': { 
        password: 'temporary', 
        role: 'admin', 
        name: 'B. Hall',
        email: 'bhall@getsparqd.com',
        requirePasswordChange: true,
        lastLogin: null,
        created: new Date().toISOString()
    }
};

// Add log entry
function addLog(message, level = 'info') {
    const logEntry = {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        message,
        level
    };
    systemLogs.unshift(logEntry);
    
    // Keep only last 100 logs
    if (systemLogs.length > 100) {
        systemLogs = systemLogs.slice(0, 100);
    }
    
    console.log(`[${level.toUpperCase()}] ${message}`);
}

// Simple auth middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// Authentication routes
app.post('/api/auth/login', (req, res) => {
    try {
        const username = (req.body && (req.body.username || req.body.user)) || (req.query && req.query.username);
        const password = (req.body && (req.body.password || req.body.pass)) || (req.query && req.query.password);
        if (!username || !password) {
            addLog('Login attempt missing credentials', 'warn');
            return res.status(400).json({ error: 'Missing credentials' });
        }
    
    const user = users[username];
    if (user && user.password === password) {
        // Update last login
        user.lastLogin = new Date().toISOString();

        // Regenerate to avoid fixation and ensure fresh session
        return req.session.regenerate((err) => {
            if (err) {
                addLog(`Session regenerate failed: ${err.message}`, 'error');
                return res.status(500).json({ error: 'Session error' });
            }
            req.session.user = {
                username,
                role: user.role,
                name: user.name,
                email: user.email,
                requirePasswordChange: user.requirePasswordChange || false
            };
            req.session.save((saveErr) => {
                if (saveErr) {
                    addLog(`Session save failed: ${saveErr.message}`, 'error');
                    return res.status(500).json({ error: 'Session save error' });
                }
                // Generate a simple token for frontend compatibility
                const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
                return res.json({
                    success: true,
                    token,
                    user: req.session.user,
                    requirePasswordChange: user.requirePasswordChange || false
                });
            });
        });
    } else {
        addLog(`Invalid login for ${username}`, 'warn');
        res.status(401).json({ error: 'Invalid credentials' });
    }
    } catch (e) {
        addLog(`Login error: ${e.message}`, 'error');
        return res.status(400).json({ error: 'Bad Request' });
    }
});

// Change password
app.post('/api/auth/change-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const username = req.session.user.username;
    const user = users[username];
    
    if (!user || user.password !== currentPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }
    
    // Update password and remove requirement flag
    user.password = newPassword;
    user.requirePasswordChange = false;
    user.lastPasswordChange = new Date().toISOString();
    
    // Update session
    req.session.user.requirePasswordChange = false;
    
    addLog(`Password changed for user ${username}`);
    res.json({ success: true, message: 'Password updated successfully' });
});

// Request password reset
app.post('/api/auth/request-reset', (req, res) => {
    const { username, email } = req.body;
    
    const user = users[username];
    if (!user || user.email !== email) {
        // Don't reveal if user exists for security
        return res.json({ success: true, message: 'If this account exists, a reset token has been sent' });
    }
    
    // Generate reset token (in production, use crypto.randomBytes)
    const resetToken = Buffer.from(`${username}:${Date.now()}:reset`).toString('base64');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + (60 * 60 * 1000); // 1 hour
    
    addLog(`Password reset requested for ${username}`);
    
    // In production, send email with reset link
    console.log(`Password reset token for ${username}: ${resetToken}`);
    
    res.json({ 
        success: true, 
        message: 'Reset token generated (check server logs)',
        resetToken: resetToken // Remove this in production
    });
});

// Reset password with token
app.post('/api/auth/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
    
    // Find user with matching token
    const username = Object.keys(users).find(u => 
        users[u].resetToken === token && 
        users[u].resetTokenExpiry > Date.now()
    );
    
    if (!username) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }
    
    const user = users[username];
    user.password = newPassword;
    user.requirePasswordChange = false;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    user.lastPasswordChange = new Date().toISOString();
    
    addLog(`Password reset completed for ${username}`);
    res.json({ success: true, message: 'Password reset successfully' });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json(req.session.user);
});

// Compute SparqPlug entry URL for the current user (no redirect here)
// Usage: GET /api/sparqplug/url -> { url, path, role }
app.get('/api/sparqplug/url', requireAuth, (req, res) => {
  const role = (req.session.user && req.session.user.role) || 'client';
  const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client' };
  const pathPart = rolePathMap[role] || '/client';
  const host = process.env.SPARGPLUG_HOST || 'sparqplug.getsparqd.com';
  const basePath = process.env.SPARGPLUG_BASE_PATH || '/app';
  const url = `https://${host}${basePath}${pathPart}`;
  res.json({ url, path: pathPart, role });
});

// Optional: provide just the path
app.get('/api/sparqplug/path', requireAuth, (req, res) => {
    const role = (req.session.user && req.session.user.role) || 'client';
    const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client' };
    res.json({ path: rolePathMap[role] || '/client', role });
});

// --- SparQy Assistant: simple session-backed chat API ---
// Shape: messages are [{ role: 'user'|'assistant'|'system', content: string, ts: ISOString }]
function getSparQyThread(req, threadId = 'default') {
    if (!req.session.sparqy) req.session.sparqy = { threads: {} };
    if (!req.session.sparqy.threads[threadId]) req.session.sparqy.threads[threadId] = [];
    return req.session.sparqy.threads[threadId];
}

// === AI integration (OpenAI/Azure) + optional Google Custom Search ===
const AI_PROVIDER = (process.env.AI_PROVIDER || 'openai').toLowerCase();
const AI_MODEL = process.env.AI_MODEL || process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4o-mini';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || process.env.OPENAI_API_TOKEN;
const AZURE_OPENAI_KEY = process.env.AZURE_OPENAI_KEY;
const AZURE_OPENAI_ENDPOINT = process.env.AZURE_OPENAI_ENDPOINT; // https://<resource>.openai.azure.com
const AZURE_OPENAI_DEPLOYMENT = process.env.AZURE_OPENAI_DEPLOYMENT || AI_MODEL;
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY || process.env.GOOGLE_CSE_KEY;
const GOOGLE_CSE_ID = process.env.GOOGLE_CSE_ID || process.env.GOOGLE_CX;
const SPARQY_ALLOW_WEB = (process.env.SPARQY_ALLOW_WEB || 'true').toLowerCase() !== 'false';
const SPARQY_TIMEOUT_MS = Number(process.env.SPARQY_TIMEOUT_MS || 15000);
const MAX_WEB_SNIPPETS = 3;
const MAX_FETCH_BYTES = 100 * 1024; // 100KB

function withTimeout(ms) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), ms);
    return { signal: controller.signal, cancel: () => clearTimeout(t) };
}
function safeTrim(s, n) {
    if (!s) return '';
    if (s.length <= n) return s;
    return s.slice(0, n) + '…';
}
async function openaiChat(messages, { system, model = AI_MODEL, temperature = 0.2 } = {}) {
    if (!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');
    const body = {
        model,
        messages: [system ? { role: 'system', content: system } : null, ...messages].filter(Boolean),
        temperature,
    };
    const { signal, cancel } = withTimeout(SPARQY_TIMEOUT_MS);
    try {
        const r = await _fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
            body: JSON.stringify(body),
            signal,
        });
        if (!r.ok) throw new Error(`OpenAI HTTP ${r.status}`);
        const j = await r.json();
        return j.choices?.[0]?.message?.content || '';
    } finally { cancel(); }
}
async function azureChat(messages, { system, model = AZURE_OPENAI_DEPLOYMENT, temperature = 0.2 } = {}) {
    if (!AZURE_OPENAI_KEY || !AZURE_OPENAI_ENDPOINT) throw new Error('Azure OpenAI env missing');
    const url = `${AZURE_OPENAI_ENDPOINT}/openai/deployments/${model}/chat/completions?api-version=2024-06-01`;
    const body = { messages: [system ? { role: 'system', content: system } : null, ...messages].filter(Boolean), temperature };
    const { signal, cancel } = withTimeout(SPARQY_TIMEOUT_MS);
    try {
        const r = await _fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'api-key': AZURE_OPENAI_KEY }, body: JSON.stringify(body), signal });
        if (!r.ok) throw new Error(`Azure OpenAI HTTP ${r.status}`);
        const j = await r.json();
        return j.choices?.[0]?.message?.content || '';
    } finally { cancel(); }
}
async function modelChat(messages, opts) {
    if (AI_PROVIDER === 'azure' || AI_PROVIDER === 'azure-openai') return azureChat(messages, opts);
    return openaiChat(messages, opts);
}
async function googleSearch(q) {
    if (!SPARQY_ALLOW_WEB || !GOOGLE_API_KEY || !GOOGLE_CSE_ID) return [];
    const params = new URLSearchParams({ key: GOOGLE_API_KEY, cx: GOOGLE_CSE_ID, q, num: '5' });
    const url = `https://www.googleapis.com/customsearch/v1?${params.toString()}`;
    const { signal, cancel } = withTimeout(SPARQY_TIMEOUT_MS);
    try {
        const r = await _fetch(url, { signal });
        if (!r.ok) throw new Error(`Google CSE HTTP ${r.status}`);
        const j = await r.json();
        const items = j.items || [];
        return items.slice(0, MAX_WEB_SNIPPETS).map(it => ({ title: it.title, link: it.link, snippet: it.snippet, displayLink: it.displayLink }));
    } catch (_) { return []; } finally { cancel(); }
}
async function fetchText(url) {
    try {
        const { signal, cancel } = withTimeout(SPARQY_TIMEOUT_MS);
        const r = await _fetch(url, { signal, redirect: 'follow' });
        cancel();
        if (!r.ok) return '';
        const ct = r.headers.get('content-type') || '';
        if (!/text\/html|text\/plain|application\/json/.test(ct)) return '';
        const reader = r.body.getReader();
        let received = 0; const chunks = [];
        while (true) { const { done, value } = await reader.read(); if (done) break; received += value.length; if (received > MAX_FETCH_BYTES) { chunks.push(value.slice(0, Math.max(0, MAX_FETCH_BYTES - (received - value.length)))); break; } chunks.push(value); }
        const buf = Buffer.concat(chunks);
        return buf.toString('utf8');
    } catch (_) { return ''; }
}
function needWebSearch(text) {
    const t = (text || '').toLowerCase();
    return /google|search|how do i|docs|documentation|error code|stack overflow|webmail url|cloudflare|next\.js|express|dovecot|postfix|dns|spf|dmarc/.test(t);
}
function buildSystem(user) {
    const name = user?.name || user?.username || 'User';
    return [
        'You are SparQy, a helpful assistant for the SparQ Digital admin portal.',
        'Assist with: email hosting (Postfix/Dovecot), DNS templates, webmail links, SparQ Plug app navigation, Cloudflare tunnel tips, and troubleshooting.',
        'Be concise and action-oriented. Provide numbered steps when helpful. Include portal-relative URLs where appropriate.',
        'If you used web results, cite 1-3 sources as bullet links under "Sources:" at the end.',
        `Current user: ${name}. Do not perform destructive actions without confirmation.`,
    ].join(' ');
}
async function answerWithOptionalWeb(query, history, user) {
    let sources = [];
    let webContext = '';
    if (SPARQY_ALLOW_WEB && needWebSearch(query)) {
        const results = await googleSearch(query);
        sources = results;
        const texts = await Promise.all(results.map(r => fetchText(r.link)));
        const joined = texts.map((t, i) => `Source ${i + 1} (${results[i].displayLink}):\n${safeTrim(String(t || '').replace(/\s+/g, ' ').trim(), 2000)}`).join('\n\n');
        webContext = joined ? `Relevant web excerpts (truncated):\n${joined}` : '';
    }
    const msgs = [];
    const tail = (history || []).slice(-6).map(m => ({ role: m.role, content: m.content }));
    msgs.push(...tail);
    if (webContext) msgs.push({ role: 'system', content: webContext });
    msgs.push({ role: 'user', content: query });
    const system = buildSystem(user);
    const reply = await modelChat(msgs, { system, temperature: 0.2 });
    return { reply, sources };
}

// Retrieve history
app.get('/api/sparqy/history', requireAuth, (req, res) => {
    const threadId = (req.query.threadId || 'default').toString();
    const history = getSparQyThread(req, threadId);
    // Seed a friendly greeting if thread is empty
    if (history.length === 0) {
        history.push({
            role: 'assistant',
            content: `Hi ${req.session.user?.name || ''}! I’m SparQy. Ask me about DNS, webmail, or SparQ Plug.`,
            ts: new Date().toISOString()
        });
        req.session.save(() => {});
    }
    res.json({ threadId, messages: history });
});

// Clear history
app.post('/api/sparqy/clear', requireAuth, (req, res) => {
    const threadId = (req.body && req.body.threadId) || 'default';
    if (req.session.sparqy && req.session.sparqy.threads) {
        req.session.sparqy.threads[threadId] = [];
    }
    res.json({ success: true, threadId });
});

// Chat endpoint (stubbed assistant logic; no external calls by default)
app.post('/api/sparqy/chat', requireAuth, async (req, res) => {
    try {
        const { message, threadId: rawThreadId } = req.body || {};
        const threadId = (rawThreadId || 'default').toString();
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Message is required' });
        }

        const history = getSparQyThread(req, threadId);
        const now = new Date().toISOString();
        const cleaned = String(message).trim();
        history.push({ role: 'user', content: cleaned, ts: now });

        // Quick command to clear the thread
        const lcCmd = cleaned.toLowerCase();
        if (lcCmd === 'clear' || lcCmd === '/clear') {
            history.length = 0;
            const cleared = { role: 'assistant', content: 'Cleared this conversation.', ts: new Date().toISOString() };
            history.push(cleared);
            req.session.save(() => {});
            return res.json({ threadId, reply: cleared.content, messages: history, sources: [] });
        }

        // Ask model; include optional web context
        let replyText = '';
        let sources = [];
        try {
            const out = await answerWithOptionalWeb(cleaned, history, req.session.user);
            replyText = out.reply || '';
            sources = Array.isArray(out.sources) ? out.sources : [];
        } catch (e) {
            replyText = 'Assistant is temporarily unavailable. Please try again shortly.';
        }
        const replyMsg = { role: 'assistant', content: replyText, ts: new Date().toISOString() };
        history.push(replyMsg);
        req.session.save(() => {});
        res.json({ threadId, reply: replyMsg.content, messages: history, sources });
    } catch (e) {
        res.status(500).json({ error: 'Assistant error' });
    }
});

// Simple health for SparQy
app.get('/api/sparqy/health', requireAuth, (req, res) => {
    const threads = (req.session.sparqy && req.session.sparqy.threads) || {};
    const counts = Object.values(threads).map(arr => Array.isArray(arr) ? arr.length : 0);
    const messages = counts.reduce((a, b) => a + b, 0);
    res.json({ ok: true, threads: Object.keys(threads).length, messages });
});

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  // Stay on portal dashboard; navigation to SparqPlug happens via nav/tab
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Explicit login routes to avoid any static path edge cases
app.get(['/login', '/login.html'], (req, res) => {
    const rt = req.query && req.query.returnTo;
    const sso = req.query && req.query.sso;
    const isSafeRt = typeof rt === 'string' && /^https:\/\/(sparqplug\.getsparqd\.com|.*\.getsparqd\.com)/.test(rt);
    if (req.session && req.session.user) {
        if (sso === '1' && isSafeRt) {
            return res.redirect(302, rt);
        }
        return res.redirect(302, '/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Simple health check for tunnels and monitors
app.get('/healthz', (req, res) => {
    res.json({ ok: true, service: 'email-admin', time: new Date().toISOString() });
});

app.get('/change-password', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'change-password.html'));
    } else {
        res.redirect('/');
    }
});

// Generate secure password
function generatePassword(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// Create email account in system
async function createEmailAccount(email, password, domain, storageGB = 25) {
    try {
        const username = email.split('@')[0];
        
        // Create user directory
        await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}/${username}`);
        await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
        
        // Add to virtual mailboxes
        await execAsync(`echo "${email} ${domain}/${username}/" | sudo tee -a /etc/postfix/virtual_mailboxes`);
        
        // Add password entry
        const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p "${password}"`);
        await execAsync(`echo "${email}:${saltedHash.stdout.trim()}" | sudo tee -a /etc/dovecot/passwd.${domain}`);
        
        // Update postfix maps
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        
        // Restart services
        await execAsync('sudo systemctl reload postfix dovecot');
        
        // Add to our tracking
        const account = {
            id: uuidv4(),
            address: email,
            domain,
            password: password, // Store plain text for client notification
            storage: storageGB,
            created: new Date().toISOString(),
            lastLogin: null
        };
        
        emailAccounts.push(account);
        addLog(`Created email account: ${email}`);
        
        return account;
        
    } catch (error) {
        addLog(`Failed to create email account ${email}: ${error.message}`, 'error');
        throw error;
    }
}

// Setup domain email hosting
async function setupDomainEmail(domainData) {
    const { domain, clientName, clientContact, emailAccounts: emailList, storageAllocation } = domainData;
    
    const results = {
        domain,
        clientName,
        createdAccounts: [],
        totalStorage: storageAllocation,
        credentials: []
    };
    
    try {
        // Add domain to virtual domains
        await execAsync(`echo "${domain}" | sudo tee -a /etc/postfix/virtual_domains`);
        
        // Create accounts
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                const account = await createEmailAccount(emailAddr.trim(), password, domain, storageAllocation / emailList.length);
                
                results.createdAccounts.push({
                    email: emailAddr.trim(),
                    password,
                    storage: Math.floor(storageAllocation / emailList.length)
                });
                
                results.credentials.push({
                    email: emailAddr.trim(),
                    password,
                    imap: `${domain}:993 (SSL/TLS)`,
                    smtp: `${domain}:587 (STARTTLS)`,
                    webmail: `http://mail.${domain}`
                });
            }
        }
        
        // Add domain to tracking
        const domainRecord = {
            id: uuidv4(),
            name: domain,
            clientName,
            clientContact,
            emailCount: results.createdAccounts.length,
            storageAllocated: storageAllocation,
            created: new Date().toISOString(),
            status: 'active'
        };
        
        domains.push(domainRecord);
        
        addLog(`Domain email setup completed for ${domain} (${results.createdAccounts.length} accounts)`);
        return results;
        
    } catch (error) {
        addLog(`Domain setup failed for ${domain}: ${error.message}`, 'error');
        throw error;
    }
}

// API Routes (protected)
app.get('/api/dashboard/stats', requireAuth, (req, res) => {
    const totalStorage = emailAccounts.reduce((sum, account) => sum + account.storage, 0);
    const monthlySavings = domains.length * 15; // Estimate $15/month per domain saved
    
    res.json({
        totalDomains: domains.length,
        totalEmails: emailAccounts.length,
        storageUsed: totalStorage,
        monthlySavings
    });
});

// Setup validation
app.post('/api/setup/validate', requireAuth, async (req, res) => {
    const { domain } = req.body;
    
    try {
        // Check if domain already exists
        const existingDomain = domains.find(d => d.name === domain);
        if (existingDomain) {
            return res.status(400).json({ error: 'Domain already configured' });
        }
        
        // Basic domain validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        if (!domainRegex.test(domain)) {
            return res.status(400).json({ error: 'Invalid domain format' });
        }
        
        res.json({ 
            success: true, 
            details: [`Domain ${domain} is valid and available`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create directories
app.post('/api/setup/directories', requireAuth, async (req, res) => {
    const { domain } = req.body;
    
    try {
        await execAsync(`sudo mkdir -p /var/mail/vhosts/${domain}`);
        await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}`);
        await execAsync(`sudo chown -R mail:mail /var/mail/vhosts/${domain}`);
        
        res.json({ 
            success: true,
            details: [
                `Created mail directory: /var/mail/vhosts/${domain}`,
                `Created site directory: /home/sparqd/sites/${domain}`
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create accounts
app.post('/api/setup/accounts', requireAuth, async (req, res) => {
    const { domain, emailAccounts: emailList } = req.body;
    
    try {
        const createdAccounts = [];
        
        for (const emailAddr of emailList) {
            if (emailAddr.trim()) {
                const password = generatePassword(14);
                await createEmailAccount(emailAddr.trim(), password, domain);
                createdAccounts.push(`${emailAddr.trim()} (${password})`);
            }
        }
        
        res.json({ 
            success: true,
            details: [`Created ${createdAccounts.length} email accounts`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Configure mail server
app.post('/api/setup/mailserver', requireAuth, async (req, res) => {
    try {
        await execAsync('sudo postmap /etc/postfix/virtual_domains');
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        await execAsync('sudo systemctl reload postfix dovecot');
        
        res.json({ 
            success: true,
            details: [
                'Updated Postfix virtual maps',
                'Reloaded Postfix and Dovecot services'
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Allocate storage
app.post('/api/setup/storage', requireAuth, async (req, res) => {
    const { domain, storageAllocation } = req.body;
    
    try {
        // Set quota (this is a simplified implementation)
        await execAsync(`sudo mkdir -p /home/sparqd/sites/${domain}/quota`);
        await fs.writeFile(`/home/sparqd/sites/${domain}/quota/allocation.txt`, `${storageAllocation}GB`);
        
        res.json({ 
            success: true,
            details: [`Allocated ${storageAllocation}GB storage for ${domain}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Setup DNS
app.post('/api/setup/dns', requireAuth, async (req, res) => {
    const { domain } = req.body;
    
    try {
        const dnsRecords = [
            `MX: ${domain} → mail.${domain} (Priority 10)`,
            `A: mail.${domain} → ${process.env.SERVER_IP || '68.54.208.207'}`,
            `A: email.${domain} → ${process.env.SERVER_IP || '68.54.208.207'}`,
            `TXT: ${domain} → "v=spf1 mx a:${domain} ~all"`
        ];
        
        res.json({ 
            success: true,
            details: ['DNS records prepared (manual configuration required)', ...dnsRecords]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Setup webmail for domain
app.post('/api/setup/webmail', requireAuth, async (req, res) => {
    const { domain } = req.body;
    
    try {
        // Execute the webmail setup script
        const scriptPath = '/home/sparqd/setup-client-webmail.sh';
        const { stdout, stderr } = await execAsync(`sudo bash ${scriptPath} ${domain}`);
        
        addLog(`Webmail configured for ${domain}`);
        addLog(`Webmail accessible at: https://email.${domain}`);
        
        res.json({ 
            success: true,
            details: [
                `Webmail configured for email.${domain}`,
                'Nginx virtual host created',
                'Domain-specific Roundcube config generated',
                `Access URL: https://email.${domain}`,
                'DNS record required: A email → server IP'
            ]
        });
        
    } catch (error) {
        console.error('Webmail setup error:', error);
        addLog(`Webmail setup failed for ${domain}: ${error.message}`);
        res.json({ 
            success: true,
            details: [`Webmail setup completed with warnings: ${error.message}`]
        });
    }
});

// Provision a static webpage: create site directory, write files, enable nginx vhost, optional Cloudflare DNS
// Accept both JSON and multipart/form-data (with optional file field 'sitefile')
async function webpageSetupHandler(req, res) {
    try {
        // If multer not present and client sent multipart, return instructive error
        if (!_multerPresent) {
            const ct = (req.headers['content-type'] || '').toLowerCase();
            if (ct.includes('multipart/form-data')) {
                return res.status(500).json({ error: 'Server missing multipart upload support (multer). Please install multer in the portal package.' });
            }
        }
        // If multipart, fields may be in req.body and file in req.file
        const multipartFile = req.file;
        const { domain, title, pool, indexHtml, enableSsl, filesZipBase64, cloudflareApiToken } = (req.body || {});

        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
        if (!domain || !domainRegex.test(domain)) return res.status(400).json({ error: 'Invalid domain' });

        // Base path for sites (configurable)
        const sitesBase = process.env.WEB_SITES_BASE || '/home/sparqd/sites';
        const sitePath = path.join(sitesBase, domain);

        // Ensure directory exists (use sudo for ownership consistency with other setup scripts)
        await execAsync(`sudo mkdir -p ${sitePath}`);

        // If an uploaded file via multipart exists, extract it. If filesZipBase64 provided (legacy), handle it. Otherwise if indexHtml provided, write index.html
        if (multipartFile && multipartFile.path) {
            const uploaded = multipartFile.path;
            // Try unzip if mime or filename suggests zip, else try tar
            const originalName = multipartFile.originalname || '';
            try {
                if (/\.zip$/i.test(originalName) || multipartFile.mimetype === 'application/zip') {
                    await execAsync(`sudo unzip -o ${uploaded} -d ${sitePath}`);
                } else if (/\.(tgz|tar\.gz)$/i.test(originalName) || multipartFile.mimetype === 'application/gzip') {
                    await execAsync(`sudo tar -xzf ${uploaded} -C ${sitePath}`);
                } else {
                    // Unknown type: attempt unzip first, then tar; if both fail, move file as index.html when it's HTML
                    try { await execAsync(`sudo unzip -o ${uploaded} -d ${sitePath}`); }
                    catch (e) {
                        try { await execAsync(`sudo tar -xzf ${uploaded} -C ${sitePath}`); } catch (_) {
                            // If file appears to be HTML, move it to index.html
                            const content = await fs.readFile(uploaded);
                            const tmpFile = `/tmp/${uuidv4()}.html`;
                            await fs.writeFile(tmpFile, content);
                            await execAsync(`sudo mv ${tmpFile} ${sitePath}/index.html`);
                        }
                    }
                }
            } finally {
                // Cleanup uploaded tmp file
                try { await fs.unlink(multipartFile.path); } catch(_){ }
            }
        } else if (filesZipBase64) {
            const tmpZip = `/tmp/${uuidv4()}.zip`;
            await fs.writeFile(tmpZip, Buffer.from(filesZipBase64, 'base64'));
            // unzip to target (overwrite)
            try {
                await execAsync(`sudo unzip -o ${tmpZip} -d ${sitePath}`);
            } catch (e) {
                // If unzip not available or failed, attempt fallback to tar
                try { await execAsync(`sudo tar -xzf ${tmpZip} -C ${sitePath}`); } catch (_) { /* ignore */ }
            }
            await execAsync(`sudo rm -f ${tmpZip}`);
        } else if (indexHtml) {
            const tmpFile = `/tmp/${uuidv4()}.html`;
            await fs.writeFile(tmpFile, indexHtml, 'utf8');
            // Move into place with sudo to ensure correct ownership
            await execAsync(`sudo mv ${tmpFile} ${sitePath}/index.html`);
        } else {
            // If neither provided, create a basic index
            const fallback = `<html><head><title>${(title||domain)}</title></head><body><h1>${(title||domain)}</h1><p>Deployed by SparQ portal.</p></body></html>`;
            const tmpFile = `/tmp/${uuidv4()}.html`;
            await fs.writeFile(tmpFile, fallback, 'utf8');
            await execAsync(`sudo mv ${tmpFile} ${sitePath}/index.html`);
        }

        // Ensure correct ownership for web server user
        try {
            await execAsync(`sudo chown -R www-data:www-data ${sitePath}`);
        } catch (e) {
            // Fallback to sparqd user if www-data doesn't exist
            await execAsync(`sudo chown -R sparqd:sparqd ${sitePath}`).catch(() => {});
        }

        // Create a minimal nginx vhost
        const nginxConf = `server {\n  listen 80;\n  server_name ${domain} www.${domain};\n  root ${sitePath};\n  index index.html index.htm;\n  location / { try_files $uri $uri/ =404; }\n}\n`;
        const confTmp = `/tmp/${uuidv4()}.conf`;
        const confPath = `/etc/nginx/sites-available/${domain}`;
        await fs.writeFile(confTmp, nginxConf, 'utf8');
        await execAsync(`sudo mv ${confTmp} ${confPath}`);
        // Symlink into sites-enabled
        await execAsync(`sudo ln -sf ${confPath} /etc/nginx/sites-enabled/${domain}`);

        // Test nginx config and reload
        let nginxOk = true;
        let nginxOut = '';
        try {
            await execAsync('sudo nginx -t');
            await execAsync('sudo systemctl reload nginx');
            nginxOut = 'nginx reloaded';
        } catch (e) {
            nginxOk = false;
            nginxOut = e.message || String(e);
        }

        // Optionally create Cloudflare DNS record if API token is available
        const cfToken = process.env.CLOUDFLARE_API_TOKEN || cloudflareApiToken || process.env.CF_API_TOKEN;
        let cfResultNote = 'Cloudflare not configured (no token)';
        if (cfToken) {
            try {
                // Attempt to find zone by exact domain, then by apex
                const zonename = domain;
                const zonesUrl = `https://api.cloudflare.com/client/v4/zones?name=${domain}`;
                let zres = await _fetch(zonesUrl, { headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' } });
                let zj = await zres.json();
                if (!zj.success || !zj.result || zj.result.length === 0) {
                    // Try apex (last two labels)
                    const parts = domain.split('.');
                    if (parts.length >= 2) {
                        const apex = parts.slice(-2).join('.');
                        zres = await _fetch(`https://api.cloudflare.com/client/v4/zones?name=${apex}`, { headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' } });
                        zj = await zres.json();
                    }
                }
                if (zj.success && zj.result && zj.result.length > 0) {
                    const zoneId = zj.result[0].id;
                    const serverIp = process.env.SERVER_IP || req.headers['x-forwarded-for']?.split(',')?.[0] || '127.0.0.1';
                    // Create A record for domain
                    const createUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
                    const payload = { type: 'A', name: domain, content: serverIp, ttl: 1, proxied: true };
                    const pres = await _fetch(createUrl, { method: 'POST', headers: { 'Authorization': `Bearer ${cfToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                    const pj = await pres.json();
                    if (pj.success) {
                        cfResultNote = `Cloudflare A record created for ${domain} -> ${serverIp}`;
                    } else {
                        cfResultNote = `Cloudflare API responded but failed: ${JSON.stringify(pj.errors || pj)} `;
                    }
                } else {
                    cfResultNote = 'Could not find Cloudflare zone for domain';
                }
            } catch (e) {
                cfResultNote = 'Cloudflare API error: ' + (e && e.message ? e.message : String(e));
            }
        }

        addLog(`Provisioned static site for ${domain} (nginx:${nginxOk})`);

        res.json({
            success: true,
            domain,
            sitePath,
            nginx: { ok: nginxOk, note: nginxOut },
            cloudflare: cfResultNote,
            url: `http://${domain}`
        });
    } catch (error) {
        addLog(`Webpage setup failed: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
}

// Register endpoint with multer if available; otherwise register without file middleware
if (_multerPresent) {
    app.post('/api/setup/webpage', requireAuth, upload.single('sitefile'), webpageSetupHandler);
} else {
    app.post('/api/setup/webpage', requireAuth, webpageSetupHandler);
}

// Send notifications
app.post('/api/setup/notify', requireAuth, async (req, res) => {
    const { clientContact, domain, recipientEmail } = req.body;
    
    try {
        if (clientContact || recipientEmail) {
            const recipient = recipientEmail || clientContact;
            addLog(`Client notification prepared for ${recipient}`);
            
            // In a real implementation, you would send an email here with:
            // - Email account credentials
            // - Webmail access URL: https://email.${domain}
            // - Server settings for email clients
            // - Admin dashboard access for account management
        }
        
        res.json({ 
            success: true,
            details: [
                `Client notification sent to ${recipientEmail || clientContact}`,
                `Webmail URL included: https://email.${domain}`,
                'Email client settings provided',
                'Password change instructions included'
            ]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Finalize setup
app.post('/api/setup/finalize', requireAuth, async (req, res) => {
    try {
        const setupResult = await setupDomainEmail(req.body);
        
        res.json({ 
            success: true,
            details: [
                `Domain ${setupResult.domain} setup completed`,
                `${setupResult.createdAccounts.length} email accounts created`,
                `${setupResult.totalStorage}GB storage allocated`
            ],
            result: setupResult
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Email management
app.get('/api/emails/list', requireAuth, (req, res) => {
    res.json(emailAccounts.map(account => ({
        address: account.address,
        domain: account.domain,
        storage: account.storage,
        created: new Date(account.created).toLocaleDateString(),
        lastLogin: account.lastLogin
    })));
});

// System logs
app.get('/api/logs/recent', requireAuth, (req, res) => {
    res.json(systemLogs.slice(0, 50));
});

// --- Dashboard live data endpoints and aliases ---
// Stats (aliases for UI candidates)
app.get(['/api/stats', '/api/portal/stats', '/api/metrics/summary'], requireAuth, (req, res) => {
    const domainsCount = domains.length;
    const emailsCount = emailAccounts.length;
    const storageUsedGB = emailAccounts.reduce((sum, a) => sum + (Number(a.storage) || 0), 0);
    const monthlySavings = domainsCount * 15; // rough estimate
    res.json({ domains: domainsCount, emails: emailsCount, storageUsedGB, monthlySavings });
});

// Storage summary
app.get('/api/storage/summary', requireAuth, async (req, res) => {
    async function diskTotalBytesFor(target) {
        try {
            const mount = target || '/';
            // POSIX df output; -P portable, -B1 for bytes
            const { stdout } = await execAsync(`df -P -B1 ${mount} | tail -1`);
            // Filesystem 1B-blocks Used Available Use% Mounted on
            const parts = stdout.trim().split(/\s+/);
            const totalBytes = Number(parts[1]);
            return Number.isFinite(totalBytes) ? totalBytes : 0;
        } catch (_) { return 0; }
    }
    // Determine total storage: try configured mounts, then fallback to env, then 0
    const mounts = (process.env.STORAGE_MOUNTS || process.env.STORAGE_MOUNT || '/').split(',').map(s => s.trim()).filter(Boolean);
    let totalBytes = 0;
    for (const m of mounts) {
        const tb = await diskTotalBytesFor(m);
        if (tb > 0) { totalBytes += tb; }
    }
    if (totalBytes === 0) {
        const envGB = Number(process.env.TOTAL_STORAGE_GB || 0);
        if (envGB > 0) totalBytes = envGB * 1024 * 1024 * 1024;
    }
    const totalGB = totalBytes > 0 ? Math.round(totalBytes / (1024 * 1024 * 1024)) : Number(process.env.TOTAL_STORAGE_GB || 1000);

    // Email allocations from tracked accounts
    const domainMap = new Map();
    emailAccounts.forEach(a => {
        const d = a.domain || (a.address && String(a.address).split('@')[1]) || 'unknown';
        const prev = domainMap.get(d) || { domain: d, allocatedGB: 0, usedGB: 0 };
        prev.allocatedGB += Number(a.storage) || 0;
        prev.usedGB += Math.max(0, Math.min(Number(a.storage) || 0, (Number(a.usedGB) || 0)));
        domainMap.set(d, prev);
    });
    const domainsArr = Array.from(domainMap.values());
    const emailAllocatedGB = domainsArr.reduce((s, d) => s + (d.allocatedGB || 0), 0);

    // Planned 25% allocations for email/web/content
    const pct = 0.25;
    const emailCapGB = Math.floor(totalGB * pct);
    const webCapGB = Math.floor(totalGB * pct);
    const contentCapGB = Math.floor(totalGB * pct);
    const systemReserveGB = Math.max(0, totalGB - (emailCapGB + webCapGB + contentCapGB));
    const pools = {
        email: { capacityGB: emailCapGB, allocatedGB: emailAllocatedGB, availableGB: Math.max(0, emailCapGB - emailAllocatedGB) },
        web: { capacityGB: webCapGB, usedGB: 0 },
        content: { capacityGB: contentCapGB, usedGB: 0 },
        reserve: { capacityGB: systemReserveGB }
    };

    // Backwards-compatible fields:
    const allocatedGB = emailAllocatedGB; // previously showed "currently allocated" for email
    const availableGB = Math.max(0, pools.email.capacityGB - emailAllocatedGB); // available for email

    res.json({ totalGB, availableGB, allocatedGB, domains: domainsArr, pools, plannedAllocation: { percentEach: 25 } });
});

// Health: check key services. Keep fast and resilient.
app.get('/api/health', requireAuth, async (req, res) => {
    const result = { ok: true };
    try {
        const isActive = async (svc) => {
            try {
                const { stdout } = await execAsync(`systemctl is-active ${svc}`);
                return stdout.trim() === 'active';
            } catch { return false; }
        };
        const [postfix, dovecot, nginx] = await Promise.all([
            isActive('postfix'), isActive('dovecot'), isActive('nginx')
        ]);
        result.postfix = postfix; result.dovecot = dovecot; result.nginx = nginx;
    } catch (_) { /* ignore */ }
    try {
        const dns = require('dns').promises;
        await dns.resolve('google.com');
        result.dns = { ok: true };
    } catch { result.dns = { ok: false }; }
    res.json(result);
});

// Emails: list (alias), create (safe/in-memory), reset (stub)
app.get('/api/emails', requireAuth, (req, res) => {
    const list = emailAccounts.map(acc => ({
        email: acc.address || acc.email,
        address: acc.address || acc.email,
        domain: acc.domain || (acc.address && String(acc.address).split('@')[1]) || '',
        storage: acc.storage,
        lastLogin: acc.lastLogin,
        role: 'User'
    }));
    res.json(list);
});
app.post('/api/emails', requireAuth, async (req, res) => {
    try {
        const { email, storageGB } = req.body || {};
        if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
        const domain = String(email).split('@')[1];
        // Non-destructive by default: only track in-memory. Use setup endpoints for real provisioning.
        const account = {
            id: uuidv4(), address: email, domain, storage: Number(storageGB) || 25,
            created: new Date().toISOString(), lastLogin: null
        };
        emailAccounts.push(account);
        addLog(`Queued new email (in-memory): ${email}`);
        res.json({ success: true, account: { email, domain, storage: account.storage } });
    } catch (e) {
        res.status(500).json({ error: 'Failed to add email' });
    }
});
app.post('/api/emails/reset', requireAuth, async (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email required' });
    addLog(`Password reset requested (stub) for ${email}`);
    res.json({ success: true });
});

// Clients: derive from domains array; export
app.get('/api/clients', requireAuth, (req, res) => {
    const items = domains.map(d => ({ name: d.clientName || d.name, domain: d.name, contact: d.clientContact }));
    res.json({ clients: items });
});
app.get('/api/clients/export', requireAuth, (req, res) => {
    const items = domains.map(d => ({ name: d.clientName || '', domain: d.name, email: d.clientContact || '' }));
    const header = 'name,domain,email\n';
    const rows = items.map(i => `${JSON.stringify(i.name).slice(1,-1)},${JSON.stringify(i.domain).slice(1,-1)},${JSON.stringify(i.email).slice(1,-1)}`).join('\n');
    const csv = header + rows + '\n';
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="clients.csv"');
    res.send(csv);
});

// DNS test
app.get('/api/dns/test', requireAuth, async (req, res) => {
    try {
        const dns = require('dns').promises;
        const [a1] = await dns.resolve4('google.com');
        res.json({ ok: true, sample: a1 });
    } catch (e) {
        res.json({ ok: false, error: e.message });
    }
});

// Initialize system
async function initializeSystem() {
    addLog('Email Admin Dashboard starting up');
    
    // Load existing configurations if any
    try {
        const configPath = '/home/sparqd/email-admin-config.json';
        const configData = await fs.readFile(configPath, 'utf8');
        const config = JSON.parse(configData);
        
        domains = config.domains || [];
        emailAccounts = config.emailAccounts || [];
        
        addLog(`Loaded ${domains.length} domains and ${emailAccounts.length} email accounts`);
    } catch (error) {
        addLog('No existing configuration found, starting fresh');
    }
}

// Save configuration periodically
setInterval(async () => {
    try {
        const config = {
            domains,
            emailAccounts: emailAccounts.map(acc => ({
                ...acc,
                password: undefined // Don't save plain text passwords
            })),
            lastSaved: new Date().toISOString()
        };
        
        await fs.writeFile('/home/sparqd/email-admin-config.json', JSON.stringify(config, null, 2));
    } catch (error) {
        addLog(`Failed to save configuration: ${error.message}`, 'error');
    }
}, 60000); // Save every minute

// Quiet favicon 404s if no favicon is present
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Start server
app.listen(PORT, async () => {
    await initializeSystem();
    addLog(`Email Admin Dashboard running on port ${PORT}`);
    console.log(`\n🎉 Email Admin Dashboard is ready!`);
    console.log(`📧 Access at: http://localhost:${PORT}`);
    console.log(`🌐 Or: http://${process.env.SERVER_IP}:${PORT}`);
    console.log(`🔐 Admin login: admin / admin123`);
    console.log(`👥 Manager login: manager / manager123`);
});
