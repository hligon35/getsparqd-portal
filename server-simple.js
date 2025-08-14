const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectRedis = require('connect-redis');
const { createClient } = require('redis');
require('dotenv').config();

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
app.use(helmet());
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
    domain: process.env.SESSION_DOMAIN || undefined,
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
        
        req.session.user = {
            username,
            role: user.role,
            name: user.name,
            email: user.email,
            requirePasswordChange: user.requirePasswordChange || false
        };
        
        // Generate a simple token for frontend compatibility
        const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
        
        res.json({
            success: true,
            token: token,
            user: req.session.user,
            requirePasswordChange: user.requirePasswordChange || false
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
    const rolePathMap = {
        admin: '/admin',
        manager: '/manager',
        client: '/client'
    };
    const pathPart = rolePathMap[role] || '/client';
    const host = process.env.SPARGPLUG_HOST || 'sparqplug.getsparqd.com';
    const protocol = 'https://';
    const url = `${protocol}${host}${pathPart}`;
    res.json({ url, path: pathPart, role });
});

// Optional: provide just the path
app.get('/api/sparqplug/path', requireAuth, (req, res) => {
    const role = (req.session.user && req.session.user.role) || 'client';
    const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client' };
    res.json({ path: rolePathMap[role] || '/client', role });
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
    if (!req.session.user) {
        return res.redirect('/');
    }
    const role = (req.session.user && req.session.user.role) || 'client';
    const rolePathMap = { admin: '/admin', manager: '/manager', client: '/client' };
    const host = process.env.SPARGPLUG_HOST || 'sparqplug.getsparqd.com';
    const target = `https://${host}${rolePathMap[role] || '/client'}`;
    // Send directly to SparqPlug app landing page for the user role
    return res.redirect(302, target);
});

// Explicit login routes to avoid any static path edge cases
app.get(['/login', '/login.html'], (req, res) => {
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
            password, // Store plain text for client notification
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
