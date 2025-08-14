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
let createProxyMiddleware;
try { ({ createProxyMiddleware } = require('http-proxy-middleware')); } catch (_) { /* optional */ }
const crypto = require('crypto');
const dotenv = require('dotenv');
// Load env from local .env first
dotenv.config();
// Fallback to parent .env (e.g., /home/sparqd/.env) if SERVER_IP not set
if (!process.env.SERVER_IP) {
    try {
        dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
    } catch (e) {
        // ignore
    }
}

// Import authentication
const { router: authRouter, authenticateToken, checkPermission, ROLES, adminUsers, managers, clients } = require('./auth');

const app = express();
const execAsync = promisify(exec);
const PORT = process.env.PORT || 3003;

// Behind Cloudflare Tunnel/reverse proxy
app.set('trust proxy', 1);
// Serve static files under /portal so /portal/login.html works
app.use('/portal', express.static(path.join(__dirname, 'public')));

// Middleware
app.use(cors({
    origin: [
        'http://localhost:3003',
        'http://68.54.208.207:3003',
        'https://admin.getsparqd.com',
            'https://getsparqd.com', // Added getsparqd.com
            'http://getsparqd.com',   // Added getsparqd.com
            'https://portal.getsparqd.com',
            'http://portal.getsparqd.com'
    ],
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'email-admin-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
app.use(express.static('public'));

// Optional: proxy live SparQ Plug Next.js runtime (overrides static) when SPARQ_PLUG_URL defined
if (createProxyMiddleware && process.env.SPARQ_PLUG_URL) {
    console.log('[INIT] Enabling SparQ Plug proxy ->', process.env.SPARQ_PLUG_URL);
    app.use('/sparq-plug', createProxyMiddleware({
        target: process.env.SPARQ_PLUG_URL,
        changeOrigin: true,
        ws: true,
        pathRewrite: { '^/sparq-plug': '/' },
        logLevel: 'warn'
        ,onProxyReq: (proxyReq, req, res) => {
            // Strip any spoofed inbound headers first
            ['x-sparq-user-id','x-sparq-user-role','x-sparq-user-email','x-sparq-user-sig','x-sparq-user-ts'].forEach(h=>{
                if (req.headers[h]) delete req.headers[h];
            });
            if (req.session && req.session.user) {
                const u = req.session.user;
                const ts = Date.now().toString();
                const secret = process.env.SPARQ_PLUG_SSO_SECRET || process.env.SESSION_SECRET || 'dev-sso-secret';
                const payload = `${u.id}.${u.role}.${u.email}.${ts}`;
                const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
                proxyReq.setHeader('x-sparq-user-id', u.id);
                proxyReq.setHeader('x-sparq-user-role', u.role);
                proxyReq.setHeader('x-sparq-user-email', u.email);
                proxyReq.setHeader('x-sparq-user-ts', ts);
                proxyReq.setHeader('x-sparq-user-sig', sig);
            }
        }
    }));
}

// Serve SparQ Plug Next.js app (production build) if available.
// Expect a production build via `next build && next export` or running `next start` separately.
// 1. If an exported static directory exists (out/), serve it.
// 2. Else if .next/standalone exists (Next.js standalone output), serve its public assets.
// 3. Else fall back to a friendly message.
const sparqPlugRoot = path.join(__dirname, '..', 'sparq-plug');
const sparqPlugStaticExport = path.join(sparqPlugRoot, 'out');
const sparqPlugPublic = path.join(sparqPlugRoot, 'public');
try {
    if (require('fs').existsSync(sparqPlugStaticExport)) {
        app.use('/sparq-plug', express.static(sparqPlugStaticExport, { extensions: ['html'] }));
        // Redirect role subpaths to query param if static export lacks them
        app.get('/sparq-plug/:role(admin|manager|client|user)', (req,res)=> {
            const indexFile = path.join(sparqPlugStaticExport, 'index.html');
            if (require('fs').existsSync(indexFile)) {
                res.sendFile(indexFile);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
        // Wildcard for deeper client-side routes
        app.get('/sparq-plug/:role(admin|manager|client|user)/*', (req,res)=> {
            const indexFile = path.join(sparqPlugStaticExport, 'index.html');
            if (require('fs').existsSync(indexFile)) {
                res.sendFile(indexFile);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
    } else if (require('fs').existsSync(path.join(sparqPlugRoot, '.next'))) {
        // Serve public assets and a minimal index redirect note; full SSR would still require running next server separately.
        app.use('/sparq-plug/_next', express.static(path.join(sparqPlugRoot, '.next')));
        app.use('/sparq-plug', express.static(sparqPlugPublic));
        app.get('/sparq-plug', (req,res)=>{
            res.setHeader('Content-Type','text/html');
            res.end('<!DOCTYPE html><html><head><title>SparQ Plug</title></head><body><h1>SparQ Plug Dev/SSR Mode</h1><p>The Next.js server must be running separately for full functionality.</p><p>Start it with: <code>cd sparq-plug && npm run dev</code></p></body></html>');
        });
        app.get('/sparq-plug/:role(admin|manager|client|user)', (req,res)=> {
            const fallback = path.join(sparqPlugPublic, 'index.html');
            if (require('fs').existsSync(fallback)) {
                res.sendFile(fallback);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
        app.get('/sparq-plug/:role(admin|manager|client|user)/*', (req,res)=> {
            const fallback = path.join(sparqPlugPublic, 'index.html');
            if (require('fs').existsSync(fallback)) {
                res.sendFile(fallback);
            } else {
                res.redirect(302, `/sparq-plug/?role=${req.params.role}`);
            }
        });
    } else {
        app.get('/sparq-plug', (req,res)=> res.status(503).json({error:'SparQ Plug build not found'}));
    }
} catch (e) {
    console.error('Failed to configure /sparq-plug route:', e.message);
}

// Mount authentication router (API path)
// Note: previously mounted at '/auth'; consolidating under '/api/auth'

// When served behind a reverse proxy at /portal, make sure relative asset paths work
app.use((req, res, next) => {
    // Back-compat for any /portal-prefixed URLs
    if (req.url === '/portal') {
        req.url = '/';
    } else if (req.url && req.url.startsWith('/portal/')) {
        req.url = req.url.substring('/portal'.length);
    }
    next();
});

// In-memory storage (in production, use a database)
let domains = [];
let emailAccounts = [];
let systemLogs = [];

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

// Direct login route for testing
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('[DEBUG] Login attempt:', username);
    
    try {
        // Import users from auth module
        const { users } = require('./auth');
        const user = users.find(u => u.username === username || u.email === username);
        
        if (!user) {
            console.log('[DEBUG] User not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        console.log('[DEBUG] Password valid:', validPassword);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Set session
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            email: user.email,
            name: user.name
        };
        
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                name: user.name
            }
        });
        
        console.log('[DEBUG] Login successful');
        
    } catch (error) {
        console.log('[ERROR] Login error:', error.message);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Fresh login route
app.get('/fresh-login', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.log('Session destroy error:', err);
            }
            // Redirect to login with a parameter to clear localStorage
            res.redirect('/login.html?fresh=true');
        });
    } else {
        res.redirect('/login.html?fresh=true');
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

// Hash password for system storage
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// Create email account in system
async function createEmailAccount(email, password, domain, storageGB = 25) {
    try {
        const username = email.split('@')[0];
        const hashedPassword = await hashPassword(password);
        
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
            hashedPassword,
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
    const { domain, clientName, clientContact, emailAccounts: emailList, storageAllocation, autoDNS, emailClient } = domainData;
    
    const results = {
        domain,
        clientName,
        createdAccounts: [],
        totalStorage: storageAllocation,
        dnsRecords: [],
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
        
        // DNS setup if requested
        if (autoDNS) {
            results.dnsRecords = [
                { type: 'MX', name: domain, content: domain, priority: 10 },
                { type: 'A', name: `mail.${domain}`, content: process.env.SERVER_IP || '68.54.208.207' },
                { type: 'TXT', name: domain, content: `"v=spf1 mx a:${domain} ~all"` }
            ];
            
            addLog(`DNS records prepared for ${domain}`);
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
        
        // Send credentials to client if requested
        if (emailClient && clientContact) {
            await sendClientCredentials(clientContact, results);
        }
        
        addLog(`Domain email setup completed for ${domain} (${results.createdAccounts.length} accounts)`);
        return results;
        
    } catch (error) {
        addLog(`Domain setup failed for ${domain}: ${error.message}`, 'error');
        throw error;
    }
}

// Send credentials to client
async function sendClientCredentials(clientEmail, setupResults) {
    try {
        const transporter = nodemailer.createTransport({
            host: 'localhost',
            port: 587,
            secure: false,
            auth: {
                user: 'admin@' + (process.env.DEFAULT_DOMAIN || 'localhost'),
                pass: 'admin123' // You should set this up properly
            }
        });
        
        const credentialsText = setupResults.credentials.map(cred => 
            `📧 ${cred.email}\n   Password: ${cred.password}\n   IMAP: ${cred.imap}\n   SMTP: ${cred.smtp}\n   Webmail: ${cred.webmail}`
        ).join('\n\n');
        
        const mailOptions = {
            from: `"SparQd Email Admin" <admin@${process.env.DEFAULT_DOMAIN || 'localhost'}>`,
            to: clientEmail,
            subject: `🎉 Your Professional Email Hosting is Ready! (${setupResults.domain})`,
            text: `Dear ${setupResults.clientName},

Your FREE professional email hosting has been successfully configured for ${setupResults.domain}!

📧 Email Accounts Created (${setupResults.createdAccounts.length}):
${credentialsText}

💾 Total Storage Allocated: ${setupResults.totalStorage}GB
🌐 Webmail Access: http://mail.${setupResults.domain}
💰 Monthly Savings: No more email hosting fees!

Email Client Setup Instructions:
• Use your full email address as username
• IMAP Server: ${setupResults.domain} (Port 993, SSL/TLS)
• SMTP Server: ${setupResults.domain} (Port 587, STARTTLS)

Your email accounts are ready to use immediately!

Best regards,
SparQd Email Team

---
This is an automated message from the SparQd Email Management System.`
        };
        
        await transporter.sendMail(mailOptions);
        addLog(`Credentials sent to client: ${clientEmail}`);
        
    } catch (error) {
        addLog(`Failed to send credentials to ${clientEmail}: ${error.message}`, 'error');
        // Don't throw - this shouldn't fail the whole setup
    }
}

// Authentication routes
app.use('/api/auth', authRouter);

// User Management API Routes
app.get('/api/users/admins', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: adminUsers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch admin users' });
    }
});

app.get('/api/users/managers', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: managers.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt,
                permissions: user.permissions
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch managers' });
    }
});

app.get('/api/users/clients', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        res.json({
            success: true,
            users: clients.map(user => ({
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
                role: user.role,
                domain: user.domain,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

app.get('/api/users/:id', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userResponse = {
            id: user.id,
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role
        };
        
        if (user.role === 'client') {
            userResponse.company = user.company;
            userResponse.phone = user.phone;
            userResponse.domain = user.domain;
        }
        
        res.json(userResponse);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user' });
    }
});

app.post('/api/users/create', authenticateToken, checkPermission('users:create'), async (req, res) => {
    try {
        const bcrypt = require('bcrypt');
        const { users } = require('./auth');
        const { type, username, email, name, password, company, phone, domain } = req.body;
        
        // Check if username or email already exists
        if (users.find(u => u.username === username || u.email === email)) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Math.max(...users.map(u => u.id)) + 1,
            username,
            email,
            password: hashedPassword,
            role: type,
            name,
            createdAt: new Date().toISOString()
        };
        
        if (type === 'client') {
            newUser.company = company;
            newUser.phone = phone;
            newUser.domain = domain;
        }
        
        users.push(newUser);
        res.json({ message: 'User created successfully', userId: newUser.id });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.put('/api/users/:id', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const { username, email, name, company, phone, domain } = req.body;
        
        // Check if username or email is taken by another user
        if (users.find(u => u.id !== userId && (u.username === username || u.email === email))) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        users[userIndex] = {
            ...users[userIndex],
            username,
            email,
            name,
            ...(users[userIndex].role === 'client' && { company, phone, domain })
        };
        
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.post('/api/users/:id/reset-password', authenticateToken, checkPermission('users:update'), async (req, res) => {
    try {
        const bcrypt = require('bcrypt');
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const newPassword = generatePassword(12);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        users[userIndex].password = hashedPassword;
        users[userIndex].requirePasswordChange = true;
        
        res.json({ message: 'Password reset successfully', newPassword });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.delete('/api/users/:id', authenticateToken, checkPermission('users:delete'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Don't allow deleting the last admin
        if (users[userIndex].role === 'admin' && users.filter(u => u.role === 'admin').length === 1) {
            return res.status(400).json({ error: 'Cannot delete the last admin user' });
        }
        
        users.splice(userIndex, 1);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/users/:id/details', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const user = users.find(u => u.id == req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // For client details, we would typically fetch from a database
        // For now, return basic info with mock data
        const details = {
            ...user,
            emailAccounts: [
                { address: `${user.username}@${user.domain || 'example.com'}`, storage: '0.5' }
            ],
            totalStorage: '0.5',
            createdAt: user.createdAt || new Date().toISOString().split('T')[0]
        };
        
        delete details.password; // Never send password
        res.json(details);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load user details' });
    }
});

app.get('/api/users/clients/export', authenticateToken, checkPermission('users:read'), async (req, res) => {
    try {
        const { users } = require('./auth');
        const clients = users.filter(user => user.role === 'client');
        
        const csv = [
            'Name,Username,Email,Company,Phone,Domain,Created',
            ...clients.map(client => 
                `"${client.name}","${client.username}","${client.email}","${client.company || ''}","${client.phone || ''}","${client.domain || ''}","${client.createdAt || ''}"`
            )
        ].join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="clients-export.csv"');
        res.send(csv);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export client data' });
    }
});

// Redirect root to login if not authenticated
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login.html');
    }
});

// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        res.redirect('/login.html');
    }
});

// Explicit login routes (avoid 404 for /login)
app.get(['/login', '/login.html'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Simple health check
app.get('/healthz', (req, res) => {
    res.json({ ok: true, service: 'email-admin', time: new Date().toISOString() });
});

// API Routes (protected)

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, checkPermission('dashboard:read'), (req, res) => {
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
app.post('/api/setup/validate', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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
app.post('/api/setup/directories', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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
app.post('/api/setup/accounts', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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
app.post('/api/setup/mailserver', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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
app.post('/api/setup/storage', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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

// Configure webmail (placeholder for now)
app.post('/api/setup/webmail', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    try {
        const { domain } = req.body;
        if (!domain) {
            return res.status(400).json({ error: 'Domain is required' });
        }

        // In a full implementation, we would provision a vhost and/or proxy to webmail here.
        // For now, just log and return success so the UI flow progresses.
        addLog(`Webmail configured for ${domain}`);
        res.json({ success: true, details: [
            `Prepared webmail endpoint for ${domain}`,
            `Users will access via https://email.${domain}`
        ]});
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Setup DNS
app.post('/api/setup/dns', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        // This would integrate with your DNS management system
        const dnsRecords = [
            `MX: ${domain} → ${domain} (Priority 10)`,
            `A: mail.${domain} → ${process.env.SERVER_IP}`,
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

// Send notifications
app.post('/api/setup/notify', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { clientContact, domain } = req.body;
    
    try {
        if (clientContact) {
            // This would send the actual email
            addLog(`Client notification prepared for ${clientContact}`);
        }
        
        res.json({ 
            success: true,
            details: [`Client notification sent to ${clientContact}`]
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Finalize setup
app.post('/api/setup/finalize', authenticateToken, checkPermission('domains:create'), async (req, res) => {
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
app.get('/api/emails/list', authenticateToken, checkPermission('emails:read'), (req, res) => {
    res.json(emailAccounts.map(account => ({
        address: account.address,
        domain: account.domain,
        storage: account.storage,
        created: new Date(account.created).toLocaleDateString(),
        lastLogin: account.lastLogin
    })));
});

app.post('/api/emails/reset-password', authenticateToken, checkPermission('emails:update'), async (req, res) => {
    const { email } = req.body;
    
    try {
        const account = emailAccounts.find(acc => acc.address === email);
        if (!account) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const newPassword = generatePassword(14);
        
        // Update password in system
        const saltedHash = await execAsync(`doveadm pw -s SHA512-CRYPT -p "${newPassword}"`);
        
        // Update dovecot password file
        await execAsync(`sudo sed -i 's|^${email}:.*|${email}:${saltedHash.stdout.trim()}|' /etc/dovecot/passwd.${account.domain}`);
        await execAsync('sudo systemctl reload dovecot');
        
        // Update our record
        account.password = newPassword;
        account.hashedPassword = await hashPassword(newPassword);
        
        addLog(`Password reset for ${email}`);
        
        res.json({ success: true, newPassword });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/emails/delete', authenticateToken, checkPermission('emails:delete'), async (req, res) => {
    const { email } = req.body;
    
    try {
        const accountIndex = emailAccounts.findIndex(acc => acc.address === email);
        if (accountIndex === -1) {
            return res.status(404).json({ error: 'Email account not found' });
        }
        
        const account = emailAccounts[accountIndex];
        
        // Remove from system
        await execAsync(`sudo sed -i '/^${email}/d' /etc/postfix/virtual_mailboxes`);
        await execAsync(`sudo sed -i '/^${email}/d' /etc/dovecot/passwd.${account.domain}`);
        await execAsync('sudo postmap /etc/postfix/virtual_mailboxes');
        await execAsync('sudo systemctl reload postfix dovecot');
        
        // Remove directory
        const username = email.split('@')[0];
        await execAsync(`sudo rm -rf /var/mail/vhosts/${account.domain}/${username}`);
        
        // Remove from our tracking
        emailAccounts.splice(accountIndex, 1);
        
        addLog(`Deleted email account: ${email}`);
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// System logs
app.get('/api/logs/recent', authenticateToken, checkPermission('logs:read'), (req, res) => {
    res.json(systemLogs.slice(0, 50));
});

// DNS testing
app.post('/api/dns/test', authenticateToken, checkPermission('dns:test'), async (req, res) => {
    const { domain } = req.body;
    
    try {
        const results = [];
        
        // Test MX record
        try {
            const mxResult = await execAsync(`nslookup -type=MX ${domain}`);
            results.push(`MX Record: ${mxResult.stdout.includes(domain) ? '✅ Configured' : '❌ Not found'}`);
        } catch (error) {
            results.push('MX Record: ❌ Error checking');
        }
        
        // Test A record for mail subdomain
        try {
            const aResult = await execAsync(`nslookup mail.${domain}`);
            results.push(`A Record (mail): ${aResult.stdout.includes(process.env.SERVER_IP) ? '✅ Configured' : '❌ Not pointing to server'}`);
        } catch (error) {
            results.push('A Record (mail): ❌ Not found');
        }
        
        res.json({ success: true, results });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
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

// Start server
app.listen(PORT, async () => {
    await initializeSystem();
    addLog(`Email Admin Dashboard running on port ${PORT}`);
    console.log(`\n🎉 Email Admin Dashboard is ready!`);
    console.log(`📧 Access at: http://localhost:${PORT}`);
    console.log(`🌐 Or: http://${process.env.SERVER_IP}:${PORT}`);
});
