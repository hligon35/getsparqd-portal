const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');

const router = express.Router();

// User roles and permissions
const ROLES = {
    ADMIN: 'admin',
    MANAGER: 'manager', 
    CLIENT: 'client'
};

const PERMISSIONS = {
    [ROLES.ADMIN]: ['*'], // All permissions
    [ROLES.MANAGER]: [
        'dashboard:read',
        'emails:read', 'emails:create', 'emails:update', 'emails:delete',
        'domains:read', 'domains:create', 'domains:update',
        'storage:read', 'dns:read', 'dns:test',
        'logs:read', 'settings:read',
        'users:read', 'users:update'
    ],
    [ROLES.CLIENT]: [
        'dashboard:read',
        'emails:read',
        'domains:read',  
        'storage:read',
        'profile:read', 'profile:update'
    ]
};

const users = [
    {
        id: 1,
        username: 'hligon',
        email: 'hligon@getsparqd.com',
        password: '$2b$10$YylpldJdY2HSz8wnhvMKBecD7f1cm83HS.Q6nsurOwLzIFsKC94f6',
        role: ROLES.ADMIN,
        name: 'Harold Ligon'
    },
    {
        id: 2,
        username: 'bhall',
        email: 'bhall@getsparqd.com', 
        password: '$2b$10$YylpldJdY2HSz8wnhvMKBecD7f1cm83HS.Q6nsurOwLzIFsKC94f6',
        role: ROLES.ADMIN,
        name: 'Bryan Hall'
    }
];

const adminUsers = users.filter(user => user.role === ROLES.ADMIN);
const managers = [];
const clients = [];

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token && !req.session.user) {
        return res.status(401).json({ error: 'Access token required' });
    }
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET || 'email-admin-secret', (err, user) => {
            if (err) return res.status(403).json({ error: 'Invalid token' });
            req.user = user;
            next();
        });
    } else if (req.session.user) {
        req.user = req.session.user;
        next();
    }
};

const checkPermission = (requiredPermission) => {
    return (req, res, next) => {
        const userRole = req.user.role;
        const permissions = PERMISSIONS[userRole] || [];
        if (permissions.includes('*') || permissions.includes(requiredPermission)) {
            next();
        } else {
            res.status(403).json({ 
                error: 'Insufficient permissions',
                required: requiredPermission,
                userRole: userRole
            });
        }
    };
};

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = users.find(u => u.username === username || u.email === username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ 
            id: user.id, 
            username: user.username, 
            role: user.role,
            email: user.email,
            name: user.name
        }, process.env.JWT_SECRET || 'email-admin-secret', { expiresIn: '24h' });
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            email: user.email,
            name: user.name
        };
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                name: user.name,
                permissions: PERMISSIONS[user.role]
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logged out successfully' });
});

router.get('/me', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (user) {
        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            name: user.name,
            permissions: PERMISSIONS[user.role]
        });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

router.post('/create-client-access', authenticateToken, checkPermission('domains:create'), async (req, res) => {
    const { domain, clientEmail, clientName } = req.body;
    try {
        const tempPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(tempPassword, 10);
        const clientUser = {
            id: users.length + 1,
            username: `client_${domain.replace(/\./g, '_')}`,
            email: clientEmail,
            password: hashedPassword,
            role: ROLES.CLIENT,
            name: clientName,
            domain: domain,
            created: new Date().toISOString()
        };
        users.push(clientUser);
        clients.push(clientUser);
        const token = jwt.sign({
            id: clientUser.id,
            username: clientUser.username,
            role: clientUser.role,
            domain: domain
        }, process.env.JWT_SECRET || 'email-admin-secret', { expiresIn: '30d' });
        res.json({
            success: true,
            clientAccess: {
                username: clientUser.username,
                tempPassword,
                loginUrl: `https://admin.getsparqd.com/client/${domain}`,
                token
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create client access' });
    }
});

module.exports = {
    router,
    authenticateToken,
    checkPermission,
    ROLES,
    PERMISSIONS,
    adminUsers,
    managers,
    clients,
    users // Add users export
};
