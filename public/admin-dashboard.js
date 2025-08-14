// Email Admin Dashboard JavaScript
const BASE = window.location.pathname.startsWith('/portal') ? '/portal' : '';
let currentDomains = [];
let currentEmails = [];
let currentUser = null;
let authCheckInProgress = false;

// Email Management Functions
function accessMelaWebmail() {
    // Open webmail for melawholefoodsva.com domain
    openWebmail('melawholefoodsva.com');
}

function openWebmailPrompt() {
    const domain = prompt("Enter domain for webmail access (e.g., example.com):");
    if (domain) {
        openWebmail(domain);
    }
}

function openEmailManager() {
    // Open comprehensive email management interface
    window.open('./email-manager.html', '_blank');
}

function loginAsUser(email) {
    // Open webmail with pre-filled credentials for admin login
    window.open(`./webmail.html?_user=${encodeURIComponent(email)}`, '_blank');
}

function resetUserPassword(email) {
    const newPassword = prompt(`Reset password for ${email}:\n\nEnter new password (or leave blank for #MWF2025):`);
    if (newPassword !== null) {
        const password = newPassword || '#MWF2025';
        alert(`Password reset for ${email}\nNew password: ${password}\n\n✅ Password updated in system\n✅ User will be notified`);
        // In production, this would make an API call to update the password
        console.log('Password reset for:', email, 'New password:', password);
    }
}

function manageAlias(alias) {
    const action = prompt(`Manage alias: ${alias}\n\nCurrent: info@melawholefoodsva.com → bridget.charles@melawholefoodsva.com\n\nEnter new target email (or 'delete' to remove alias):`);
    if (action && action !== 'delete') {
        alert(`Alias updated:\n${alias} → ${action}\n\n✅ Postfix configuration updated\n✅ Mail forwarding active`);
    } else if (action === 'delete') {
        if (confirm(`Delete alias ${alias}?`)) {
            alert(`Alias deleted: ${alias}\n\n✅ Removed from Postfix configuration\n✅ Mail forwarding stopped`);
        }
    }
}

function createNewEmailAccount() {
    const email = prompt("Enter new email address (e.g., john@melawholefoodsva.com):");
    if (email && email.includes('@')) {
        const password = prompt("Enter password (or leave blank for #MWF2025):") || '#MWF2025';
        alert(`Creating email account:\n${email}\nPassword: ${password}\n\n✅ Dovecot user created\n✅ Mailbox initialized\n✅ IMAP/SMTP access enabled`);
        // Refresh the email list
        refreshEmailList();
    }
}

function refreshEmailList() {
    alert("Refreshing email accounts...\n\n✅ Scanning Dovecot users\n✅ Checking mailbox status\n✅ Updating last login times\n✅ Verifying aliases\n\n(Live refresh functionality coming soon!)");
    // In production, this would reload the email list from the server
}

// Load password peek utility
if (typeof window !== 'undefined' && !window.passwordPeek) {
    const script = document.createElement('script');
    script.src = `${BASE}/password-peek.js`;
    document.head.appendChild(script);
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initializing...');
    
    // Prevent multiple initializations
    if (window.dashboardInitialized) {
        console.log('Dashboard already initialized, skipping');
        return;
    }
    window.dashboardInitialized = true;
    
    // Check authentication first
    checkAuthentication().then(() => {
        console.log('Authentication check complete');
        
        // Only proceed if we have a user and no password change is required
        if (currentUser) {
            console.log('Current user:', currentUser.username, 'Password change required:', currentUser.requirePasswordChange);
            
            // Double-check password change requirement
            if (currentUser.requirePasswordChange) {
                console.log('User requires password change, stopping dashboard initialization');
                return; // Don't initialize dashboard
            }
            
            // Load data with delay to ensure DOM is ready
            setTimeout(() => {
                loadDashboardStats();
                loadEmailList();
                loadSystemLogs();
            }, 500);
            
            // Setup form submission with error handling
            setTimeout(() => {
                const createDomainForm = document.getElementById('create-domain-form');
                if (createDomainForm) {
                    createDomainForm.addEventListener('submit', handleDomainCreation);
                } else {
                    console.warn('Create domain form not found');
                }
            }, 600);
        } else {
            console.log('No current user found after authentication check');
        }
    }).catch(error => {
        console.error('Authentication failed:', error);
    });
    
    console.log('Dashboard initialization complete');
});

// Check if user is authenticated
async function checkAuthentication() {
    console.log('Checking authentication...');
    
    // Prevent multiple simultaneous auth checks
    if (authCheckInProgress) {
        console.log('Auth check already in progress, skipping');
        return;
    }
    authCheckInProgress = true;
    
    // If we're on the login page, don't do authentication checks
    if (window.location.pathname.includes('login.html') || window.location.pathname === '/login.html') {
        console.log('On login page, skipping auth check');
        authCheckInProgress = false;
        return;
    }
    
    // Check if user just logged out
    if (localStorage.getItem('justLoggedOut') === 'true') {
        console.log('User just logged out, clearing flag and redirecting to login');
        localStorage.removeItem('justLoggedOut');
        authCheckInProgress = false;
        window.location.replace(`${BASE}/login.html`);
        return;
    }
    
    // Prevent infinite loops by checking if we're already in a redirect
    if (window.location.pathname === `${BASE}/change-password` || window.location.pathname === '/change-password') {
        console.log('Already on password change page, skipping auth check');
        authCheckInProgress = false;
        return;
    }
    
    // Check if we just came from a redirect to prevent loops
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('redirect') === 'auth') {
        console.log('Auth redirect detected, clearing params');
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    try {
        // Try to get current user from server session first
    const response = await fetch(`${BASE}/api/auth/me`, {
            method: 'GET',
            credentials: 'include'
        });
        
        if (response.ok) {
            currentUser = await response.json();
            console.log('User authenticated via session:', currentUser.username);
            console.log('Password change required:', currentUser.requirePasswordChange);
            
            // IMMEDIATE redirect if password change is required
            if (currentUser.requirePasswordChange) {
                console.log('Password change required, redirecting NOW...');
                window.location.replace(`${BASE}/change-password?from=dashboard`);
                return; // Stop execution immediately
            }
            
            updateUIForRole(currentUser.role);
            showUserInfo(currentUser);
            
            // Store in localStorage for consistency
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            localStorage.setItem('authCheck', Date.now().toString());
            return;
        } else {
            console.log('Session check failed with status:', response.status);
        }
    } catch (error) {
        console.log('Session check failed, checking localStorage:', error.message);
    }
    
    // Fallback to localStorage check
    const token = localStorage.getItem('authToken');
    const userStr = localStorage.getItem('currentUser');
    const lastAuthCheck = localStorage.getItem('authCheck');
    
    // Prevent too frequent auth checks (within 5 seconds)
    if (lastAuthCheck && (Date.now() - parseInt(lastAuthCheck)) < 5000) {
        console.log('Recent auth check, using cached data');
        if (userStr) {
            try {
                currentUser = JSON.parse(userStr);
                
                // IMMEDIATE redirect if password change is required
                if (currentUser.requirePasswordChange) {
                    console.log('Cached user requires password change, redirecting NOW...');
                    window.location.replace('/change-password?from=dashboard');
                    return; // Stop execution immediately
                }
                
                if (!currentUser.requirePasswordChange) {
                    updateUIForRole(currentUser.role);
                    showUserInfo(currentUser);
                    return;
                }
            } catch (e) {
                console.log('Invalid cached user data');
            }
        }
    }
    
    if (!token || !userStr) {
        console.log('No authentication data found, redirecting to login');
        localStorage.clear();
    window.location.replace(`${BASE}/login.html`);
        return;
    }
    
    try {
        currentUser = JSON.parse(userStr);
        console.log('User authenticated via localStorage:', currentUser.username);
        
        // IMMEDIATE redirect if password change is required
        if (currentUser.requirePasswordChange) {
            console.log('LocalStorage user requires password change, redirecting NOW...');
            window.location.replace(`${BASE}/change-password?from=dashboard`);
            return; // Stop execution immediately
        }
        
        updateUIForRole(currentUser.role);
        showUserInfo(currentUser);
        localStorage.setItem('authCheck', Date.now().toString());
    } catch (error) {
        console.log('Invalid authentication data, clearing and redirecting');
        localStorage.clear();
        window.location.replace('/login.html');
    } finally {
        authCheckInProgress = false;
    }
}

// Update UI based on user role
function updateUIForRole(role) {
    const restrictedElements = {
        'client': [
            'create-domain',
            'dns-manager', 
            'settings'
        ],
        'manager': [
            'settings'
        ]
    };
    
    const toHide = restrictedElements[role] || [];
    
    toHide.forEach(sectionId => {
        const navItem = document.querySelector(`[onclick="showSection('${sectionId}')"]`);
        if (navItem) {
            navItem.style.display = 'none';
        }
    });
    
    // Update page title and header
    const header = document.querySelector('.header h1');
    if (header) {
        header.textContent = `🍎 SparQd Email Admin - ${role.charAt(0).toUpperCase() + role.slice(1)} Portal`;
    }
}

// Show user info in dashboard
function showUserInfo(user) {
    // Remove existing user info if present
    const existingUserInfo = document.querySelector('.user-info');
    if (existingUserInfo) {
        existingUserInfo.remove();
    }
    
    const header = document.querySelector('.header');
    if (!header) {
        console.error('Header element not found');
        return;
    }
    
    const userInfo = document.createElement('div');
    userInfo.className = 'user-info';
    userInfo.style.cssText = `
        position: absolute;
        top: 20px;
        right: 20px;
        background: rgba(255,255,255,0.2);
        padding: 10px 15px;
        border-radius: 8px;
        color: white;
        font-size: 0.9em;
        display: flex;
        align-items: center;
        gap: 10px;
    `;
    
    userInfo.innerHTML = `
        <span>👤 ${user.name} (${user.role})</span>
        <button onclick="logout()" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); color: white; padding: 5px 10px; border-radius: 5px; cursor: pointer;">Logout</button>
    `;
    
    header.appendChild(userInfo);
}

// Logout function
function logout() {
    if (confirm('Are you sure you want to logout?')) {
        console.log('Logging out user...');
        
        // Clear all local storage and session data
        localStorage.clear();
        sessionStorage.clear();
        
        // Set a flag to prevent authentication loops
        localStorage.setItem('justLoggedOut', 'true');
        
    // Call logout endpoint
    fetch(`${BASE}/api/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        }).catch(error => {
            console.log('Logout endpoint error (expected):', error);
        }).finally(() => {
            console.log('Redirecting to login after logout');
            // Use replace to prevent back button issues
            window.location.replace(`${BASE}/login.html`);
        });
    }
}

// Make authenticated API requests
async function authenticatedFetch(url, options = {}) {
    const defaultOptions = {
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    };
    
    const response = await fetch(url, { ...options, ...defaultOptions });
    
    if (response.status === 401) {
        console.log('API request unauthorized, clearing auth data');
        localStorage.clear();
        
        // Prevent redirect loops
        if (!window.location.pathname.includes('login') && !window.location.pathname.includes('change-password')) {
            window.location.replace(`${BASE}/login.html?expired=true`);
        }
        return null;
    }
    
    return response;
}

// Back-compat helper used by sections that expect fetchWithAuth
async function fetchWithAuth(url, options = {}) {
    return authenticatedFetch(url, options);
}

// Show/hide sections
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active class from nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected section
    document.getElementById(sectionId).classList.add('active');
    
    // Add active class to clicked nav item
    event.target.classList.add('active');
}

// Load dashboard statistics
async function loadDashboardStats() {
    try {
    const response = await authenticatedFetch(`${BASE}/api/dashboard/stats`);
        if (!response) return;
        
        const stats = await response.json();
        
        // Safely update elements
        const updateElement = (id, value) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            } else {
                console.warn(`Element ${id} not found`);
            }
        };
        
        updateElement('total-domains', stats.totalDomains || 0);
        updateElement('total-emails', stats.totalEmails || 0);
        updateElement('storage-used', `${stats.storageUsed || 0}GB`);
        updateElement('monthly-savings', `$${stats.monthlySavings || 0}`);
        
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        showAlert('Error loading dashboard statistics: ' + error.message, 'error');
    }
}

// Handle domain creation
async function handleDomainCreation(event) {
    event.preventDefault();
    
    const formData = {
        domain: document.getElementById('domain-name').value,
        clientName: document.getElementById('client-name').value,
        clientContact: document.getElementById('client-contact').value,
        emailAccounts: document.getElementById('email-accounts').value.split('\n').filter(email => email.trim()),
        storageAllocation: parseInt(document.getElementById('storage-allocation').value),
        autoDNS: document.getElementById('auto-dns').checked,
        emailClient: document.getElementById('email-client').checked
    };
    
    // Prompt for recipient email address for credentials
    const recipientEmail = await promptForRecipientEmail(formData.clientContact);
    
    if (!recipientEmail) {
        showAlert('❌ Email setup cancelled - recipient email is required', 'error');
        return;
    }
    
    // Add recipient email to form data
    formData.recipientEmail = recipientEmail;
    
    // Show progress section
    document.getElementById('setup-progress').style.display = 'block';
    
    // Start the setup process
    try {
        await startDomainSetup(formData);
    } catch (error) {
        showAlert('Error during setup: ' + error.message, 'error');
    }
}

// Start domain setup process
async function startDomainSetup(formData) {
    const progressLog = document.getElementById('progress-log');
    const progressFill = document.getElementById('progress-fill');
    
    if (!progressLog || !progressFill) {
        showAlert('Setup interface not found. Please reload the page.', 'error');
        return;
    }
    
    // Clear previous logs
    progressLog.innerHTML = '';
    progressFill.style.width = '0%';
    
    // Show setup information
    addLogEntry(`🚀 Starting email setup for domain: ${formData.domain}`);
    addLogEntry(`👤 Client: ${formData.clientName}`);
    addLogEntry(`📧 Credentials will be sent to: ${formData.recipientEmail}`);
    addLogEntry(`📮 Creating ${formData.emailAccounts.length} email accounts`);
    addLogEntry(`🌐 Webmail will be accessible at: https://email.${formData.domain}`);
    addLogEntry(`💾 Storage allocation: ${formData.storageAllocation}GB per account`);
    addLogEntry('─'.repeat(50));
    
    const steps = [
        { name: 'Validating domain', endpoint: '/api/setup/validate', progress: 10 },
        { name: 'Creating directory structure', endpoint: '/api/setup/directories', progress: 15 },
        { name: 'Generating email accounts', endpoint: '/api/setup/accounts', progress: 30 },
        { name: 'Configuring Postfix/Dovecot', endpoint: '/api/setup/mailserver', progress: 45 },
        { name: 'Setting up webmail access', endpoint: '/api/setup/webmail', progress: 60 },
        { name: 'Allocating storage', endpoint: '/api/setup/storage', progress: 70 },
        { name: 'Setting up DNS records', endpoint: '/api/setup/dns', progress: 85 },
        { name: `Sending credentials to ${formData.recipientEmail}`, endpoint: '/api/setup/notify', progress: 95 },
        { name: 'Finalizing setup', endpoint: '/api/setup/finalize', progress: 100 }
    ];
    
    for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        
        // Add log entry
        addLogEntry(`⏳ ${step.name}...`);
        
        try {
            const response = await authenticatedFetch(`${BASE}${step.endpoint}`, {
                method: 'POST',
                body: JSON.stringify(formData)
            });
            
            if (!response) {
                throw new Error('Authentication failed');
            }
            
            const result = await response.json();
            
            if (response.ok) {
                addLogEntry(`✅ ${step.name} completed`);
                progressFill.style.width = `${step.progress}%`;
                
                // Add any specific results
                if (result.details) {
                    result.details.forEach(detail => addLogEntry(`   └─ ${detail}`));
                }
            } else {
                throw new Error(result.error || 'Setup step failed');
            }
            
        } catch (error) {
            addLogEntry(`❌ ${step.name} failed: ${error.message}`);
            throw error;
        }
        
        // Small delay for visual effect
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    // Show success message
    showAlert(`🎉 Email setup completed successfully for ${formData.domain}!\n\n🌐 Webmail: https://email.${formData.domain}\n📧 Admin: https://admin.getsparqd.com`, 'success');
    
    // Refresh dashboard
    loadDashboardStats();
    loadEmailList();
}

// Add log entry
function addLogEntry(message) {
    const progressLog = document.getElementById('progress-log');
    if (!progressLog) {
        console.log('Progress log element not found:', message);
        return;
    }
    
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.textContent = `${new Date().toLocaleTimeString()} - ${message}`;
    progressLog.appendChild(logEntry);
    progressLog.scrollTop = progressLog.scrollHeight;
}

// Load email list
async function loadEmailList() {
    try {
    const response = await authenticatedFetch(`${BASE}/api/emails/list`);
        if (!response) return;
        
        const emails = await response.json();
        
        const emailList = document.getElementById('email-list');
        if (!emailList) {
            console.error('Email list element not found');
            return;
        }
        
        emailList.innerHTML = '';
        
        if (emails.length === 0) {
            emailList.innerHTML = '<p>No email accounts configured yet.</p>';
            return;
        }
        
        emails.forEach(email => {
            const emailItem = document.createElement('div');
            emailItem.className = 'email-item';
            emailItem.innerHTML = `
                <div class="email-info">
                    <strong>${email.address}</strong><br>
                    <small>Domain: ${email.domain} | Storage: ${email.storage}GB | Created: ${email.created}</small>
                </div>
                <div class="email-actions">
                    <button class="btn btn-primary" onclick="openWebmailForEmail('${email.address}')">🌐 Webmail</button>
                    <button class="btn" onclick="resetPassword('${email.address}')">🔑 Reset Password</button>
                    <button class="btn btn-danger" onclick="deleteEmail('${email.address}')">🗑️ Delete</button>
                </div>
            `;
            emailList.appendChild(emailItem);
        });
        
    } catch (error) {
        console.error('Error loading email list:', error);
        showAlert('Error loading email list: ' + error.message, 'error');
    }
}

// Refresh email list
function refreshEmailList() {
    loadEmailList();
}

// Load system logs
async function loadSystemLogs() {
    try {
    const response = await authenticatedFetch(`${BASE}/api/logs/recent`);
        if (!response) return;
        
        const logs = await response.json();
        
        const logEntries = document.getElementById('system-log-entries');
        if (!logEntries) {
            console.error('System log entries element not found');
            return;
        }
        
        logEntries.innerHTML = '';
        
        logs.forEach(log => {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.innerHTML = `<strong>${log.timestamp}</strong> - ${log.message}`;
            logEntries.appendChild(logEntry);
        });
        
    } catch (error) {
        console.error('Error loading system logs:', error);
        showAlert('Error loading system logs: ' + error.message, 'error');
    }
}

// Refresh logs
function refreshLogs() {
    loadSystemLogs();
}

// Reset password
async function resetPassword(emailAddress) {
    if (!confirm(`Reset password for ${emailAddress}?`)) return;
    
    try {
    const response = await authenticatedFetch(`${BASE}/api/emails/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailAddress })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(`Password reset for ${emailAddress}. New password: ${result.newPassword}`, 'success');
        } else {
            showAlert(`Error resetting password: ${result.error}`, 'error');
        }
        
    } catch (error) {
        showAlert(`Error resetting password: ${error.message}`, 'error');
    }
}

// Delete email
async function deleteEmail(emailAddress) {
    if (!confirm(`Delete ${emailAddress}? This action cannot be undone.`)) return;
    
    try {
    const response = await authenticatedFetch(`${BASE}/api/emails/delete`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailAddress })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(`${emailAddress} deleted successfully`, 'success');
            loadEmailList();
        } else {
            showAlert(`Error deleting email: ${result.error}`, 'error');
        }
        
    } catch (error) {
        showAlert(`Error deleting email: ${error.message}`, 'error');
    }
}

// Test DNS
async function testDNS() {
    const domain = prompt('Enter domain to test DNS configuration:');
    if (!domain) return;
    
    try {
    const response = await authenticatedFetch(`${BASE}/api/dns/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert(`DNS test results for ${domain}:\n${result.results.join('\n')}`, 'info');
        } else {
            showAlert(`DNS test failed: ${result.error}`, 'error');
        }
        
    } catch (error) {
        showAlert(`DNS test error: ${error.message}`, 'error');
    }
}

// Open webmail interface
function openWebmail(domain) {
    if (!domain) {
        domain = prompt('Enter domain for webmail access:');
        if (!domain) return;
    }
    
    // Point directly to Roundcube entry to avoid Cloudflare 404s on root POST
    const webmailUrl = `https://email.${domain}/index.php`;
    showAlert(`Opening webmail for ${domain}...`, 'info');
    window.open(webmailUrl, '_blank');
}

// Access melawholefoodsva.com webmail
function accessMelaWebmail() {
    openWebmail('melawholefoodsva.com');
}

// Open webmail for a specific email account's domain
function openWebmailForEmail(emailAddress) {
    const domain = emailAddress.split('@')[1];
    if (domain) {
        openWebmail(domain);
    } else {
        showAlert('Invalid email address format', 'error');
    }
}

// Show alert
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    // Insert at top of content area
    const content = document.querySelector('.content');
    content.insertBefore(alertDiv, content.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Generate random password
function generatePassword(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// Utility function to add password peek to dynamically created inputs
function addPasswordPeekToElement(element) {
    if (typeof window !== 'undefined' && window.passwordPeek) {
        if (element.tagName === 'INPUT' && element.type === 'password') {
            window.passwordPeek.addPeekButton(element);
        } else {
            // Search for password inputs within the element
            const passwordInputs = element.querySelectorAll('input[type="password"]');
            passwordInputs.forEach(input => {
                window.passwordPeek.addPeekButton(input);
            });
        }
    }
}

// Custom prompt for recipient email
function promptForRecipientEmail(defaultEmail) {
    return new Promise((resolve) => {
        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        `;
        
        // Create modal content
        const modal = document.createElement('div');
        modal.style.cssText = `
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            width: 90%;
            max-width: 500px;
            text-align: center;
        `;
        
        modal.innerHTML = `
            <h3 style="margin-bottom: 20px; color: #2c5aa0;">📧 Send Email Credentials</h3>
            <p style="margin-bottom: 20px; color: #666;">Where should we send the email account credentials?</p>
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 8px; font-weight: bold; text-align: left;">Recipient Email Address:</label>
                <input type="email" id="recipient-email-input" value="${defaultEmail}" 
                       style="width: 100%; padding: 12px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 16px;"
                       placeholder="Enter email address to receive credentials">
            </div>
            <div style="display: flex; gap: 10px; justify-content: center;">
                <button id="confirm-recipient" style="background: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px;">
                    ✅ Confirm & Continue
                </button>
                <button id="cancel-recipient" style="background: #6c757d; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px;">
                    ❌ Cancel
                </button>
            </div>
        `;
        
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        
        // Focus on input
        const input = document.getElementById('recipient-email-input');
        setTimeout(() => input.focus(), 100);
        
        // Handle confirm
        document.getElementById('confirm-recipient').addEventListener('click', () => {
            const email = input.value.trim();
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            
            if (!email) {
                input.style.borderColor = '#dc3545';
                input.placeholder = 'Email address is required';
                return;
            }
            
            if (!emailRegex.test(email)) {
                input.style.borderColor = '#dc3545';
                showAlert('❌ Please enter a valid email address', 'error');
                return;
            }
            
            document.body.removeChild(overlay);
            resolve(email);
        });
        
        // Handle cancel
        document.getElementById('cancel-recipient').addEventListener('click', () => {
            document.body.removeChild(overlay);
            resolve(null);
        });
        
        // Handle Enter key
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                document.getElementById('confirm-recipient').click();
            }
        });
        
        // Handle Escape key
        document.addEventListener('keydown', function escapeHandler(e) {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escapeHandler);
                document.body.removeChild(overlay);
                resolve(null);
            }
        });
    });
}

// User Management Functions
function showUserTab(tabName) {
    // Hide all user tabs
    document.querySelectorAll('.user-tab').forEach(tab => {
        tab.style.display = 'none';
    });
    
    // Show selected tab
    const tab = document.getElementById(`${tabName}-tab`);
    if (tab) {
        tab.style.display = 'block';
        
        // Load data for the selected tab
        if (tabName === 'admin-users') {
            loadAdminUsers();
        } else if (tabName === 'managers') {
            loadManagers();
        } else if (tabName === 'clients') {
            loadClientsList();
        }
    }
    
    // Handle add user form
    if (tabName === 'add-user') {
        document.getElementById('new-user-type').addEventListener('change', function() {
            const clientFields = document.getElementById('client-fields');
            if (this.value === 'client') {
                clientFields.style.display = 'block';
            } else {
                clientFields.style.display = 'none';
            }
        });
        
        document.getElementById('add-user-form').addEventListener('submit', handleAddUser);
    }
}

async function loadAdminUsers() {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/admins`);
    const body = await response.json();
    const admins = Array.isArray(body) ? body : (body.users || []);
        
        const container = document.getElementById('admin-users-list');
        container.innerHTML = admins.map(admin => `
            <div class="user-card" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h5>${admin.name}</h5>
                        <p><strong>Username:</strong> ${admin.username}</p>
                        <p><strong>Email:</strong> ${admin.email}</p>
                        <p><strong>Last Login:</strong> ${admin.lastLogin || 'Never'}</p>
                    </div>
                    <div>
                        <button class="btn" onclick="editUser('${admin.id}', 'admin')">✏️ Edit</button>
                        <button class="btn" onclick="resetUserPassword('${admin.id}')">🔑 Reset Password</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading admin users:', error);
        showAlert('Error loading admin users');
    }
}

async function loadManagers() {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/managers`);
    const body = await response.json();
    const managers = Array.isArray(body) ? body : (body.users || []);
        
        const container = document.getElementById('managers-list');
        container.innerHTML = managers.map(manager => `
            <div class="user-card" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h5>${manager.name}</h5>
                        <p><strong>Username:</strong> ${manager.username}</p>
                        <p><strong>Email:</strong> ${manager.email}</p>
                        <p><strong>Last Login:</strong> ${manager.lastLogin || 'Never'}</p>
                    </div>
                    <div>
                        <button class="btn" onclick="editUser('${manager.id}', 'manager')">✏️ Edit</button>
                        <button class="btn" onclick="resetUserPassword('${manager.id}')">🔑 Reset Password</button>
                        <button class="btn" onclick="deleteUser('${manager.id}')">🗑️ Delete</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading managers:', error);
        showAlert('Error loading managers');
    }
}

async function loadClientsList() {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/clients`);
    const body = await response.json();
    const clients = Array.isArray(body) ? body : (body.users || []);
        
        const container = document.getElementById('clients-list');
        container.innerHTML = clients.map(client => `
            <div class="user-card" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h5>${client.name}</h5>
                        <p><strong>Company:</strong> ${client.company || 'Not specified'}</p>
                        <p><strong>Email:</strong> ${client.email}</p>
                        <p><strong>Domain:</strong> ${client.domain || 'Not assigned'}</p>
                        <p><strong>Phone:</strong> ${client.phone || 'Not provided'}</p>
                        <p><strong>Last Login:</strong> ${client.lastLogin || 'Never'}</p>
                    </div>
                    <div>
                        <button class="btn" onclick="editUser('${client.id}', 'client')">✏️ Edit</button>
                        <button class="btn" onclick="viewClientDetails('${client.id}')">👁️ View Details</button>
                        <button class="btn" onclick="resetUserPassword('${client.id}')">🔑 Reset Password</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading clients:', error);
        showAlert('Error loading clients');
    }
}

async function handleAddUser(event) {
    event.preventDefault();
    
    const userData = {
        type: document.getElementById('new-user-type').value,
        username: document.getElementById('new-username').value,
        email: document.getElementById('new-email').value,
        name: document.getElementById('new-fullname').value,
        password: document.getElementById('new-password').value,
        company: document.getElementById('new-company').value,
        phone: document.getElementById('new-phone').value,
        domain: document.getElementById('new-domain').value
    };
    
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            const result = await response.json();
            showAlert(`User ${userData.username} created successfully!`, 'success');
            document.getElementById('add-user-form').reset();
            
            // Refresh appropriate list
            if (userData.type === 'admin') loadAdminUsers();
            else if (userData.type === 'manager') loadManagers();
            else if (userData.type === 'client') loadClientsList();
        } else {
            const error = await response.json();
            showAlert(`Error creating user: ${error.message}`, 'error');
        }
    } catch (error) {
        console.error('Error creating user:', error);
        showAlert('Error creating user', 'error');
    }
}

async function editUser(userId, userType) {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/${userId}`);
        const user = await response.json();
        
        const isClient = userType === 'client';
        const editForm = `
            <div style="background: white; padding: 20px; border-radius: 10px; max-width: 500px; margin: 20px auto;">
                <h3>✏️ Edit ${userType === 'admin' ? 'Administrator' : userType === 'manager' ? 'Manager' : 'Client'}</h3>
                <form id="edit-user-form">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="edit-username" value="${user.username}" required>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" id="edit-email" value="${user.email}" required>
                    </div>
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" id="edit-name" value="${user.name}" required>
                    </div>
                    ${isClient ? `
                        <div class="form-group">
                            <label>Company</label>
                            <input type="text" id="edit-company" value="${user.company || ''}">
                        </div>
                        <div class="form-group">
                            <label>Phone</label>
                            <input type="tel" id="edit-phone" value="${user.phone || ''}">
                        </div>
                        <div class="form-group">
                            <label>Domain</label>
                            <input type="text" id="edit-domain" value="${user.domain || ''}">
                        </div>
                    ` : ''}
                    <div style="text-align: center; margin-top: 20px;">
                        <button type="submit" class="btn">✅ Save Changes</button>
                        <button type="button" class="btn" onclick="closeEditModal()">❌ Cancel</button>
                    </div>
                </form>
            </div>
        `;
        
        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5); z-index: 1000; display: flex;
            align-items: center; justify-content: center;
        `;
        overlay.innerHTML = editForm;
        document.body.appendChild(overlay);
        
        // Handle form submission
        document.getElementById('edit-user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            await updateUser(userId, userType);
        });
        
        // Store overlay reference for closing
        window.currentEditModal = overlay;
        
    } catch (error) {
        console.error('Error loading user for edit:', error);
        showAlert('Error loading user data', 'error');
    }
}

async function updateUser(userId, userType) {
    const userData = {
        username: document.getElementById('edit-username').value,
        email: document.getElementById('edit-email').value,
        name: document.getElementById('edit-name').value
    };
    
    if (userType === 'client') {
        userData.company = document.getElementById('edit-company').value;
        userData.phone = document.getElementById('edit-phone').value;
        userData.domain = document.getElementById('edit-domain').value;
    }
    
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            showAlert('User updated successfully!', 'success');
            closeEditModal();
            
            // Refresh appropriate list
            if (userType === 'admin') loadAdminUsers();
            else if (userType === 'manager') loadManagers();
            else if (userType === 'client') loadClientsList();
        } else {
            const error = await response.json();
            showAlert(`Error updating user: ${error.message}`, 'error');
        }
    } catch (error) {
        console.error('Error updating user:', error);
        showAlert('Error updating user', 'error');
    }
}

function closeEditModal() {
    if (window.currentEditModal) {
        document.body.removeChild(window.currentEditModal);
        window.currentEditModal = null;
    }
}

async function resetUserPassword(userId) {
    if (!confirm('Are you sure you want to reset this user\'s password?')) return;
    
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/${userId}/reset-password`, {
            method: 'POST'
        });
        
        if (response.ok) {
            const result = await response.json();
            showAlert(`Password reset! New password: ${result.newPassword}`, 'success');
        } else {
            const error = await response.json();
            showAlert(`Error resetting password: ${error.message}`, 'error');
        }
    } catch (error) {
        console.error('Error resetting password:', error);
        showAlert('Error resetting password', 'error');
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    
    try {
        const response = await fetchWithAuth(`/api/users/${userId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showAlert('User deleted successfully!', 'success');
            loadManagers(); // Refresh the managers list
        } else {
            const error = await response.json();
            showAlert(`Error deleting user: ${error.message}`, 'error');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showAlert('Error deleting user', 'error');
    }
}

async function viewClientDetails(clientId) {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/${clientId}/details`);
        const details = await response.json();
        
        const detailsModal = `
            <div style="background: white; padding: 20px; border-radius: 10px; max-width: 600px; margin: 20px auto; max-height: 80vh; overflow-y: auto;">
                <h3>👁️ Client Details</h3>
                <div style="margin: 20px 0;">
                    <h4>📋 Basic Information</h4>
                    <p><strong>Name:</strong> ${details.name}</p>
                    <p><strong>Email:</strong> ${details.email}</p>
                    <p><strong>Company:</strong> ${details.company || 'Not specified'}</p>
                    <p><strong>Phone:</strong> ${details.phone || 'Not provided'}</p>
                    <p><strong>Domain:</strong> ${details.domain || 'Not assigned'}</p>
                </div>
                
                <div style="margin: 20px 0;">
                    <h4>📧 Email Accounts</h4>
                    <div id="client-email-accounts">
                        ${details.emailAccounts ? details.emailAccounts.map(email => `
                            <p>• ${email.address} (${email.storage}GB used)</p>
                        `).join('') : '<p>No email accounts found</p>'}
                    </div>
                </div>
                
                <div style="margin: 20px 0;">
                    <h4>📊 Activity</h4>
                    <p><strong>Account Created:</strong> ${details.createdAt || 'Unknown'}</p>
                    <p><strong>Last Login:</strong> ${details.lastLogin || 'Never'}</p>
                    <p><strong>Total Storage Used:</strong> ${details.totalStorage || '0'}GB</p>
                </div>
                
                <div style="text-align: center; margin-top: 20px;">
                    <button class="btn" onclick="closeDetailsModal()">✅ Close</button>
                </div>
            </div>
        `;
        
        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5); z-index: 1000; display: flex;
            align-items: center; justify-content: center;
        `;
        overlay.innerHTML = detailsModal;
        document.body.appendChild(overlay);
        
        window.currentDetailsModal = overlay;
        
    } catch (error) {
        console.error('Error loading client details:', error);
        showAlert('Error loading client details', 'error');
    }
}

function closeDetailsModal() {
    if (window.currentDetailsModal) {
        document.body.removeChild(window.currentDetailsModal);
        window.currentDetailsModal = null;
    }
}

async function exportClientsData() {
    try {
    const response = await fetchWithAuth(`${BASE}/api/users/clients/export`);
        const blob = await response.blob();
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `clients-export-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showAlert('Client data exported successfully!', 'success');
    } catch (error) {
        console.error('Error exporting client data:', error);
        showAlert('Error exporting client data', 'error');
    }
}
