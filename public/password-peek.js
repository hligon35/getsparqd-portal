/**
 * Password Peek Utility
 * Adds show/hide functionality to password fields
 */

class PasswordPeek {
    constructor() {
        this.initializeOnLoad();
    }

    initializeOnLoad() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }

    initialize() {
        // Find all password inputs and add peek functionality
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => this.addPeekButton(input));
        
        // Observer for dynamically added password fields
        this.observeNewPasswordFields();
    }

    addPeekButton(passwordInput) {
        // Skip if already has peek button
        if (passwordInput.parentElement.classList.contains('password-peek-container')) {
            return;
        }

        // Create container
        const container = document.createElement('div');
        container.className = 'password-peek-container';
        container.style.cssText = `
            position: relative;
            display: inline-block;
            width: 100%;
        `;

        // Wrap the input
        passwordInput.parentNode.insertBefore(container, passwordInput);
        container.appendChild(passwordInput);

        // Create peek button
        const peekButton = document.createElement('button');
        peekButton.type = 'button';
        peekButton.className = 'password-peek-btn';
        peekButton.innerHTML = '👁️';
        peekButton.setAttribute('aria-label', 'Show password');
        peekButton.style.cssText = `
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            color: #666;
            padding: 5px;
            border-radius: 3px;
            transition: all 0.2s ease;
            z-index: 10;
            user-select: none;
        `;

        // Add hover effects
        peekButton.addEventListener('mouseenter', () => {
            peekButton.style.backgroundColor = 'rgba(0,0,0,0.1)';
            peekButton.style.color = '#333';
        });

        peekButton.addEventListener('mouseleave', () => {
            peekButton.style.backgroundColor = 'transparent';
            peekButton.style.color = '#666';
        });

        // Add peek functionality
        let isShowing = false;
        peekButton.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            if (isShowing) {
                passwordInput.type = 'password';
                peekButton.innerHTML = '👁️';
                peekButton.setAttribute('aria-label', 'Show password');
                isShowing = false;
            } else {
                passwordInput.type = 'text';
                peekButton.innerHTML = '🙈';
                peekButton.setAttribute('aria-label', 'Hide password');
                isShowing = true;
            }
        });

        // Adjust input padding to make room for button
        const inputStyles = getComputedStyle(passwordInput);
        const currentPaddingRight = parseInt(inputStyles.paddingRight) || 15;
        passwordInput.style.paddingRight = (currentPaddingRight + 35) + 'px';

        container.appendChild(peekButton);

        // Add keyboard support
        peekButton.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                peekButton.click();
            }
        });

        // Hide peek when input loses focus (security feature)
        passwordInput.addEventListener('blur', () => {
            if (isShowing) {
                setTimeout(() => {
                    passwordInput.type = 'password';
                    peekButton.innerHTML = '👁️';
                    peekButton.setAttribute('aria-label', 'Show password');
                    isShowing = false;
                }, 100); // Small delay to allow button click
            }
        });
    }

    observeNewPasswordFields() {
        // Create observer for dynamically added password fields
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        // Check if the added node is a password input
                        if (node.type === 'password') {
                            this.addPeekButton(node);
                        }
                        // Check for password inputs within the added node
                        const passwordInputs = node.querySelectorAll ? node.querySelectorAll('input[type="password"]') : [];
                        passwordInputs.forEach(input => this.addPeekButton(input));
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    // Method to manually add peek to specific input
    static addToInput(inputElement) {
        const instance = new PasswordPeek();
        instance.addPeekButton(inputElement);
    }

    // Method to add peek to all password inputs in a container
    static addToContainer(container) {
        const instance = new PasswordPeek();
        const passwordInputs = container.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => instance.addPeekButton(input));
    }
}

// Auto-initialize
window.passwordPeek = new PasswordPeek();

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PasswordPeek;
}
