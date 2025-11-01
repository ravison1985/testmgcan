class FyersAuth {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // Generate Auth URL button
        document.getElementById('generateAuthBtn').addEventListener('click', () => {
            this.generateAuthUrl();
        });

        // Show token input button
        document.getElementById('showTokenInputBtn').addEventListener('click', () => {
            this.showTokenInput();
        });

        // Submit auth code button
        document.getElementById('submitAuthCodeBtn').addEventListener('click', () => {
            this.submitAuthCode();
        });

        // Submit token button
        document.getElementById('submitTokenBtn').addEventListener('click', () => {
            this.submitToken();
        });

        // Enter key handlers
        document.getElementById('authCodeInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.submitAuthCode();
            }
        });

        document.getElementById('tokenInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.submitToken();
            }
        });
    }

    async generateAuthUrl() {
        try {
            this.showLoading(true);
            this.showStatus('info', 'Generating authentication URL...', false);

            const response = await fetch('/generate_auth_url');
            const result = await response.json();

            if (result.status === 'success') {
                // Open auth URL in new tab
                window.open(result.auth_url, '_blank');
                
                this.showStatus('success', 'Authentication URL opened in new tab. Complete login and copy the auth code from the redirect URL.');
                this.showAuthCodeInput();
            } else {
                this.showStatus('danger', `Error: ${result.message}`);
            }
        } catch (error) {
            this.showStatus('danger', `Network error: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }

    showAuthCodeInput() {
        document.getElementById('authCodeSection').style.display = 'block';
        document.getElementById('tokenSection').style.display = 'none';
        document.getElementById('authCodeInput').focus();
    }

    showTokenInput() {
        document.getElementById('tokenSection').style.display = 'block';
        document.getElementById('authCodeSection').style.display = 'none';
        document.getElementById('tokenInput').focus();
    }

    async submitAuthCode() {
        const authCode = document.getElementById('authCodeInput').value.trim();
        
        if (!authCode) {
            this.showStatus('warning', 'Please enter the authentication code');
            return;
        }

        try {
            this.showLoading(true);
            this.showStatus('info', 'Authenticating with Fyers API...', false);

            const response = await fetch('/authenticate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ auth_code: authCode })
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.showStatus('success', 'Authentication successful! Redirecting to dashboard...');
                setTimeout(() => {
                    window.location.href = result.redirect_url;
                }, 2000);
            } else {
                this.showStatus('danger', `Authentication failed: ${result.message}`);
            }
        } catch (error) {
            this.showStatus('danger', `Network error: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }

    async submitToken() {
        const accessToken = document.getElementById('tokenInput').value.trim();
        
        if (!accessToken) {
            this.showStatus('warning', 'Please enter the access token');
            return;
        }

        try {
            this.showLoading(true);
            this.showStatus('info', 'Validating access token...', false);

            const response = await fetch('/authenticate_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ access_token: accessToken })
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.showStatus('success', 'Token validation successful! Redirecting to dashboard...');
                setTimeout(() => {
                    window.location.href = result.redirect_url;
                }, 2000);
            } else {
                this.showStatus('danger', `Token validation failed: ${result.message}`);
            }
        } catch (error) {
            this.showStatus('danger', `Network error: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }

    showStatus(type, message, autoHide = true) {
        const statusElement = document.getElementById('authStatus');
        const iconMap = {
            'info': 'fas fa-info-circle',
            'success': 'fas fa-check-circle',
            'warning': 'fas fa-exclamation-triangle',
            'danger': 'fas fa-exclamation-circle'
        };

        statusElement.className = `alert alert-${type}`;
        statusElement.innerHTML = `
            <i class="${iconMap[type]} me-2"></i>
            ${message}
        `;

        statusElement.style.display = 'block';

        if (autoHide && type === 'success') {
            setTimeout(() => {
                statusElement.style.display = 'none';
            }, 5000);
        }
    }

    showLoading(show) {
        const loadingIndicator = document.getElementById('loadingIndicator');
        const buttons = document.querySelectorAll('button');
        
        if (show) {
            loadingIndicator.style.display = 'block';
            buttons.forEach(btn => btn.disabled = true);
        } else {
            loadingIndicator.style.display = 'none';
            buttons.forEach(btn => btn.disabled = false);
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new FyersAuth();
});
