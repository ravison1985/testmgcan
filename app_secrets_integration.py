"""
Example: How to integrate encrypted secrets into app.py

Copy this code to your app.py to use encrypted secrets
"""

# Add at the top of app.py with other imports
from secrets_manager import get_secrets_manager

# Initialize secrets manager (do this early in app.py)
secrets = get_secrets_manager()

# Replace all os.environ.get() calls with secrets.get()
# The secrets.get() method will:
# 1. Try to get from encrypted file first
# 2. Fallback to environment variable if not in file
# 3. Return default value if not found anywhere

# BEFORE (using environment variables only):
# SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-12345')

# AFTER (using encrypted secrets with fallback):
SECRET_KEY = secrets.get('SECRET_KEY', 'dev-key-12345')

# More examples:
DATABASE_URL = secrets.get('DATABASE_URL')
GOOGLE_CLIENT_ID = secrets.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = secrets.get('GOOGLE_CLIENT_SECRET')
RAZORPAY_KEY_ID = secrets.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = secrets.get('RAZORPAY_KEY_SECRET')
FYERS_CLIENT_ID = secrets.get('FYERS_CLIENT_ID')
FYERS_SECRET_KEY = secrets.get('FYERS_SECRET_KEY')

# That's it! Your app will now:
# ✓ Read from encrypted secrets.encrypted.json if available
# ✓ Fall back to Replit Secrets (environment variables) if not
# ✓ Use default values if specified
