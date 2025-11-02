# Secrets & Environment Variables Setup Guide

This guide explains how to configure secrets for your trading dashboard application.

## 🔒 On Replit (Recommended - Most Secure)

Your app is already configured to use Replit Secrets. No file needed!

1. Click the **Secrets** tab (🔒 icon) in the left sidebar
2. Add each secret with its name and value
3. Your app automatically reads them from `os.environ`

### Required Secrets on Replit:

- `SECRET_KEY` - Flask session secret (generate random string)
- `DATABASE_URL` - Automatically provided by Replit PostgreSQL
- `GOOGLE_CLIENT_ID` - For Google OAuth login
- `GOOGLE_CLIENT_SECRET` - For Google OAuth login
- `RAZORPAY_KEY_ID` - Payment gateway key
- `RAZORPAY_KEY_SECRET` - Payment gateway secret
- `FYERS_CLIENT_ID` - Trading API client ID
- `FYERS_SECRET_KEY` - Trading API secret
- `FYERS_REDIRECT_URI` - Your app URL + /authenticate

## 📁 Using .env File (Local Development or Other Platforms)

If deploying outside Replit:

### Step 1: Create .env file
```bash
cp .env.example .env
```

### Step 2: Edit .env file
Open `.env` and replace all placeholder values with your actual secrets:

```env
SECRET_KEY=actual-secret-key-here
GOOGLE_CLIENT_ID=your-actual-client-id.apps.googleusercontent.com
# ... and so on
```

### Step 3: Install python-dotenv
```bash
pip install python-dotenv
```

### Step 4: Load in app.py
Add at the top of `app.py`:
```python
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file
```

## ⚠️ Important Security Notes

1. **NEVER commit .env file** - It's already in `.gitignore`
2. **NEVER share your .env file** - Contains sensitive credentials
3. **Use .env.example** - Safe to commit, shows structure without values
4. **On Replit** - Use Secrets tab instead of .env file

## 🔑 How to Get API Keys

### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create project → Enable Google+ API
3. Create OAuth 2.0 credentials
4. Add authorized redirect URI: `https://your-app.replit.app/google_login/callback`

### Razorpay
1. Sign up at [Razorpay](https://razorpay.com)
2. Get API keys from Dashboard → Settings → API Keys
3. Use Test keys for development, Live keys for production

### Fyers API
1. Sign up at [Fyers](https://fyers.in)
2. Create app in API Portal
3. Get Client ID and Secret Key
4. Set redirect URI to your app URL

## 🚀 Current Setup

Your app reads secrets like this (already implemented):
```python
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-dev-key')
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
DATABASE_URL = os.environ.get('DATABASE_URL')
```

This works with both Replit Secrets AND .env files!
