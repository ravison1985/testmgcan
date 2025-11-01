# 🔐 Encrypted Secrets System Guide

This guide explains how to use the encrypted JSON secrets system.

## 🎯 How It Works

1. **Secrets stored in encrypted JSON file** (`secrets.encrypted.json`)
2. **Master encryption key** stored in Replit Secrets (`MASTER_ENCRYPTION_KEY`)
3. **App automatically decrypts** secrets at runtime
4. **Encrypted file is safe** to commit to Git

## 📋 Setup Steps

### Step 1: Generate Master Encryption Key

```bash
python manage_secrets.py generate-key
```

This will output a key like: `xvK2_3mN9pQ7rT8sV1wX4yZ5aB6cD0eF1gH2iJ3kL4m=`

**Important**: Copy this key!

### Step 2: Save Key in Replit Secrets

1. Click **Secrets** tab (🔒) in Replit sidebar
2. Click **New Secret**
3. Key name: `MASTER_ENCRYPTION_KEY`
4. Value: Paste the key from Step 1
5. Click **Add Secret**

### Step 3: Create Your Secrets File

```bash
cp secrets.json.template secrets.json
```

Edit `secrets.json` with your actual secret values:
```json
{
  "SECRET_KEY": "my-actual-flask-secret",
  "RAZORPAY_KEY_ID": "rzp_live_ABC123",
  "RAZORPAY_KEY_SECRET": "actual_secret_here"
}
```

### Step 4: Encrypt Your Secrets

```bash
python manage_secrets.py encrypt
```

This creates `secrets.encrypted.json` (encrypted, safe to commit)

### Step 5: Delete Unencrypted File

```bash
rm secrets.json
```

**Important**: Never commit `secrets.json` to Git!

### Step 6: Test It Works

```bash
python manage_secrets.py test
```

## 🔧 Using in Your App

### Current app.py (uses environment variables):
```python
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback')
```

### With encrypted secrets system:
```python
from secrets_manager import get_secrets_manager

secrets = get_secrets_manager()

# Get secrets from encrypted file (with fallback to environment variables)
SECRET_KEY = secrets.get('SECRET_KEY', 'fallback')
RAZORPAY_KEY_ID = secrets.get('RAZORPAY_KEY_ID')
GOOGLE_CLIENT_ID = secrets.get('GOOGLE_CLIENT_ID')
```

## 📁 Files Overview

| File | Purpose | Safe to Commit? |
|------|---------|----------------|
| `secrets_manager.py` | Encryption/decryption code | ✅ Yes |
| `manage_secrets.py` | CLI tool to manage secrets | ✅ Yes |
| `secrets.json.template` | Template showing structure | ✅ Yes |
| `secrets.json` | Your actual secrets (unencrypted) | ❌ **NO** |
| `secrets.encrypted.json` | Encrypted secrets | ✅ Yes |
| `.gitignore` | Blocks secrets.json from Git | ✅ Yes |

## 🛠️ Management Commands

```bash
# Generate new master key
python manage_secrets.py generate-key

# Encrypt secrets.json → secrets.encrypted.json
python manage_secrets.py encrypt

# View decrypted secrets (masked)
python manage_secrets.py decrypt

# Test if everything works
python manage_secrets.py test

# Show help
python manage_secrets.py help
```

## 🔄 Updating Secrets

1. Decrypt to secrets.json: manually create it or copy template
2. Edit secrets.json with new values
3. Re-encrypt: `python manage_secrets.py encrypt`
4. Delete: `rm secrets.json`
5. Restart app to load new secrets

## ✅ Advantages

✓ Secrets encrypted with AES-128 (Fernet)
✓ Encrypted file safe to commit to Git
✓ Only need to protect master key (in Replit Secrets)
✓ Easy backup and portability
✓ Automatic fallback to environment variables

## ⚠️ Security Notes

1. **Master key is critical** - If lost, encrypted file cannot be decrypted
2. **Never commit secrets.json** - Already in .gitignore
3. **Master key in Replit Secrets** - Most secure location
4. **Encrypted file is safe** - Can be shared publicly
5. **Rotate keys regularly** - Good security practice

## 🆚 Comparison

| Method | Security | Ease of Use | Portability |
|--------|----------|-------------|-------------|
| Replit Secrets | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Encrypted JSON | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Plain .env | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Hardcoded | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 🚀 Production Deployment

For production:
1. Keep `secrets.encrypted.json` in your repository
2. Set `MASTER_ENCRYPTION_KEY` in your hosting platform's environment variables
3. App will automatically decrypt secrets on startup
4. Works on Heroku, AWS, Google Cloud, etc.
