# 🚀 Quick Start: Encrypted Secrets in 5 Minutes

## Step-by-Step Setup

### 1️⃣ Generate Master Key (30 seconds)
```bash
python manage_secrets.py generate-key
```
**Copy the key** that appears (looks like: `xvK2_3mN9pQ7...`)

### 2️⃣ Save Key in Replit Secrets (1 minute)
1. Click **🔒 Secrets** tab in left sidebar
2. Click **New Secret**
3. Key: `MASTER_ENCRYPTION_KEY`
4. Value: Paste the key from step 1
5. Click **Add Secret**

### 3️⃣ Create Secrets File (2 minutes)
```bash
cp secrets.json.template secrets.json
```

Edit `secrets.json` with your actual values:
```json
{
  "SECRET_KEY": "your-actual-secret",
  "RAZORPAY_KEY_ID": "rzp_live_ABC123"
}
```

### 4️⃣ Encrypt Secrets (10 seconds)
```bash
python manage_secrets.py encrypt
```

### 5️⃣ Clean Up (10 seconds)
```bash
rm secrets.json
```

### 6️⃣ Test (10 seconds)
```bash
python manage_secrets.py test
```

## ✅ Done!

Now your secrets are:
- ✓ **Encrypted** in `secrets.encrypted.json`
- ✓ **Safe to commit** to Git
- ✓ **Automatically decrypted** when app runs
- ✓ **Protected** by master key in Replit Secrets

## 🔄 To Update Secrets Later

1. Create new `secrets.json` with updated values
2. Run: `python manage_secrets.py encrypt`
3. Delete: `rm secrets.json`
4. Restart your app

## 📖 Need More Help?

Read the full guide: `ENCRYPTED_SECRETS_GUIDE.md`
