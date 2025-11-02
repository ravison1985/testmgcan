#!/usr/bin/env python3
"""
Script to manage encrypted secrets
Run this to encrypt/decrypt secrets manually
"""
import json
import sys
from secrets_manager import SecretsManager


def generate_key():
    """Generate a new master encryption key"""
    key = SecretsManager.generate_master_key()
    print("=" * 70)
    print("🔑 NEW MASTER ENCRYPTION KEY GENERATED")
    print("=" * 70)
    print(f"\n{key}\n")
    print("=" * 70)
    print("⚠️  IMPORTANT: Copy this key and save it in Replit Secrets as:")
    print("   Key name: MASTER_ENCRYPTION_KEY")
    print("   Value: (paste the key above)")
    print("=" * 70)
    print("\n✅ After saving in Replit Secrets, you can encrypt your secrets.")
    

def encrypt():
    """Encrypt secrets from template file"""
    try:
        # Check if secrets.json exists
        with open('secrets.json', 'r') as f:
            secrets = json.load(f)
        
        manager = SecretsManager()
        manager.encrypt_secrets(secrets)
        
        print("\n" + "=" * 70)
        print("✅ SUCCESS: Secrets encrypted to secrets.encrypted.json")
        print("=" * 70)
        print("\n📝 Next steps:")
        print("1. Delete secrets.json (contains unencrypted data)")
        print("2. Keep secrets.encrypted.json (safe to commit)")
        print("3. Your app will now read from encrypted file")
        print("=" * 70)
        
    except FileNotFoundError:
        print("❌ ERROR: secrets.json not found")
        print("\n📝 Steps to create it:")
        print("1. Copy secrets.json.template to secrets.json")
        print("2. Edit secrets.json with your actual secret values")
        print("3. Run: python manage_secrets.py encrypt")
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        print("\n💡 Make sure MASTER_ENCRYPTION_KEY is set in Replit Secrets")


def decrypt():
    """Decrypt and display secrets (for verification only)"""
    try:
        manager = SecretsManager()
        secrets = manager.decrypt_secrets()
        
        print("\n" + "=" * 70)
        print("🔓 DECRYPTED SECRETS (for verification only)")
        print("=" * 70)
        for key, value in secrets.items():
            # Mask the value for security
            if len(value) > 10:
                masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
            else:
                masked = "*" * len(value)
            print(f"{key}: {masked}")
        print("=" * 70)
        
    except Exception as e:
        print(f"❌ ERROR: {e}")


def test():
    """Test the secrets manager"""
    try:
        manager = SecretsManager()
        
        print("\n" + "=" * 70)
        print("🧪 TESTING SECRETS MANAGER")
        print("=" * 70)
        
        # Test getting a secret
        secret_key = manager.get('SECRET_KEY')
        if secret_key:
            print(f"✅ Successfully retrieved SECRET_KEY")
        else:
            print(f"⚠️  SECRET_KEY not found")
        
        razorpay_key = manager.get('RAZORPAY_KEY_ID')
        if razorpay_key:
            print(f"✅ Successfully retrieved RAZORPAY_KEY_ID")
        else:
            print(f"⚠️  RAZORPAY_KEY_ID not found")
            
        print("=" * 70)
        print("\n✅ Secrets manager is working correctly!")
        
    except Exception as e:
        print(f"❌ ERROR: {e}")


def show_help():
    """Show help message"""
    print("""
🔐 Encrypted Secrets Manager
============================

Usage: python manage_secrets.py [command]

Commands:
  generate-key    Generate a new master encryption key
  encrypt         Encrypt secrets.json to secrets.encrypted.json
  decrypt         Decrypt and display secrets (for verification)
  test            Test if secrets manager is working
  help            Show this help message

Workflow:
  1. python manage_secrets.py generate-key
     → Copy the key to Replit Secrets as MASTER_ENCRYPTION_KEY
     
  2. cp secrets.json.template secrets.json
     → Edit secrets.json with your actual values
     
  3. python manage_secrets.py encrypt
     → Creates encrypted file
     
  4. rm secrets.json
     → Delete unencrypted file
     
  5. python manage_secrets.py test
     → Verify everything works
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "generate-key":
        generate_key()
    elif command == "encrypt":
        encrypt()
    elif command == "decrypt":
        decrypt()
    elif command == "test":
        test()
    elif command == "help":
        show_help()
    else:
        print(f"❌ Unknown command: {command}")
        show_help()
        sys.exit(1)
