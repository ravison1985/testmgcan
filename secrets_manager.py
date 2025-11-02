"""
Encrypted Secrets Manager
Securely stores and retrieves secrets from an encrypted JSON file
"""
import os
import json
from cryptography.fernet import Fernet


class SecretsManager:
    def __init__(self, encrypted_file='secrets.encrypted.json', master_key_env='MASTER_ENCRYPTION_KEY'):
        """
        Initialize the secrets manager
        
        Args:
            encrypted_file: Path to encrypted secrets file
            master_key_env: Environment variable name containing the master encryption key
        """
        self.encrypted_file = encrypted_file
        self.master_key_env = master_key_env
        self._secrets_cache = None
        
    def _get_master_key(self):
        """Get the master encryption key from environment variable"""
        key = os.environ.get(self.master_key_env)
        if not key:
            raise ValueError(
                f"Master encryption key not found in environment variable '{self.master_key_env}'. "
                f"Please set it in Replit Secrets tab."
            )
        return key.encode()
    
    def _get_cipher(self):
        """Get Fernet cipher instance"""
        return Fernet(self._get_master_key())
    
    def encrypt_secrets(self, secrets_dict):
        """
        Encrypt secrets dictionary and save to file
        
        Args:
            secrets_dict: Dictionary of secrets to encrypt
        """
        cipher = self._get_cipher()
        json_data = json.dumps(secrets_dict).encode()
        encrypted_data = cipher.encrypt(json_data)
        
        with open(self.encrypted_file, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"✅ Secrets encrypted and saved to {self.encrypted_file}")
    
    def decrypt_secrets(self):
        """
        Decrypt and return secrets from encrypted file
        
        Returns:
            Dictionary of decrypted secrets
        """
        if self._secrets_cache:
            return self._secrets_cache
            
        if not os.path.exists(self.encrypted_file):
            print(f"⚠️  Encrypted file {self.encrypted_file} not found. Using fallback to environment variables.")
            return {}
        
        try:
            cipher = self._get_cipher()
            
            with open(self.encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = cipher.decrypt(encrypted_data)
            secrets_dict = json.loads(decrypted_data.decode())
            
            self._secrets_cache = secrets_dict
            return secrets_dict
            
        except Exception as e:
            print(f"❌ Error decrypting secrets: {e}")
            print("⚠️  Falling back to environment variables")
            return {}
    
    def get(self, key, default=None, fallback_to_env=True):
        """
        Get a secret value by key
        
        Args:
            key: Secret key name
            default: Default value if not found
            fallback_to_env: If True, try to get from environment variable if not in encrypted file
            
        Returns:
            Secret value or default
        """
        secrets = self.decrypt_secrets()
        value = secrets.get(key)
        
        if value is None and fallback_to_env:
            # Fallback to environment variable
            value = os.environ.get(key, default)
        
        return value if value is not None else default
    
    @staticmethod
    def generate_master_key():
        """
        Generate a new master encryption key
        
        Returns:
            String key that should be stored in MASTER_ENCRYPTION_KEY environment variable
        """
        key = Fernet.generate_key()
        return key.decode()


def get_secrets_manager():
    """Get a singleton instance of SecretsManager"""
    if not hasattr(get_secrets_manager, '_instance'):
        get_secrets_manager._instance = SecretsManager()
    return get_secrets_manager._instance
