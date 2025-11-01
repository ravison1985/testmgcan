import hashlib
import webbrowser
from fyers_apiv3 import fyersModel
from config import Config
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Import models at module level to avoid import issues
try:
    from models import db, AccessToken
except ImportError:
    # Handle case where app context might not be available yet
    db = None
    AccessToken = None

def _import_models():
    """Helper function to import models when needed"""
    global db, AccessToken
    if db is None or AccessToken is None:
        from models import db, AccessToken
    return db, AccessToken

class FyersAuth:
    def __init__(self):
        self.client_id = Config.CLIENT_ID
        self.secret_key = Config.SECRET_KEY
        self.redirect_uri = Config.REDIRECT_URI
        self.appSession = None
        self.access_token = None
        
    def get_stored_token(self):
        """Get valid stored token from database"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Find active token for this client
            stored_token = AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).order_by(AccessToken.created_at.desc()).first()
            
            if stored_token and stored_token.is_valid():
                logger.debug("Found valid stored token")
                return stored_token.token
            elif stored_token:
                # Token expired, deactivate it
                stored_token.is_active = False
                db.session.commit()
                logger.info("Stored token expired, deactivated")
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving stored token: {str(e)}")
            return None
    
    def store_token(self, token):
        """Store token in database with expiry"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Deactivate any existing tokens for this client
            AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).update({'is_active': False})
            
            # Fyers tokens are valid until 1 hour before market close next day
            # Set expiry to 2:30 PM next trading day (1 hour before 3:30 PM market close)
            expires_at = datetime.now().replace(hour=14, minute=30, second=0, microsecond=0)
            if datetime.now().hour >= 14 and datetime.now().minute >= 30:
                # If after 2:30 PM, extend to next day
                expires_at += timedelta(days=1)
            
            # Create new token record
            new_token = AccessToken()
            new_token.token = token
            new_token.client_id = self.client_id
            new_token.expires_at = expires_at
            new_token.is_active = True
            
            db.session.add(new_token)
            db.session.commit()
            
            logger.info(f"Token stored successfully, expires at: {expires_at}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing token: {str(e)}")
            return False
        
    def generate_auth_url(self):
        """Generate authentication URL for Fyers login"""
        try:
            self.appSession = fyersModel.SessionModel(
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                response_type="code",
                state="sample_state",
                secret_key=self.secret_key,
                grant_type="authorization_code"
            )
            
            auth_url = self.appSession.generate_authcode()
            logger.info(f"Generated auth URL: {auth_url}")
            return auth_url
            
        except Exception as e:
            logger.error(f"Error generating auth URL: {str(e)}")
            raise
    
    def get_valid_token(self):
        """Get a valid token from database or require fresh authentication if none found"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Check database for valid stored token
            stored_token = AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).order_by(AccessToken.created_at.desc()).first()
            
            if stored_token and stored_token.is_valid():
                logger.debug(f"Found valid stored token, expires at: {stored_token.expires_at}")
                return {
                    'status': 'success',
                    'access_token': stored_token.token,
                    'expires_at': stored_token.expires_at
                }
            else:
                if stored_token:
                    logger.info(f"Stored token expired at: {stored_token.expires_at}")
                else:
                    logger.info("No stored token found")
                    
                return {
                    'status': 'requires_auth',
                    'message': 'No valid token found, authentication required'
                }
                
        except Exception as e:
            logger.error(f"Error checking stored token: {str(e)}")
            return {
                'status': 'requires_auth',
                'message': 'Error accessing stored token, authentication required'
            }
    
    def is_token_recent(self):
        """Check if stored token is recent enough for reliable WebSocket connection"""
        try:
            # Check if token file exists and is recent
            import os
            token_file = '/tmp/fyers_token.txt'
            if os.path.exists(token_file):
                import time
                file_age = time.time() - os.path.getmtime(token_file)
                # Consider token recent if less than 4 hours old (14400 seconds)
                return file_age < 14400
            return False
        except Exception as e:
            logger.error(f"Error checking token age: {str(e)}")
            return False

    def generate_access_token(self, auth_code):
        """Generate access token from auth code"""
        try:
            if not self.appSession:
                raise ValueError("Authentication session not initialized")
            
            # Set the auth code
            self.appSession.set_token(auth_code)
            
            # Generate access token
            response = self.appSession.generate_token()
            
            if response and response.get('s') == 'ok':
                self.access_token = response.get('access_token')
                
                # Store the token for future use
                self.store_token(self.access_token)
                
                logger.info("Access token generated and stored successfully")
                return {
                    'status': 'success',
                    'access_token': self.access_token,
                    'message': 'Authentication successful'
                }
            else:
                error_msg = response.get('message', 'Unknown error occurred')
                logger.error(f"Token generation failed: {error_msg}")
                return {
                    'status': 'error',
                    'message': error_msg
                }
                
        except Exception as e:
            logger.error(f"Error generating access token: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def validate_token(self, access_token=None):
        """Validate access token by making a test API call"""
        try:
            token_to_validate = access_token or self.access_token
            if not token_to_validate:
                return False
            
            # Create Fyers model instance
            fyers = fyersModel.FyersModel(
                client_id=self.client_id,
                token=token_to_validate,
                log_path=""
            )
            
            # Test with profile API
            profile_response = fyers.get_profile()
            
            if profile_response and profile_response.get('s') == 'ok':
                logger.info("Token validation successful")
                # If this token isn't stored yet, store it
                if access_token and access_token != self.access_token:
                    self.store_token(access_token)
                    self.access_token = access_token
                return True
            else:
                logger.warning("Token validation failed")
                return False
                
        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return False
    
    def get_fyers_model(self, access_token=None):
        """Get initialized Fyers model instance"""
        token_to_use = access_token or self.access_token
        if not token_to_use:
            raise ValueError("No access token available")
        
        return fyersModel.FyersModel(
            client_id=self.client_id,
            token=token_to_use,
            log_path=""
        )


class FyersHistDataAuth:
    """Authentication class specifically for historical data access (365 days)"""
    
    def __init__(self):
        self.client_id = Config.HIST_CLIENT_ID
        self.secret_key = Config.HIST_SECRET_KEY
        self.redirect_uri = Config.HIST_REDIRECT_URI
        self.appSession = None
        self.access_token = None
        
    def get_stored_token(self):
        """Get valid stored token from database for historical data"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Find active token for this client (historical data client)
            stored_token = AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).order_by(AccessToken.created_at.desc()).first()
            
            if stored_token and stored_token.is_valid():
                logger.debug("Found valid stored token for historical data")
                return stored_token.token
            elif stored_token:
                # Token expired, deactivate it
                stored_token.is_active = False
                db.session.commit()
                logger.info("Historical data token expired, deactivated")
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving stored historical data token: {str(e)}")
            return None
    
    def store_token(self, token):
        """Store historical data token in database with extended expiry (365 days)"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Deactivate any existing tokens for this client
            AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).update({'is_active': False})
            
            # Historical data tokens are valid for 365 days
            expires_at = datetime.now() + timedelta(days=365)
            
            # Create new token record
            new_token = AccessToken()
            new_token.token = token
            new_token.client_id = self.client_id
            new_token.expires_at = expires_at
            new_token.is_active = True
            
            db.session.add(new_token)
            db.session.commit()
            
            logger.info(f"Historical data token stored successfully, expires at: {expires_at}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing historical data token: {str(e)}")
            return False
        
    def generate_auth_url(self):
        """Generate authentication URL for Fyers historical data login"""
        try:
            self.appSession = fyersModel.SessionModel(
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                response_type="code",
                state="hist_data_state",
                secret_key=self.secret_key,
                grant_type="authorization_code"
            )
            
            auth_url = self.appSession.generate_authcode()
            logger.info(f"Generated historical data auth URL: {auth_url}")
            return auth_url
            
        except Exception as e:
            logger.error(f"Error generating historical data auth URL: {str(e)}")
            raise
    
    def get_valid_token(self):
        """Get a valid token from database or require fresh authentication if none found"""
        try:
            # Import models if needed
            db, AccessToken = _import_models()
            
            # Check database for valid stored token
            stored_token = AccessToken.query.filter_by(
                client_id=self.client_id,
                is_active=True
            ).order_by(AccessToken.created_at.desc()).first()
            
            if stored_token and stored_token.is_valid():
                logger.info(f"Found valid stored historical data token, expires at: {stored_token.expires_at}")
                return {
                    'status': 'success',
                    'access_token': stored_token.token,
                    'expires_at': stored_token.expires_at
                }
            else:
                if stored_token:
                    logger.info(f"Stored historical data token expired at: {stored_token.expires_at}")
                else:
                    logger.info("No stored historical data token found")
                    
                return {
                    'status': 'requires_auth',
                    'message': 'No valid historical data token found, authentication required'
                }
                
        except Exception as e:
            logger.error(f"Error checking stored historical data token: {str(e)}")
            return {
                'status': 'requires_auth',
                'message': 'Error accessing stored historical data token, authentication required'
            }

    def generate_access_token(self, auth_code):
        """Generate access token from auth code for historical data"""
        try:
            if not self.appSession:
                raise ValueError("Historical data authentication session not initialized")
            
            # Set the auth code
            self.appSession.set_token(auth_code)
            
            # Generate access token
            response = self.appSession.generate_token()
            
            if response and response.get('s') == 'ok':
                self.access_token = response.get('access_token')
                
                # Store the token for future use
                self.store_token(self.access_token)
                
                logger.info("Historical data access token generated and stored successfully")
                return {
                    'status': 'success',
                    'access_token': self.access_token,
                    'message': 'Historical data authentication successful'
                }
            else:
                error_msg = response.get('message', 'Unknown error occurred')
                logger.error(f"Historical data token generation failed: {error_msg}")
                return {
                    'status': 'error',
                    'message': error_msg
                }
                
        except Exception as e:
            logger.error(f"Error generating historical data access token: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def validate_token(self, access_token=None):
        """Validate historical data access token by making a test API call"""
        try:
            token_to_validate = access_token or self.access_token
            if not token_to_validate:
                return False
            
            # Create Fyers model instance
            fyers = fyersModel.FyersModel(
                client_id=self.client_id,
                token=token_to_validate,
                log_path=""
            )
            
            # Test with profile API
            profile_response = fyers.get_profile()
            
            if profile_response and profile_response.get('s') == 'ok':
                logger.info("Historical data token validation successful")
                # If this token isn't stored yet, store it
                if access_token and access_token != self.access_token:
                    self.store_token(access_token)
                    self.access_token = access_token
                return True
            else:
                logger.warning("Historical data token validation failed")
                return False
                
        except Exception as e:
            logger.error(f"Error validating historical data token: {str(e)}")
            return False
    
    def get_fyers_model(self, access_token=None):
        """Get initialized Fyers model instance for historical data"""
        token_to_use = access_token or self.access_token
        if not token_to_use:
            raise ValueError("No historical data access token available")
        
        return fyersModel.FyersModel(
            client_id=self.client_id,
            token=token_to_use,
            log_path=""
        )
