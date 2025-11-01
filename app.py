import os
import logging
import json
import time
import threading
import schedule
import pytz
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, and_
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from auth import FyersAuth, FyersHistDataAuth
from websocket_manager import WebSocketManager
from config import Config
from models import db, StockData, HistoricalData, DataFetchLog, AccessToken, CamarillaLevels, CprLevel, FibonacciLevel, User, HistData365, HistData1Min, HistData2Min, HistData3Min, HistData5Min, HistData10Min, HistData15Min, HistData20Min, HistData30Min, HistData45Min, HistData60Min, HistData120Min, HistData180Min, HistData240Min, Watchlist, UserSession, DailyOHLCData, WeeklyOHLCData, FiveMinCandleData, SubscriptionPlan, CouponCode
from historical_data import HistoricalDataManager
from camarilla_calculator import CamarillaCalculator
from ohlc_storage import OHLCStorage
from fyers_apiv3 import fyersModel
from symbols_loader import get_fo_symbols_for_widget, get_fo_symbols_for_chart
from google_auth import google_auth
from technical_indicators import TechnicalIndicators
from secrets_manager import SecretsManager

# In-memory cache for 5-minute chart data
chart_data_cache = {}
CACHE_DURATION_MINUTES = 5

# In-memory cache for technical indicators (recalculate every 10 seconds with live LTP)
technical_indicators_cache = {
    'data': None,
    'timestamp': None,
    'ttl_seconds': 10  # Cache for 10 seconds - recalculate indicators with live LTP more frequently
}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize encrypted secrets manager
secrets = SecretsManager()
logger.info("🔐 Encrypted Secrets Manager initialized")

app = Flask(__name__)
app.secret_key = secrets.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Database configuration
database_url = "postgresql://neondb_owner:npg_zNPIYAOih59c@ep-blue-block-afn02w4c.c-2.us-west-2.aws.neon.tech/neondb?sslmode=require"
if not database_url:
    # Fallback for when DATABASE_URL is not set or empty
    logger.error("DATABASE_URL not found in encrypted secrets or environment variables")
    raise ValueError("DATABASE_URL is required - add to secrets.encrypted.json or Replit Secrets")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_size": 5,
    "max_overflow": 5,
    "pool_timeout": 30,
    "echo_pool": False,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db.init_app(app)

# Register Google OAuth blueprint (will inject functions later)
app.register_blueprint(google_auth)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
# login_manager.login_view = 'login'  # Commented out to fix LSP warning
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Session management functions for IP-based security
def get_client_ip():
    """Get client IP address with security considerations"""
    # In production, use ProxyFix middleware to properly handle proxy headers
    # For now, prioritize direct connection IP for security
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for and app.config.get('TRUSTED_PROXY'):
        # Only use forwarded headers if explicitly configured as trusted
        forwarded_ips = forwarded_for.split(',')
        return forwarded_ips[0].strip()
    elif request.headers.get('X-Real-IP') and app.config.get('TRUSTED_PROXY'):
        return request.headers.get('X-Real-IP')
    else:
        # Default to direct connection IP (most secure)
        return request.remote_addr

def create_user_session(user_id, ip_address, user_agent=None):
    """Create a new user session record"""
    import uuid
    try:
        # Generate unique session ID
        session_id = str(uuid.uuid4())
        
        # Create new session record
        new_session = UserSession(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            login_time=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        # Store session ID in Flask session
        session['user_session_id'] = session_id
        
        logger.info(f"Created new session for user {user_id} from IP {ip_address}")
        return session_id
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user session: {str(e)}")
        return None

def deactivate_user_sessions(user_id, exclude_session_id=None):
    """Deactivate all active sessions for a user, optionally excluding one session"""
    try:
        query = UserSession.query.filter_by(user_id=user_id, is_active=True)
        
        if exclude_session_id:
            query = query.filter(UserSession.session_id != exclude_session_id)
        
        sessions_to_deactivate = query.all()
        
        for session_record in sessions_to_deactivate:
            session_record.is_active = False
            logger.info(f"Deactivated session {session_record.session_id} for user {user_id} from IP {session_record.ip_address}")
        
        db.session.commit()
        return len(sessions_to_deactivate)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deactivating user sessions: {str(e)}")
        return 0

def check_ip_session_limit(user, current_ip):
    """Check if user can login from this IP (single IP rule for non-admin users)"""
    if user.is_admin():
        return True, None  # Admin users are exempt from IP restrictions
    
    # Get all active sessions for this user
    active_sessions = UserSession.query.filter_by(
        user_id=user.id, 
        is_active=True
    ).all()
    
    if not active_sessions:
        return True, None  # No active sessions, allow login
    
    # Check if any active session is from the same IP
    same_ip_sessions = [s for s in active_sessions if s.ip_address == current_ip]
    if same_ip_sessions:
        return True, None  # Same IP, allow login
    
    # Different IP detected, return info about existing sessions
    existing_ips = [s.ip_address for s in active_sessions]
    return False, existing_ips

def enforce_single_ip_policy(user, current_ip, current_session_id):
    """Enforce single IP policy: logout sessions from other IPs"""
    if user.is_admin():
        return  # Admin users are exempt
    
    try:
        # Deactivate all sessions from different IPs
        sessions_to_deactivate = UserSession.query.filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True,
            UserSession.ip_address != current_ip,
            UserSession.session_id != current_session_id
        ).all()
        
        for session_record in sessions_to_deactivate:
            session_record.is_active = False
            logger.info(f"Enforced single IP policy: Deactivated session {session_record.session_id} for user {user.username} from IP {session_record.ip_address} (new login from {current_ip})")
        
        if sessions_to_deactivate:
            db.session.commit()
            logger.info(f"Single IP policy: Deactivated {len(sessions_to_deactivate)} sessions for user {user.username}")
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error enforcing single IP policy: {str(e)}")

def send_subscription_email(user_email, username, plan_name, start_date, end_date):
    """Send subscription activation email to user"""
    try:
        smtp_email = secrets.get('SMTP_EMAIL')
        smtp_password = secrets.get('SMTP_PASSWORD')
        
        if not smtp_email or not smtp_password:
            logger.error("SMTP credentials not configured")
            return False
        
        msg = MIMEMultipart('alternative')
        msg['From'] = f'MG F&O Dashboard <{smtp_email}>'
        msg['To'] = user_email
        msg['Subject'] = 'Subscription Activated - MG F&O Stocks Dashboard'
        msg['Reply-To'] = smtp_email
        msg['Return-Path'] = smtp_email
        
        html_body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #4da6ff 0%, #66b3ff 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
              <h1 style="color: white; margin: 0; font-size: 28px;">🎉 Subscription Activated!</h1>
            </div>
            
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                Hi <strong>{username}</strong>,
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                Your subscription to <strong>MG F&O Stocks Dashboard</strong> has been successfully activated! 🚀
              </p>
              
              <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #4da6ff; margin: 25px 0;">
                <h2 style="color: #4da6ff; margin-top: 0; font-size: 20px;">Subscription Details</h2>
                <p style="margin: 10px 0;"><strong>Plan:</strong> {plan_name}</p>
                <p style="margin: 10px 0;"><strong>Start Date:</strong> {start_date}</p>
                <p style="margin: 10px 0;"><strong>End Date:</strong> {end_date}</p>
                <p style="margin: 10px 0; color: #28a745;"><strong>Status:</strong> ✅ Active</p>
              </div>
              
              <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 25px 0;">
                <h3 style="color: #4da6ff; margin-top: 0; font-size: 18px;">What You Get:</h3>
                <ul style="margin: 10px 0; padding-left: 20px;">
                  <li>📊 Real-time RVOL Analysis</li>
                  <li>📈 Volume Profile Charts</li>
                  <li>🎯 Camarilla, CPR & Fibonacci Level Screeners</li>
                  <li>🔔 Instant High/Low Break Alerts</li>
                  <li>📉 100-Day EOD Charts with Support & Resistance</li>
                  <li>💹 Live Market Sentiment Analysis</li>
                  <li>📱 Access from Any Device</li>
                </ul>
              </div>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="https://{request.host}/dashboard" style="display: inline-block; background: #4da6ff; color: white; padding: 15px 40px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">
                  Access Dashboard
                </a>
              </div>
              
              <p style="font-size: 14px; color: #666; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                Need help? Reply to this email or visit our support page.<br>
                Thank you for choosing MG F&O Stocks Dashboard!
              </p>
              
              <p style="font-size: 14px; color: #999; margin-top: 20px; text-align: center;">
                © 2025 MG F&O Stocks Dashboard. All rights reserved.
              </p>
            </div>
          </body>
        </html>
        """
        
        text_body = f"""
        Hi {username},
        
        Your subscription to MG F&O Stocks Dashboard has been successfully activated!
        
        Subscription Details:
        - Plan: {plan_name}
        - Start Date: {start_date}
        - End Date: {end_date}
        - Status: Active
        
        What You Get:
        - Real-time RVOL Analysis
        - Volume Profile Charts
        - Camarilla, CPR & Fibonacci Level Screeners
        - Instant High/Low Break Alerts
        - 100-Day EOD Charts with Support & Resistance
        - Live Market Sentiment Analysis
        - Access from Any Device
        
        Access your dashboard: https://{request.host}/dashboard
        
        Thank you for choosing MG F&O Stocks Dashboard!
        
        © 2025 MG F&O Stocks Dashboard
        """
        
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, user_email, msg.as_string())
        
        logger.info(f"Subscription email sent to {user_email} for plan {plan_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending subscription email: {str(e)}")
        return False

# Inject session management functions into google_auth module
import google_auth as google_auth_module
google_auth_module.get_client_ip = get_client_ip
google_auth_module.create_user_session = create_user_session
google_auth_module.deactivate_user_sessions = deactivate_user_sessions
google_auth_module.send_subscription_email = send_subscription_email

# Session security configuration
# SESSION_COOKIE_SECURE should be True in production (HTTPS) but False in development
app.config['SESSION_COOKIE_SECURE'] = True if secrets.get('REPL_ID') else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

@app.before_request
def check_session_validity():
    """Check if the current user session is still valid (IP-based security)"""
    # Skip for non-authenticated users, static files, API endpoints, and auth-related routes
    if (not current_user.is_authenticated or 
        request.endpoint == 'static' or
        request.endpoint is None or
        request.endpoint.startswith('api/') or
        request.endpoint in ['login', 'logout', 'auth', 'generate_auth_url', 'authenticate'] or
        request.endpoint.startswith('google_auth.') or
        request.path.startswith('/api/') or
        request.path.startswith('/static/')):
        return
    
    # Skip for admin users (they are exempt from IP restrictions)
    if current_user.is_admin():
        return
    
    # Get current session info
    user_session_id = session.get('user_session_id')
    current_ip = get_client_ip()
    
    # Only check session validity if user_session_id exists (avoid checking on first login)
    if user_session_id:
        try:
            # Check if session is still active and matches current IP
            user_session = UserSession.query.filter_by(
                session_id=user_session_id,
                user_id=current_user.id,
                is_active=True
            ).first()
            
            if not user_session:
                # Session not found or deactivated
                logger.info(f"Session {user_session_id} not found or deactivated for user {current_user.username}")
                logout_user()
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
            
            elif user_session.ip_address != current_ip:
                # IP address changed
                logger.warning(f"IP address changed for user {current_user.username}: {user_session.ip_address} -> {current_ip}")
                user_session.is_active = False
                db.session.commit()
                logout_user()
                session.clear()
                flash('You have been logged out because your session was accessed from a different location.', 'warning')
                return redirect(url_for('login'))
            
            else:
                # Valid session - update last activity (but not on every single request to avoid DB overload)
                import time
                last_update = session.get('last_activity_update', 0)
                current_time = time.time()
                
                # Only update last activity every 60 seconds to reduce DB load
                if current_time - last_update > 60:
                    user_session.last_activity = datetime.utcnow()
                    db.session.commit()
                    session['last_activity_update'] = current_time
                
        except Exception as e:
            logger.error(f"Error checking session validity: {str(e)}")
            # On database errors, don't logout to avoid disrupting user experience
            # Just log the error and continue
            pass

# Global variables
websocket_manager = None
fyers_auth = FyersAuth()
ohlc_storage = None
fyers_hist_auth = FyersHistDataAuth()
historical_manager = None
hist_data_manager = None
camarilla_calculator = CamarillaCalculator()

# Thread-safe WebSocket manager singleton
_ws_manager = None
_ws_lock = threading.Lock()
_current_ws_token = None  # Track current token in WebSocket manager

def _get_best_available_token():
    """Get the best available token with priority: database > session"""
    # Priority 1: Get valid token from database (user's independent authentication)
    token_result = fyers_auth.get_valid_token()
    if token_result['status'] == 'success':
        return token_result['access_token'], 'database'
    
    # Priority 2: Fall back to session token only if no database token exists
    session_token = session.get('access_token')
    if session_token:
        return session_token, 'session'
    
    return None, None

def force_rebuild_websocket_manager():
    """Force rebuild of WebSocket manager - used when tokens change"""
    global _ws_manager, _current_ws_token
    with _ws_lock:
        if _ws_manager:
            logger.info("🔄 Force rebuilding WebSocket manager due to token change")
            try:
                _ws_manager.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting old WebSocket manager: {e}")
        
        _ws_manager = None
        _current_ws_token = None
        
        # Get the WebSocket manager with new token
        return get_websocket_manager()

def get_websocket_manager():
    """Thread-safe singleton accessor for WebSocket manager with token refresh support"""
    global _ws_manager, _current_ws_token
    with _ws_lock:
        # Get current best available token
        access_token, token_source = _get_best_available_token()
        
        if not access_token:
            logger.error("❌ No access token available for WebSocket manager")
            return None
        
        # Check if token has changed and we need to rebuild
        if _ws_manager is not None and _current_ws_token != access_token:
            logger.info(f"🔄 Token changed from cached version, rebuilding WebSocket manager")
            try:
                _ws_manager.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting old WebSocket manager: {e}")
            _ws_manager = None
        
        # Return existing manager if it exists and token hasn't changed
        if _ws_manager is not None:
            return _ws_manager
        
        # Create new WebSocket manager with app context for database access
        logger.info(f"🔗 Using {token_source} token for WebSocket")
        _ws_manager = WebSocketManager(access_token, app=app)
        _current_ws_token = access_token
        _ws_manager.connect()
        logger.info(f"🔗 WebSocket manager created via singleton accessor: connected={_ws_manager.is_connected}")
        # Initialize break levels cache for live alerts
        _ws_manager.refresh_break_levels_cache()
        return _ws_manager
ohlc_storage = None
scheduler_thread = None
scheduler_initialized = False
last_eod_save_time = None
last_eod_save_count = 0

def get_historical_data_manager():
    """Get appropriate historical data manager based on available authentication"""
    global hist_data_manager
    
    # Check if we have historical data authentication
    hist_token = session.get('hist_access_token')
    if hist_token:
        if not hist_data_manager or hist_data_manager.access_token != hist_token:
            hist_data_manager = HistoricalDataManager(hist_token, use_hist_auth=True)
        return hist_data_manager
    
    # Fall back to regular authentication
    global historical_manager
    regular_token = session.get('access_token')
    if regular_token:
        if not historical_manager or historical_manager.access_token != regular_token:
            historical_manager = HistoricalDataManager(regular_token, use_hist_auth=False)
        return historical_manager
    
    return None

def get_current_day_ohlc(symbol):
    """Get current day OHLC data - first check storage, then Fyers API"""
    try:
        # First, try to get from OHLC storage to avoid API rate limits
        global ohlc_storage
        if ohlc_storage:
            stored_ohlc = ohlc_storage.get_ohlc_data(symbol)
            if stored_ohlc:
                logger.info(f"Retrieved OHLC for {symbol} from storage (avoiding API call)")
                return {
                    'open_price': stored_ohlc['open_price'],
                    'high_price': stored_ohlc['high_price'], 
                    'low_price': stored_ohlc['low_price'],
                    'prev_close_price': stored_ohlc['close_price']  # Use close as prev_close
                }
        
        # If not in storage, fetch from Fyers API (but this will count against rate limit)
        access_token = session.get('access_token')
        if not access_token:
            return None
            
        fyers = fyersModel.FyersModel(client_id=Config.CLIENT_ID, token=access_token)
        
        # Get current day data using quotes API
        data = {
            "symbols": f"NSE:{symbol}-EQ",
            "ohlcv_flag": "1"
        }
        
        response = fyers.quotes(data)
        
        # Handle both synchronous and asynchronous responses
        if hasattr(response, '__await__'):
            # If it's a coroutine, we can't await in non-async function
            logger.warning(f"Fyers API returned coroutine for {symbol}, skipping OHLC fetch")
            return None
            
        if response and isinstance(response, dict) and response.get('s') == 'ok' and response.get('d'):
            quote_data = response['d'][0]
            ohlc_data = {
                'open_price': float(quote_data.get('o', 0)),
                'high_price': float(quote_data.get('h', 0)), 
                'low_price': float(quote_data.get('l', 0)),
                'prev_close_price': float(quote_data.get('prev_close_price', 0))
            }
            
            # Store this data for future use (avoid future API calls)
            if ohlc_storage and ohlc_data['open_price'] > 0:
                symbol_data = {
                    'symbol': symbol,
                    'full_symbol': f"NSE:{symbol}-EQ",
                    'trading_date': datetime.now().date(),
                    'open_price': ohlc_data['open_price'],
                    'high_price': ohlc_data['high_price'],
                    'low_price': ohlc_data['low_price'],
                    'close_price': ohlc_data['prev_close_price'],
                    'volume': 0
                }
                ohlc_storage.store_daily_ohlc(symbol_data)
                logger.info(f"Stored OHLC for {symbol} for future reference")
            
            return ohlc_data
            
    except Exception as e:
        logger.error(f"Error fetching OHLC for {symbol}: {str(e)}")
        return None

@app.route('/')
def index():
    """Main route - show landing page as primary page"""
    return redirect(url_for('landing'))

@app.route('/auth')
def auth_page():
    """Fyers authentication page"""
    return render_template('index.html')

@app.route('/generate_auth_url')
def generate_auth_url():
    """Generate Fyers authentication URL"""
    try:
        auth_url = fyers_auth.generate_auth_url()
        return jsonify({
            'status': 'success',
            'auth_url': auth_url,
            'message': 'Authentication URL generated successfully'
        })
    except Exception as e:
        logger.error(f"Error generating auth URL: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Authenticate with auth code"""
    try:
        data = request.get_json() or {}
        auth_code = data.get('auth_code', '').strip()
        
        if not auth_code:
            return jsonify({
                'status': 'error',
                'message': 'Auth code is required'
            }), 400
        
        # Generate access token
        result = fyers_auth.generate_access_token(auth_code)
        
        if result['status'] == 'success':
            # Store in session
            session['access_token'] = result['access_token']
            session['authenticated'] = True
            
            # Initialize historical data manager
            global historical_manager
            historical_manager = HistoricalDataManager(result['access_token'])
            
            return jsonify({
                'status': 'success',
                'message': 'Authentication successful',
                'redirect_url': url_for('dashboard')
            })
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/authenticate_token', methods=['POST'])
@login_required
def authenticate_token():
    """Authenticate with direct access token (Admin only - sets up shared system authentication)"""
    # Admin sets up shared authentication for the entire system
    if not current_user.is_admin():
        return jsonify({
            'status': 'error',
            'message': 'Admin access required to set up system authentication'
        }), 403
    
    try:
        data = request.get_json() or {}
        access_token = data.get('access_token', '').strip()
        
        if not access_token:
            return jsonify({
                'status': 'error',
                'message': 'Access token is required'
            }), 400
        
        # Store the token without API validation (trust admin input)
        # Just store it and let the WebSocket/API calls determine if it works
        session['access_token'] = access_token
        session['authenticated'] = True
        
        # Store the token for future use in database
        fyers_auth.store_token(access_token)
        fyers_auth.access_token = access_token
        
        # Force rebuild WebSocket manager with new token
        logger.info(f"🔄 Admin {current_user.username} updated shared system token, rebuilding WebSocket manager")
        force_rebuild_websocket_manager()
        
        # Initialize historical data manager
        global historical_manager
        historical_manager = HistoricalDataManager(access_token)
        
        return jsonify({
            'status': 'success',
            'message': 'System authentication set up successfully. All users now have access to live streaming.',
            'redirect_url': url_for('dashboard')
        })
            
    except Exception as e:
        logger.error(f"Token authentication error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# Historical Data Authentication Routes
@app.route('/hist_auth')
def hist_auth_page():
    """Historical data authentication page"""
    return render_template('hist_auth.html')

@app.route('/generate_hist_auth_url')
def generate_hist_auth_url():
    """Generate Fyers historical data authentication URL"""
    try:
        auth_url = fyers_hist_auth.generate_auth_url()
        return jsonify({
            'status': 'success',
            'auth_url': auth_url,
            'message': 'Historical data authentication URL generated successfully'
        })
    except Exception as e:
        logger.error(f"Error generating hist auth URL: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/authenticate_hist', methods=['POST'])
def authenticate_hist():
    """Authenticate with auth code for historical data"""
    try:
        data = request.get_json() or {}
        auth_code = data.get('auth_code', '').strip()
        
        if not auth_code:
            return jsonify({
                'status': 'error',
                'message': 'Auth code is required'
            }), 400
        
        # Generate access token for historical data
        result = fyers_hist_auth.generate_access_token(auth_code)
        
        if result['status'] == 'success':
            # Store in session
            session['hist_access_token'] = result['access_token']
            session['hist_authenticated'] = True
            
            return jsonify({
                'status': 'success',
                'message': 'Historical data authentication successful',
                'redirect_url': url_for('hist_data_365_download')
            })
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Historical data authentication error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/authenticate_hist_token', methods=['POST'])
@login_required
def authenticate_hist_token():
    """Authenticate with direct access token for historical data (Admin only)"""
    try:
        # Only allow admin users to set historical data tokens
        if not current_user.is_admin():
            logger.warning(f"Non-admin user {current_user.username} attempted to set historical data token")
            return jsonify({
                'status': 'error',
                'message': 'Admin privileges required for historical data token management'
            }), 403
            
        data = request.get_json() or {}
        access_token = data.get('access_token', '').strip()
        
        if not access_token:
            return jsonify({
                'status': 'error',
                'message': 'Access token is required'
            }), 400
        
        # Store the token for historical data
        session['hist_access_token'] = access_token
        session['hist_authenticated'] = True
        
        # Store the token for future use
        fyers_hist_auth.store_token(access_token)
        fyers_hist_auth.access_token = access_token
        
        logger.info(f"Admin user {current_user.username} successfully set historical data token")
        
        return jsonify({
            'status': 'success',
            'message': 'Historical data token authenticated and stored for future use',
            'redirect_url': url_for('admin_panel')
        })
            
    except Exception as e:
        logger.error(f"Historical data token authentication error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Redirect to Google OAuth login - Google-only authentication"""
    # Preserve any query parameters (plan, amount, validity) for payment flow
    if request.args:
        return redirect(url_for('google_auth.login', **request.args))
    return redirect(url_for('google_auth.login'))

@app.route('/login-old', methods=['GET', 'POST'])
def login_old():
    """Old user login route (disabled, kept for reference)"""
    if request.method == 'POST':
        form_type = request.form.get('form_type', 'login')
        
        if form_type == 'register':
            # Handle user registration
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validation
            if not username or len(username) < 3:
                flash('Username must be at least 3 characters long.', 'danger')
                return render_template('login.html')
            
            # Note: Username uniqueness will be enforced by database constraint
            
            # Password validation: 8 chars minimum with letters and numbers
            password_regex = re.compile(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$')
            if not password_regex.match(password):
                flash('Password must be at least 8 characters long and contain both letters and numbers.', 'danger')
                return render_template('login.html')
            
            # Confirm password match
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('login.html')
            
            
            try:
                # Create new user with inactive account (awaiting admin activation)
                new_user = User(
                    username=username,
                    role='user',
                    account_active=False  # Admin needs to activate
                )
                new_user.set_password(password)
                
                
                db.session.add(new_user)
                db.session.commit()
                
                flash('Account created successfully! Please wait for admin activation before you can log in.', 'success')
                logger.info(f"New user registered: {username}")
                
                # Use Post-Redirect-Get pattern to prevent resubmission
                return redirect(url_for('login'))
                
            except IntegrityError:
                db.session.rollback()
                # Generic message to prevent username enumeration
                logger.warning(f"Duplicate username registration attempt: {username}")
                flash('Registration failed. Please check your input and try again.', 'danger')
                return render_template('login.html')
            except Exception as e:
                db.session.rollback()
                logger.error(f"User registration error: {str(e)}")
                flash('Registration failed. Please try again.', 'danger')
                return render_template('login.html')
        
        else:
            # Handle user login
            username = request.form['username']
            password = request.form['password']
            
            user = User.query.filter_by(username=username, account_active=True).first()
            
            if user and user.check_password(password):
                # Get client IP address
                client_ip = get_client_ip()
                user_agent = request.headers.get('User-Agent', '')
                
                # Check IP-based session limits for non-admin users
                if not user.is_admin():
                    can_login, existing_ips = check_ip_session_limit(user, client_ip)
                    if not can_login:
                        logger.warning(f"User {user.username} attempted login from new IP {client_ip}. Existing active sessions from: {existing_ips}")
                        flash(f'Login from new location detected. Previous session from different IP has been logged out for security.', 'warning')
                
                # Clear session to prevent session fixation
                session.clear()
                
                # Proceed with login
                login_user(user)
                session.permanent = True  # Enable permanent session for proper timeout handling
                user.last_login = datetime.utcnow()
                
                # Create new session record
                session_id = create_user_session(user.id, client_ip, user_agent)
                
                if session_id:
                    # Enforce single IP policy (logout other IP sessions for non-admin users)
                    enforce_single_ip_policy(user, client_ip, session_id)
                
                db.session.commit()
                
                # Check subscription status for non-admin users
                if not user.is_admin() and not user.is_subscription_active():
                    return redirect(url_for('subscription_required'))
                
                flash(f'Welcome {user.username}!', 'success')
                logger.info(f"User {user.username} logged in from IP {client_ip}")
                
                # Redirect based on role
                if user.is_admin():
                    return redirect(url_for('admin_panel'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                # Check if user exists but is inactive
                inactive_user = User.query.filter_by(username=username, account_active=False).first()
                if inactive_user and inactive_user.check_password(password):
                    flash('Your account is pending admin activation. Please contact admin.', 'warning')
                else:
                    flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/landing')
def landing():
    """Marketing landing page for new customers"""
    razorpay_key_id = secrets.get('RAZORPAY_KEY_ID', '')
    
    # Fetch active subscription plans from database
    plans = SubscriptionPlan.query.filter_by(is_active=True).order_by(SubscriptionPlan.sort_order).all()
    
    # Create a dictionary for easy template access
    plans_dict = {}
    for plan in plans:
        plans_dict[plan.plan_name.lower()] = {
            'display_name': plan.display_name,
            'price': plan.price,
            'strike_price': plan.strike_price or plan.price,  # Use strike price for "original price" display
            'discount_percent': plan.get_discount_percent(),
            'validity_display': plan.validity_display,
            'validity_days': plan.validity_days,
            'description': plan.description
        }
    
    response = make_response(render_template('landing.html', 
                                            razorpay_key_id=razorpay_key_id,
                                            plans=plans_dict))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Vary'] = 'Cookie'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/legal')
def legal():
    """Legal documents page - Terms, Privacy, About, Contact"""
    return render_template('legal.html')

@app.route('/account')
@login_required
def account():
    """User account page showing subscription details"""
    show_success = request.args.get('success', '0') == '1'
    return render_template('account.html', show_success=show_success)

@app.route('/check_auth')
def check_auth():
    """Check if user is authenticated via Google OAuth"""
    # Only consider users authenticated if they have a Google ID (signed up via Google OAuth)
    if current_user.is_authenticated and current_user.google_id:
        response = jsonify({'authenticated': True})
    else:
        response = jsonify({'authenticated': False})
    
    # Prevent caching so logout status is immediately reflected
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/validate-coupon', methods=['POST'])
@login_required
def validate_coupon():
    """Validate coupon code and return discount details"""
    from datetime import date
    
    try:
        data = request.get_json()
        coupon_code = data.get('coupon_code', '').strip().upper()
        plan_amount = data.get('plan_amount', 0)  # Amount in paise
        
        if not coupon_code:
            return jsonify({'valid': False, 'message': 'Please enter a coupon code'})
        
        # Find coupon in database
        coupon = CouponCode.query.filter_by(code=coupon_code).first()
        
        if not coupon:
            return jsonify({'valid': False, 'message': 'Invalid coupon code'})
        
        # Check if coupon is active
        if not coupon.is_active:
            return jsonify({'valid': False, 'message': 'This coupon is no longer active'})
        
        # Check expiration date
        if coupon.valid_until:
            from datetime import datetime
            today = datetime.now().date()
            valid_until_date = coupon.valid_until.date() if hasattr(coupon.valid_until, 'date') else coupon.valid_until
            if valid_until_date < today:
                return jsonify({'valid': False, 'message': 'This coupon has expired'})
        
        # Check usage limit
        if coupon.max_uses and coupon.uses_count >= coupon.max_uses:
            return jsonify({'valid': False, 'message': 'This coupon has reached its usage limit'})
        
        # Calculate discount
        discount_amount = 0
        if coupon.discount_percent:
            # Percentage discount
            discount_amount = int((plan_amount * coupon.discount_percent) / 100)
        elif coupon.discount_amount:
            # Fixed amount discount (convert to paise)
            discount_amount = coupon.discount_amount * 100
        
        # Ensure discount doesn't exceed plan price
        discount_amount = min(discount_amount, plan_amount)
        final_amount = plan_amount - discount_amount
        
        return jsonify({
            'valid': True,
            'message': f'Coupon "{coupon.code}" applied successfully!',
            'coupon_code': coupon.code,
            'discount_percent': coupon.discount_percent,
            'discount_amount': discount_amount,
            'final_amount': final_amount,
            'original_amount': plan_amount
        })
        
    except Exception as e:
        logger.error(f"Error validating coupon: {str(e)}")
        return jsonify({'valid': False, 'message': 'Error validating coupon'}), 500

@app.route('/activate-free-subscription', methods=['POST'])
@login_required
def activate_free_subscription():
    """Activate free subscription when using 100% discount coupon"""
    from datetime import date, timedelta
    
    try:
        data = request.get_json()
        plan = data.get('plan')
        validity = data.get('validity')
        coupon_code = data.get('coupon_code')
        
        if not coupon_code:
            return jsonify({'success': False, 'message': 'Coupon code required for free subscription'}), 400
        
        # Validate coupon server-side
        coupon = CouponCode.query.filter_by(code=coupon_code.upper()).first()
        
        if not coupon or not coupon.is_active:
            return jsonify({'success': False, 'message': 'Invalid or inactive coupon'}), 400
        
        # Check expiration
        if coupon.valid_until:
            today = date.today()
            valid_until_date = coupon.valid_until.date() if hasattr(coupon.valid_until, 'date') else coupon.valid_until
            if valid_until_date < today:
                return jsonify({'success': False, 'message': 'Coupon has expired'}), 400
        
        # Check usage limit
        if coupon.max_uses and coupon.uses_count >= coupon.max_uses:
            return jsonify({'success': False, 'message': 'Coupon has reached usage limit'}), 400
        
        # Verify it's a 100% discount coupon
        if coupon.discount_percent != 100:
            return jsonify({'success': False, 'message': 'This endpoint is only for 100% discount coupons'}), 400
        
        # Calculate subscription dates
        today = date.today()
        if plan == 'short':
            days = 30
        elif plan == 'midterm':
            days = 90
        elif plan == 'longterm':
            days = 180
        else:
            days = 30
        
        # Update user subscription
        user = User.query.get(current_user.id)
        
        # Check if this is a trial plan (3 days) and user has already used trial
        if days == 3 and user.has_used_trial:
            return jsonify({'success': False, 'message': 'Free trial can only be used once per account'}), 400
        
        # If user already has active subscription, extend from end date
        if user.subscription_end and user.subscription_end > today:
            user.subscription_start = user.subscription_end + timedelta(days=1)
        else:
            user.subscription_start = today
        
        user.subscription_end = user.subscription_start + timedelta(days=days)
        user.subscription_period = plan
        user.account_active = True
        
        # Mark trial as used if this is a 3-day trial
        if days == 3:
            user.has_used_trial = True
        
        # Increment coupon usage
        coupon.uses_count = (coupon.uses_count or 0) + 1
        
        db.session.commit()
        
        logger.info(f"Free subscription activated for user {user.username} using coupon {coupon_code}. Valid until {user.subscription_end}")
        
        # Send subscription activation email
        try:
            plan_names = {
                'short': 'Short Term (1 Month)',
                'midterm': 'Mid Term (3 Months)',
                'longterm': 'Long Term (6 Months)',
                'free_trial': 'Free Trial (3 Days)'
            }
            send_subscription_email(
                user_email=user.email,
                username=user.username,
                plan_name=plan_names.get(plan, 'Subscription'),
                start_date=user.subscription_start.strftime('%B %d, %Y'),
                end_date=user.subscription_end.strftime('%B %d, %Y')
            )
        except Exception as email_error:
            logger.error(f"Failed to send subscription email: {str(email_error)}")
        
        return jsonify({
            'success': True,
            'message': 'Free subscription activated successfully',
            'subscription_end': user.subscription_end.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error activating free subscription: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error activating subscription'}), 500

@app.route('/process-payment', methods=['POST'])
@login_required
def process_payment():
    """Process Razorpay payment and update user subscription"""
    import razorpay
    from datetime import date, timedelta
    
    try:
        data = request.get_json()
        payment_id = data.get('payment_id')
        plan = data.get('plan')
        amount = data.get('amount')  # Amount in paise from client
        validity = data.get('validity')
        coupon_code = data.get('coupon_code')  # Optional coupon code
        
        # Initialize Razorpay client
        razorpay_key_id = secrets.get('RAZORPAY_KEY_ID')
        razorpay_key_secret = secrets.get('RAZORPAY_KEY_SECRET')
        
        if not razorpay_key_id or not razorpay_key_secret:
            logger.error("Razorpay credentials not configured")
            return jsonify({'success': False, 'message': 'Payment gateway not configured'}), 500
        
        client = razorpay.Client(auth=(razorpay_key_id, razorpay_key_secret))
        
        # Verify payment
        try:
            payment = client.payment.fetch(payment_id)
            
            if payment['status'] == 'captured':
                # Get expected amount from database instead of hardcoded values
                plan_mapping = {
                    'short': 'Short Term',
                    'midterm': 'Mid Term',
                    'longterm': 'Long Term'
                }
                
                if plan not in plan_mapping:
                    logger.error(f"Invalid plan: {plan}")
                    return jsonify({'success': False, 'message': 'Invalid plan selected'}), 400
                
                # Fetch plan from database
                db_plan = SubscriptionPlan.query.filter_by(plan_name=plan_mapping[plan], is_active=True).first()
                
                if not db_plan:
                    logger.error(f"Plan not found in database: {plan}")
                    return jsonify({'success': False, 'message': 'Plan not available'}), 400
                
                # Calculate expected amount (with coupon if provided)
                expected_amount = db_plan.price * 100  # Convert to paise
                coupon_obj = None
                
                if coupon_code:
                    # Validate coupon server-side
                    coupon_obj = CouponCode.query.filter_by(code=coupon_code.upper()).first()
                    if coupon_obj and coupon_obj.is_active:
                        # Check expiration and usage limits
                        today = date.today()
                        is_valid = True
                        
                        if coupon_obj.valid_until:
                            valid_until_date = coupon_obj.valid_until.date() if hasattr(coupon_obj.valid_until, 'date') else coupon_obj.valid_until
                            if valid_until_date < today:
                                is_valid = False
                        
                        if coupon_obj.max_uses and coupon_obj.uses_count >= coupon_obj.max_uses:
                            is_valid = False
                        
                        if is_valid:
                            # Apply discount
                            if coupon_obj.discount_percent:
                                discount = int((expected_amount * coupon_obj.discount_percent) / 100)
                            elif coupon_obj.discount_amount:
                                discount = coupon_obj.discount_amount * 100
                            else:
                                discount = 0
                            
                            expected_amount = expected_amount - min(discount, expected_amount)
                            logger.info(f"Coupon {coupon_code} applied. Original: {expected_amounts[plan]}, Discounted: {expected_amount}")
                
                # Verify payment amount matches expected amount (with or without coupon)
                if payment['amount'] != expected_amount:
                    logger.error(f"Payment amount mismatch. Expected: {expected_amount}, Got: {payment['amount']}")
                    return jsonify({'success': False, 'message': 'Payment amount mismatch'}), 400
                
                # Payment successful and validated - update user subscription
                logger.info(f"Payment verified: {payment_id}, Plan: {plan}, Amount: {payment['amount']/100}, User: {current_user.username}")
                
                # Update user subscription in database
                user = User.query.get(current_user.id)
                
                # Capture mobile number from Razorpay payment contact field
                contact_number = payment.get('contact', '')
                if contact_number and (not user.mobile or user.mobile != contact_number):
                    user.mobile = contact_number
                    logger.info(f"Mobile number captured from payment: {contact_number} for user {user.username}")
                
                # Calculate subscription dates based on plan
                today = date.today()
                if plan == 'short':
                    days = 30  # 1 month
                elif plan == 'midterm':
                    days = 90  # 3 months
                elif plan == 'longterm':
                    days = 180  # 6 months
                else:
                    days = 30  # default to 1 month
                
                # If user already has active subscription, extend from end date
                if user.subscription_end and user.subscription_end > today:
                    user.subscription_start = user.subscription_end + timedelta(days=1)
                else:
                    user.subscription_start = today
                
                user.subscription_end = user.subscription_start + timedelta(days=days)
                user.subscription_period = plan
                user.account_active = True
                
                # Increment coupon usage count if coupon was used
                if coupon_obj:
                    coupon_obj.uses_count = (coupon_obj.uses_count or 0) + 1
                    logger.info(f"Coupon {coupon_code} usage incremented. Uses: {coupon_obj.uses_count}/{coupon_obj.max_uses or 'unlimited'}")
                
                db.session.commit()
                
                logger.info(f"Subscription updated for user {user.username}: {user.subscription_start} to {user.subscription_end}")
                
                # Send subscription activation email
                try:
                    send_subscription_email(
                        user_email=user.email,
                        username=user.username,
                        plan_name=db_plan.display_name,
                        start_date=user.subscription_start.strftime('%B %d, %Y'),
                        end_date=user.subscription_end.strftime('%B %d, %Y')
                    )
                except Exception as email_error:
                    logger.error(f"Failed to send subscription email: {str(email_error)}")
                
                return jsonify({
                    'success': True,
                    'message': 'Payment processed successfully',
                    'payment_id': payment_id,
                    'plan': plan,
                    'subscription_end': user.subscription_end.isoformat()
                })
            else:
                logger.warning(f"Payment not captured: {payment_id}, Status: {payment['status']}")
                return jsonify({'success': False, 'message': 'Payment not completed'}), 400
                
        except razorpay.errors.BadRequestError as e:
            logger.error(f"Razorpay verification failed: {str(e)}")
            return jsonify({'success': False, 'message': 'Payment verification failed'}), 400
            
    except Exception as e:
        logger.error(f"Error processing payment: {str(e)}")
        return jsonify({'success': False, 'message': 'Error processing payment'}), 500

@app.route('/subscription-required')
@login_required
def subscription_required():
    """Show subscription required message for users without active subscription"""
    # Allow access only to non-admin users with inactive subscriptions
    if current_user.is_admin() or current_user.is_subscription_active():
        return redirect(url_for('dashboard'))
    
    status = current_user.get_subscription_status()
    return render_template('subscription_required.html', subscription_status=status)


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Admin login page with username/password"""
    # If already logged in as admin, redirect to admin panel
    if current_user.is_authenticated and current_user.is_admin():
        return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_admin():
            # Log in the admin user
            login_user(user, remember=True)
            logger.info(f"Admin logged in: {username}")
            
            # Create user session for tracking
            try:
                client_ip = get_client_ip()
                user_agent = request.headers.get('User-Agent', '')
                user_session_id = create_user_session(user.id, client_ip, user_agent)
                session['user_session_id'] = user_session_id
            except Exception as e:
                logger.error(f"Error creating admin session: {str(e)}")
            
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid admin credentials', 'danger')
            logger.warning(f"Failed admin login attempt for username: {username}")
    
    return render_template('admin_login.html')

@app.route('/admin/panel')
@login_required
def admin_panel():
    """Main admin panel route"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('admin_panel.html')

@app.route('/admin/plans')
@login_required
def admin_plans():
    """Manage subscription plans"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    plans = SubscriptionPlan.query.order_by(SubscriptionPlan.validity_days).all()
    return render_template('admin_plans.html', plans=plans)

@app.route('/admin/plans/add', methods=['POST'])
@login_required
def admin_add_plan():
    """Add new subscription plan"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        plan_name = request.form.get('name')
        display_name = request.form.get('name')
        price = int(request.form.get('price'))
        strike_price_str = request.form.get('strike_price', '')
        strike_price = int(strike_price_str) if strike_price_str else None
        validity_days = int(request.form.get('duration_days'))
        description = request.form.get('description', '')
        is_active = 'is_active' in request.form
        
        validity_display = f"{validity_days} days"
        
        new_plan = SubscriptionPlan(
            plan_name=plan_name,
            display_name=display_name,
            price=price,
            strike_price=strike_price,
            validity_days=validity_days,
            validity_display=validity_display,
            description=description,
            is_active=is_active
        )
        
        db.session.add(new_plan)
        db.session.commit()
        
        flash(f'Plan "{plan_name}" created successfully!', 'success')
        return redirect(url_for('admin_plans'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error adding plan: {str(e)}')
        flash(f'Error creating plan: {str(e)}', 'danger')
        return redirect(url_for('admin_plans'))

@app.route('/admin/plans/update', methods=['POST'])
@login_required
def admin_update_plan():
    """Update subscription plan"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        plan_id = int(request.form.get('plan_id'))
        plan = SubscriptionPlan.query.get_or_404(plan_id)
        
        # Keep plan_name unchanged (it's the internal identifier)
        # Only update display_name (what users see)
        plan.display_name = request.form.get('name')
        plan.price = int(request.form.get('price'))
        strike_price_str = request.form.get('strike_price', '')
        plan.strike_price = int(strike_price_str) if strike_price_str else None
        validity_days = int(request.form.get('duration_days'))
        plan.validity_days = validity_days
        plan.validity_display = f"{validity_days} days"
        plan.description = request.form.get('description', '')
        plan.is_active = 'is_active' in request.form
        
        db.session.commit()
        
        flash(f'Plan "{plan.plan_name}" updated successfully!', 'success')
        return redirect(url_for('admin_plans'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating plan: {str(e)}')
        flash(f'Error updating plan: {str(e)}', 'danger')
        return redirect(url_for('admin_plans'))

@app.route('/admin/plans/delete', methods=['POST'])
@login_required
def admin_delete_plan():
    """Delete subscription plan"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        plan_id = data.get('plan_id')
        plan = SubscriptionPlan.query.get_or_404(plan_id)
        
        db.session.delete(plan)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Plan deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error deleting plan: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/coupons')
@login_required
def admin_coupons():
    """Manage coupon codes"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    coupons = CouponCode.query.order_by(CouponCode.created_at.desc()).all()
    return render_template('admin_coupons.html', coupons=coupons)

@app.route('/admin/coupons/add', methods=['POST'])
@login_required
def admin_add_coupon():
    """Add new coupon code"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        code = request.form.get('code').upper()
        discount_type = request.form.get('discount_type')
        discount_value = float(request.form.get('discount_value'))
        max_uses = request.form.get('max_usage')
        expiry_date_str = request.form.get('expiry_date')
        is_active = 'is_active' in request.form
        
        max_uses = int(max_uses) if max_uses else None
        valid_until = datetime.strptime(expiry_date_str, '%Y-%m-%d') if expiry_date_str else None
        
        new_coupon = CouponCode(
            code=code,
            discount_type=discount_type,
            discount_percent=discount_value if discount_type == 'percentage' else None,
            discount_amount=int(discount_value) if discount_type == 'fixed' else None,
            max_uses=max_uses,
            valid_until=valid_until,
            is_active=is_active
        )
        
        db.session.add(new_coupon)
        db.session.commit()
        
        flash(f'Coupon "{code}" created successfully!', 'success')
        return redirect(url_for('admin_coupons'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error adding coupon: {str(e)}')
        flash(f'Error creating coupon: {str(e)}', 'danger')
        return redirect(url_for('admin_coupons'))

@app.route('/admin/coupons/update', methods=['POST'])
@login_required
def admin_update_coupon():
    """Update coupon code"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        coupon_id = int(request.form.get('coupon_id'))
        coupon = CouponCode.query.get_or_404(coupon_id)
        
        coupon.code = request.form.get('code').upper()
        discount_type = request.form.get('discount_type')
        discount_value = float(request.form.get('discount_value'))
        
        coupon.discount_type = discount_type
        coupon.discount_percent = discount_value if discount_type == 'percentage' else None
        coupon.discount_amount = int(discount_value) if discount_type == 'fixed' else None
        
        max_uses = request.form.get('max_usage')
        coupon.max_uses = int(max_uses) if max_uses else None
        
        expiry_date_str = request.form.get('expiry_date')
        coupon.valid_until = datetime.strptime(expiry_date_str, '%Y-%m-%d') if expiry_date_str else None
        
        coupon.is_active = 'is_active' in request.form
        
        db.session.commit()
        
        flash(f'Coupon "{coupon.code}" updated successfully!', 'success')
        return redirect(url_for('admin_coupons'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating coupon: {str(e)}')
        flash(f'Error updating coupon: {str(e)}', 'danger')
        return redirect(url_for('admin_coupons'))

@app.route('/admin/coupons/delete', methods=['POST'])
@login_required
def admin_delete_coupon():
    """Delete coupon code"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        coupon_id = data.get('coupon_id')
        coupon = CouponCode.query.get_or_404(coupon_id)
        
        db.session.delete(coupon)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Coupon deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error deleting coupon: {str(e)}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/database')
@login_required
def admin_database():
    """Database management admin page"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for daily_ohlc_data
    query = text("""
        SELECT symbol, full_symbol, trading_date, open_price, high_price, 
               low_price, close_price, volume, created_at, updated_at
        FROM daily_ohlc_data
        WHERE 1=1
    """)
    
    # Add search filter if provided
    params = {}
    if search:
        query = text("""
            SELECT symbol, full_symbol, trading_date, open_price, high_price, 
                   low_price, close_price, volume, created_at, updated_at
            FROM daily_ohlc_data
            WHERE UPPER(symbol) LIKE UPPER(:search) OR UPPER(full_symbol) LIKE UPPER(:search)
            ORDER BY trading_date DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
    else:
        query = text("""
            SELECT symbol, full_symbol, trading_date, open_price, high_price, 
                   low_price, close_price, volume, created_at, updated_at
            FROM daily_ohlc_data
            ORDER BY trading_date DESC, symbol ASC
        """)
    
    # Get total count for pagination
    count_query = text("SELECT COUNT(*) as total FROM daily_ohlc_data")
    if search:
        count_query = text("""
            SELECT COUNT(*) as total FROM daily_ohlc_data
            WHERE UPPER(symbol) LIKE UPPER(:search) OR UPPER(full_symbol) LIKE UPPER(:search)
        """)
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_database.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/admin/users')
@login_required
def admin_users():
    """User management admin page"""
    from datetime import date
    
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get today's activations (users who activated subscriptions today)
    today = date.today()
    todays_activations = User.query.filter(
        User.subscription_start == today,
        User.account_active == True
    ).order_by(User.subscription_start.desc()).all()
    
    # Separate users by account activation status
    pending_users = User.query.filter_by(account_active=False).all()
    active_users = User.query.filter_by(account_active=True).all()
    all_users = pending_users + active_users
    
    # Calculate subscription active/inactive user counts
    subscription_active_count = sum(1 for user in all_users if user.is_subscription_active())
    subscription_inactive_count = len(all_users) - subscription_active_count
    
    return render_template('admin_users.html', 
                         users=all_users,
                         pending_users=pending_users,
                         active_users=active_users,
                         pending_count=len(pending_users),
                         active_users_count=subscription_active_count,
                         inactive_users_count=subscription_inactive_count,
                         todays_activations=todays_activations,
                         todays_activation_count=len(todays_activations))

@app.route('/admin/database/camarilla')
@login_required
def admin_camarilla_levels():
    """Camarilla levels database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for camarilla_levels
    params = {}
    if search:
        query = text("""
            SELECT symbol, date, prev_close, pivot, r5, r4, r3, r2, r1, s1, s2, s3, s4, s5, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM camarilla_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
            ORDER BY date DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM camarilla_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT symbol, date, prev_close, pivot, r5, r4, r3, r2, r1, s1, s2, s3, s4, s5, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM camarilla_levels
            ORDER BY date DESC, symbol ASC
        """)
        count_query = text("SELECT COUNT(*) as total FROM camarilla_levels")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_camarilla.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/admin/database/cpr')
@login_required
def admin_cpr_levels():
    """CPR levels database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for cpr_levels
    params = {}
    if search:
        query = text("""
            SELECT symbol, date, pp, tc, bc, r1, r2, r3, s1, s2, s3, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM cpr_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
            ORDER BY date DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM cpr_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT symbol, date, pp, tc, bc, r1, r2, r3, s1, s2, s3, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM cpr_levels
            ORDER BY date DESC, symbol ASC
        """)
        count_query = text("SELECT COUNT(*) as total FROM cpr_levels")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_cpr.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/admin/database/fibonacci')
@login_required
def admin_fibonacci_levels():
    """Fibonacci levels database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for fibonacci_levels
    params = {}
    if search:
        query = text("""
            SELECT symbol, date, prev_close, pp, r1_61, r2_123, r3_161, s1_61, s2_123, s3_161, level_38, level_50, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM fibonacci_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
            ORDER BY date DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM fibonacci_levels
            WHERE UPPER(symbol) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT symbol, date, prev_close, pp, r1_61, r2_123, r3_161, s1_61, s2_123, s3_161, level_38, level_50, current_ltp, break_level, trend_direction, created_at, updated_at
            FROM fibonacci_levels
            ORDER BY date DESC, symbol ASC
        """)
        count_query = text("SELECT COUNT(*) as total FROM fibonacci_levels")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_fibonacci.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/admin/database/historical')
@login_required
def admin_historical_data():
    """Historical data database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for historical_data
    params = {}
    if search:
        query = text("""
            SELECT symbol, candle_time, open_price, high_price, low_price, close_price, volume, resolution, created_at
            FROM historical_data
            WHERE UPPER(symbol) LIKE UPPER(:search)
            ORDER BY candle_time DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM historical_data
            WHERE UPPER(symbol) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT symbol, candle_time, open_price, high_price, low_price, close_price, volume, resolution, created_at
            FROM historical_data
            ORDER BY candle_time DESC, symbol ASC
        """)
        count_query = text("SELECT COUNT(*) as total FROM historical_data")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_historical.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)


@app.route('/admin/database/tokens')
@login_required
def admin_access_tokens():
    """Access tokens database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for access_tokens
    params = {}
    if search:
        query = text("""
            SELECT id, token_type, access_token, expires_at, created_at, updated_at
            FROM access_tokens
            WHERE UPPER(token_type) LIKE UPPER(:search)
            ORDER BY created_at DESC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM access_tokens
            WHERE UPPER(token_type) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT id, token_type, access_token, expires_at, created_at, updated_at
            FROM access_tokens
            ORDER BY created_at DESC
        """)
        count_query = text("SELECT COUNT(*) as total FROM access_tokens")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_tokens.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

@app.route('/admin/database/hist_data_365')
@login_required
def admin_hist_data_365():
    """365-day historical data database admin view"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '')
    
    # Base query for hist_data_365
    params = {}
    if search:
        query = text("""
            SELECT id, symbol, date, datetime_stamp, open, high, low, close, volume, timeframe, source, day_of_week, created_at
            FROM hist_data_365
            WHERE UPPER(symbol) LIKE UPPER(:search)
            ORDER BY date DESC, symbol ASC
        """)
        params['search'] = f'%{search}%'
        count_query = text("""
            SELECT COUNT(*) as total FROM hist_data_365
            WHERE UPPER(symbol) LIKE UPPER(:search)
        """)
    else:
        query = text("""
            SELECT id, symbol, date, datetime_stamp, open, high, low, close, volume, timeframe, source, day_of_week, created_at
            FROM hist_data_365
            ORDER BY date DESC, symbol ASC
        """)
        count_query = text("SELECT COUNT(*) as total FROM hist_data_365")
    
    count_result = db.session.execute(count_query, params).fetchone()
    total_records = count_result.total if count_result else 0
    
    # Calculate offset and get paginated results
    offset = (page - 1) * per_page
    paginated_query = text(str(query) + f" LIMIT :limit OFFSET :offset")
    params.update({'limit': per_page, 'offset': offset})
    
    records = db.session.execute(paginated_query, params).fetchall()
    
    # Calculate pagination info
    total_pages = (total_records + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin_hist_data_365.html', 
                         records=records,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         search=search)

def get_hist_access_token():
    """Get historical data access token from session or database fallback (authenticated users only)"""
    try:
        # Only allow authenticated users to access historical data tokens
        if not current_user.is_authenticated:
            logger.warning("Unauthenticated user attempted to access historical data token")
            return None
            
        # First try session
        hist_access_token = session.get('hist_access_token')
        if hist_access_token:
            return hist_access_token
            
        # Fallback to database (only for authenticated users)
        logger.info("Session token missing, checking database for stored historical data token")
        result = fyers_hist_auth.get_valid_token()
        
        if result['status'] == 'success':
            # Found valid token in database, update session
            hist_access_token = result['access_token']
            session['hist_access_token'] = hist_access_token
            session['hist_authenticated'] = True
            logger.info(f"Loaded historical data token from database, expires at: {result['expires_at']}")
            return hist_access_token
        else:
            logger.info("No valid stored historical data token found")
            return None
            
    except Exception as e:
        logger.error(f"Error getting historical data access token: {str(e)}")
        return None

@app.route('/admin/database/daily-ohlc/download-csv', methods=['GET'])
@login_required
def download_daily_ohlc_csv():
    """Download Daily OHLC Data as CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from flask import make_response
        
        # Query all daily OHLC data
        query = text("""
            SELECT symbol, full_symbol, trading_date, open_price, high_price, 
                   low_price, close_price, volume, created_at, updated_at
            FROM daily_ohlc_data
            ORDER BY trading_date DESC, symbol ASC
        """)
        
        records = db.session.execute(query).fetchall()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write header
        writer.writerow(['Symbol', 'Full Symbol', 'Trading Date', 'Open', 'High', 'Low', 'Close', 'Volume', 'Created At', 'Updated At'])
        
        # Write data rows
        for record in records:
            writer.writerow([
                record.symbol,
                record.full_symbol,
                record.trading_date,
                record.open_price,
                record.high_price,
                record.low_price,
                record.close_price,
                record.volume,
                record.created_at,
                record.updated_at
            ])
        
        # Create response
        output = si.getvalue()
        response = make_response(output)
        response.headers["Content-Disposition"] = "attachment; filename=daily_ohlc_data.csv"
        response.headers["Content-type"] = "text/csv"
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading daily OHLC CSV: {str(e)}")
        flash(f'Error downloading CSV: {str(e)}', 'danger')
        return redirect(url_for('admin_database'))

@app.route('/admin/database/hist-365/download-csv', methods=['GET'])
@login_required
def download_hist_365_csv():
    """Download 365-Day Historical Data as CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from flask import make_response
        
        # Query all 365-day historical data
        query = text("""
            SELECT id, symbol, date, datetime_stamp, open, high, low, close, 
                   volume, timeframe, source, day_of_week, created_at
            FROM hist_data_365
            ORDER BY date DESC, symbol ASC
        """)
        
        records = db.session.execute(query).fetchall()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write header
        writer.writerow(['ID', 'Symbol', 'Date', 'Datetime', 'Open', 'High', 'Low', 'Close', 'Volume', 'Timeframe', 'Source', 'Day of Week', 'Created At'])
        
        # Write data rows
        for record in records:
            writer.writerow([
                record.id,
                record.symbol,
                record.date,
                record.datetime_stamp,
                record.open,
                record.high,
                record.low,
                record.close,
                record.volume,
                record.timeframe,
                record.source,
                record.day_of_week,
                record.created_at
            ])
        
        # Create response
        output = si.getvalue()
        response = make_response(output)
        response.headers["Content-Disposition"] = "attachment; filename=hist_data_365.csv"
        response.headers["Content-type"] = "text/csv"
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading 365-day historical CSV: {str(e)}")
        flash(f'Error downloading CSV: {str(e)}', 'danger')
        return redirect(url_for('admin_hist_data_365'))

@app.route('/admin/database/daily-ohlc/upload-csv', methods=['POST'])
@login_required
def upload_daily_ohlc_csv():
    """Upload Daily OHLC Data from CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from datetime import datetime as dt
        
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_database'))
        
        file = request.files['csv_file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin_database'))
        
        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'danger')
            return redirect(url_for('admin_database'))
        
        # Read CSV file
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        records_added = 0
        records_updated = 0
        
        for row in csv_reader:
            try:
                symbol = row.get('Symbol', '').strip()
                full_symbol = row.get('Full Symbol', '').strip()
                trading_date = row.get('Trading Date', '').strip()
                
                if not symbol or not trading_date:
                    continue
                
                # Parse date
                date_obj = dt.strptime(trading_date, '%Y-%m-%d').date()
                
                # Check if record exists
                existing = db.session.execute(
                    text("SELECT id FROM daily_ohlc_data WHERE symbol = :symbol AND trading_date = :date"),
                    {'symbol': symbol, 'date': date_obj}
                ).fetchone()
                
                if existing:
                    # Update existing record
                    db.session.execute(
                        text("""
                            UPDATE daily_ohlc_data 
                            SET full_symbol = :full_symbol,
                                open_price = :open_price,
                                high_price = :high_price,
                                low_price = :low_price,
                                close_price = :close_price,
                                volume = :volume,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE symbol = :symbol AND trading_date = :date
                        """),
                        {
                            'symbol': symbol,
                            'full_symbol': full_symbol,
                            'date': date_obj,
                            'open_price': float(row.get('Open', 0)),
                            'high_price': float(row.get('High', 0)),
                            'low_price': float(row.get('Low', 0)),
                            'close_price': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0))
                        }
                    )
                    records_updated += 1
                else:
                    # Insert new record
                    db.session.execute(
                        text("""
                            INSERT INTO daily_ohlc_data 
                            (symbol, full_symbol, trading_date, open_price, high_price, low_price, close_price, volume, created_at, updated_at)
                            VALUES (:symbol, :full_symbol, :date, :open_price, :high_price, :low_price, :close_price, :volume, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """),
                        {
                            'symbol': symbol,
                            'full_symbol': full_symbol,
                            'date': date_obj,
                            'open_price': float(row.get('Open', 0)),
                            'high_price': float(row.get('High', 0)),
                            'low_price': float(row.get('Low', 0)),
                            'close_price': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0))
                        }
                    )
                    records_added += 1
                    
            except Exception as row_error:
                logger.error(f"Error processing row: {row_error}")
                continue
        
        db.session.commit()
        flash(f'CSV upload successful! Added: {records_added}, Updated: {records_updated}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error uploading CSV: {str(e)}")
        flash(f'Error uploading CSV: {str(e)}', 'danger')
    
    return redirect(url_for('admin_database'))

@app.route('/admin/database/hist-365/upload-csv', methods=['POST'])
@login_required
def upload_hist_365_csv():
    """Upload 365-Day Historical Data from CSV"""
    logger.info("📤 365-Day Historical CSV upload route accessed")
    
    if not current_user.is_admin():
        logger.warning("Non-admin user attempted 365-day data upload")
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from datetime import datetime as dt
        
        logger.info("📤 Starting 365-day CSV upload process")
        
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            logger.warning("No csv_file in request.files")
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_hist_data_365'))
        
        file = request.files['csv_file']
        logger.info(f"📤 File received: {file.filename}")
        
        if file.filename == '':
            logger.warning("Empty filename")
            flash('No file selected', 'danger')
            return redirect(url_for('admin_hist_data_365'))
        
        if not file.filename.endswith('.csv'):
            logger.warning(f"Invalid file type: {file.filename}")
            flash('Please upload a CSV file', 'danger')
            return redirect(url_for('admin_hist_data_365'))
        
        # Read CSV file
        logger.info(f"📤 Reading CSV file: {file.filename}")
        csv_content = file.stream.read().decode("UTF8")
        stream = StringIO(csv_content, newline=None)
        csv_reader = csv.DictReader(stream)
        
        logger.info("📤 CSV file parsed successfully, starting row processing...")
        
        records_added = 0
        records_updated = 0
        records_failed = 0
        batch_size = 100
        batch_count = 0
        
        for row in csv_reader:
            try:
                symbol = row.get('Symbol', '').strip()
                date_str = row.get('Date', '').strip()
                datetime_str = row.get('Datetime', '').strip()
                
                if not symbol or not date_str:
                    continue
                
                # Parse dates
                date_obj = dt.strptime(date_str, '%Y-%m-%d').date()
                datetime_obj = dt.strptime(datetime_str, '%Y-%m-%d %H:%M:%S') if datetime_str else None
                
                # Check if record exists
                existing = db.session.execute(
                    text("SELECT id FROM hist_data_365 WHERE symbol = :symbol AND date = :date"),
                    {'symbol': symbol, 'date': date_obj}
                ).fetchone()
                
                if existing:
                    # Update existing record
                    db.session.execute(
                        text("""
                            UPDATE hist_data_365 
                            SET datetime_stamp = :datetime_stamp,
                                open = :open,
                                high = :high,
                                low = :low,
                                close = :close,
                                volume = :volume,
                                timeframe = :timeframe,
                                source = :source,
                                day_of_week = :day_of_week
                            WHERE symbol = :symbol AND date = :date
                        """),
                        {
                            'symbol': symbol,
                            'date': date_obj,
                            'datetime_stamp': datetime_obj,
                            'open': float(row.get('Open', 0)),
                            'high': float(row.get('High', 0)),
                            'low': float(row.get('Low', 0)),
                            'close': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0)),
                            'timeframe': row.get('Timeframe', 'D'),
                            'source': row.get('Source', 'csv_upload'),
                            'day_of_week': row.get('Day of Week', '')
                        }
                    )
                    records_updated += 1
                else:
                    # Insert new record
                    db.session.execute(
                        text("""
                            INSERT INTO hist_data_365 
                            (symbol, date, datetime_stamp, open, high, low, close, volume, timeframe, source, day_of_week, created_at)
                            VALUES (:symbol, :date, :datetime_stamp, :open, :high, :low, :close, :volume, :timeframe, :source, :day_of_week, CURRENT_TIMESTAMP)
                        """),
                        {
                            'symbol': symbol,
                            'date': date_obj,
                            'datetime_stamp': datetime_obj,
                            'open': float(row.get('Open', 0)),
                            'high': float(row.get('High', 0)),
                            'low': float(row.get('Low', 0)),
                            'close': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0)),
                            'timeframe': row.get('Timeframe', 'D'),
                            'source': row.get('Source', 'csv_upload'),
                            'day_of_week': row.get('Day of Week', '')
                        }
                    )
                    records_added += 1
                
                # Commit in batches
                batch_count += 1
                if batch_count % batch_size == 0:
                    db.session.commit()
                    logger.info(f"📤 Committed batch at {batch_count} records (Added: {records_added}, Updated: {records_updated})")
                    
            except Exception as row_error:
                db.session.rollback()
                records_failed += 1
                logger.error(f"📤 Error processing row for {symbol} at {date_str}: {str(row_error)}")
                continue
        
        # Final commit
        db.session.commit()
        total_processed = records_added + records_updated
        logger.info(f"📤 CSV upload completed! Added: {records_added}, Updated: {records_updated}, Failed: {records_failed}")
        
        if records_failed > 0:
            flash(f'CSV upload completed! Added: {records_added}, Updated: {records_updated}, Failed: {records_failed}', 'warning')
        else:
            flash(f'CSV upload successful! Added: {records_added}, Updated: {records_updated}', 'success')
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"📤 Error uploading 365-day CSV: {str(e)}\n{error_details}")
        flash(f'Error uploading CSV: {str(e)}', 'danger')
    
    return redirect(url_for('admin_hist_data_365'))

@app.route('/admin/database/minute-data', methods=['GET'])
@login_required
def admin_minute_data():
    """Admin page for managing minute resolution data"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Get timeframe from query parameter (default to 5min)
        timeframe = request.args.get('timeframe', '5min')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '').strip()
        
        # Map timeframe to table name
        table_name = f'hist_data_{timeframe}'
        
        # Build query with search
        if search:
            count_query = text(f"""
                SELECT COUNT(*) as count 
                FROM {table_name}
                WHERE symbol ILIKE :search
            """)
            data_query = text(f"""
                SELECT id, symbol, datetime_stamp, open, high, low, close, volume, source, created_at
                FROM {table_name}
                WHERE symbol ILIKE :search
                ORDER BY datetime_stamp DESC, symbol ASC
                LIMIT :limit OFFSET :offset
            """)
            count_result = db.session.execute(count_query, {'search': f'%{search}%'}).fetchone()
            records = db.session.execute(data_query, {
                'search': f'%{search}%',
                'limit': per_page,
                'offset': (page - 1) * per_page
            }).fetchall()
        else:
            count_query = text(f"SELECT COUNT(*) as count FROM {table_name}")
            data_query = text(f"""
                SELECT id, symbol, datetime_stamp, open, high, low, close, volume, source, created_at
                FROM {table_name}
                ORDER BY datetime_stamp DESC, symbol ASC
                LIMIT :limit OFFSET :offset
            """)
            count_result = db.session.execute(count_query).fetchone()
            records = db.session.execute(data_query, {
                'limit': per_page,
                'offset': (page - 1) * per_page
            }).fetchall()
        
        total_records = count_result.count
        total_pages = (total_records + per_page - 1) // per_page
        
        # Available timeframes
        timeframes = ['1min', '2min', '3min', '5min', '10min', '15min', '20min', '30min', '45min', '60min', '120min', '180min', '240min']
        
        return render_template('admin_minute_data.html',
            records=records,
            total_records=total_records,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            search=search,
            timeframe=timeframe,
            timeframes=timeframes,
            has_prev=page > 1,
            has_next=page < total_pages
        )
        
    except Exception as e:
        logger.error(f"Error loading minute data: {str(e)}")
        flash(f'Error loading data: {str(e)}', 'danger')
        return redirect(url_for('admin_panel'))

@app.route('/admin/database/minute-data/download-csv', methods=['GET'])
@login_required
def download_minute_data_csv():
    """Download minute resolution data as CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from flask import make_response
        
        timeframe = request.args.get('timeframe', '5min')
        table_name = f'hist_data_{timeframe}'
        
        # Query all data for the selected timeframe
        query = text(f"""
            SELECT id, symbol, datetime_stamp, open, high, low, close, volume, source, created_at
            FROM {table_name}
            ORDER BY datetime_stamp DESC, symbol ASC
        """)
        
        records = db.session.execute(query).fetchall()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write header
        writer.writerow(['ID', 'Symbol', 'Datetime', 'Open', 'High', 'Low', 'Close', 'Volume', 'Source', 'Created At'])
        
        # Write data rows
        for record in records:
            writer.writerow([
                record.id,
                record.symbol,
                record.datetime_stamp,
                record.open,
                record.high,
                record.low,
                record.close,
                record.volume,
                record.source,
                record.created_at
            ])
        
        # Create response
        output = si.getvalue()
        response = make_response(output)
        response.headers["Content-Disposition"] = f"attachment; filename=hist_data_{timeframe}.csv"
        response.headers["Content-type"] = "text/csv"
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading minute data CSV: {str(e)}")
        flash(f'Error downloading CSV: {str(e)}', 'danger')
        return redirect(url_for('admin_minute_data'))

@app.route('/admin/database/minute-data/upload-csv', methods=['POST'])
@login_required
def upload_minute_data_csv():
    """Upload minute resolution data from CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from datetime import datetime as dt
        
        timeframe = request.form.get('timeframe', '5min')
        table_name = f'hist_data_{timeframe}'
        
        logger.info(f"Starting CSV upload for timeframe: {timeframe}, table: {table_name}")
        
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            logger.warning("No file uploaded in request")
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_minute_data', timeframe=timeframe))
        
        file = request.files['csv_file']
        
        if file.filename == '':
            logger.warning("Empty filename")
            flash('No file selected', 'danger')
            return redirect(url_for('admin_minute_data', timeframe=timeframe))
        
        if not file.filename.endswith('.csv'):
            logger.warning(f"Invalid file type: {file.filename}")
            flash('Please upload a CSV file', 'danger')
            return redirect(url_for('admin_minute_data', timeframe=timeframe))
        
        # Read CSV file
        logger.info(f"Reading CSV file: {file.filename}")
        csv_content = file.stream.read().decode("UTF8")
        stream = StringIO(csv_content, newline=None)
        csv_reader = csv.DictReader(stream)
        
        records_added = 0
        records_updated = 0
        batch_size = 500  # Process in batches
        batch_count = 0
        
        logger.info("Starting to process CSV rows...")
        
        for row in csv_reader:
            try:
                symbol = row.get('Symbol', '').strip()
                datetime_str = row.get('Datetime', '').strip()
                
                if not symbol or not datetime_str:
                    continue
                
                # Parse datetime
                datetime_obj = dt.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
                
                # Check if record exists
                existing = db.session.execute(
                    text(f"SELECT id FROM {table_name} WHERE symbol = :symbol AND datetime_stamp = :datetime"),
                    {'symbol': symbol, 'datetime': datetime_obj}
                ).fetchone()
                
                if existing:
                    # Update existing record
                    db.session.execute(
                        text(f"""
                            UPDATE {table_name} 
                            SET open = :open,
                                high = :high,
                                low = :low,
                                close = :close,
                                volume = :volume,
                                source = :source
                            WHERE symbol = :symbol AND datetime_stamp = :datetime
                        """),
                        {
                            'symbol': symbol,
                            'datetime': datetime_obj,
                            'open': float(row.get('Open', 0)),
                            'high': float(row.get('High', 0)),
                            'low': float(row.get('Low', 0)),
                            'close': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0)),
                            'source': row.get('Source', 'csv_upload')
                        }
                    )
                    records_updated += 1
                else:
                    # Insert new record
                    db.session.execute(
                        text(f"""
                            INSERT INTO {table_name} 
                            (symbol, datetime_stamp, open, high, low, close, volume, source, created_at)
                            VALUES (:symbol, :datetime, :open, :high, :low, :close, :volume, :source, CURRENT_TIMESTAMP)
                        """),
                        {
                            'symbol': symbol,
                            'datetime': datetime_obj,
                            'open': float(row.get('Open', 0)),
                            'high': float(row.get('High', 0)),
                            'low': float(row.get('Low', 0)),
                            'close': float(row.get('Close', 0)),
                            'volume': int(row.get('Volume', 0)),
                            'source': row.get('Source', 'csv_upload')
                        }
                    )
                    records_added += 1
                
                # Commit in batches to avoid memory issues
                batch_count += 1
                if batch_count % batch_size == 0:
                    db.session.commit()
                    logger.info(f"Committed batch at {batch_count} records (Added: {records_added}, Updated: {records_updated})")
                    
            except Exception as row_error:
                logger.error(f"Error processing row for {symbol} at {datetime_str}: {str(row_error)}")
                continue
        
        # Final commit
        db.session.commit()
        logger.info(f"CSV upload completed! Total Added: {records_added}, Updated: {records_updated}")
        flash(f'CSV upload successful! Added: {records_added}, Updated: {records_updated}', 'success')
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error uploading CSV: {str(e)}\n{error_details}")
        flash(f'Error uploading CSV: {str(e)}', 'danger')
    
    return redirect(url_for('admin_minute_data', timeframe=timeframe))

@app.route('/admin/database/users/download-csv', methods=['GET'])
@login_required
def download_users_csv():
    """Download Users Database as CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        
        # Query all users
        users = User.query.order_by(User.id).all()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write header
        writer.writerow(['ID', 'Username', 'Email', 'Mobile', 'Role', 'Google ID', 'Profile Image URL', 
                        'Subscription Period', 'Subscription Start', 'Subscription End', 
                        'Has Used Trial', 'Account Active', 'Created At', 'Last Login'])
        
        # Write data rows
        for user in users:
            writer.writerow([
                user.id,
                user.username,
                user.email or '',
                user.mobile or '',
                user.role,
                user.google_id or '',
                user.profile_image_url or '',
                user.subscription_period or 'monthly',
                user.subscription_start.isoformat() if user.subscription_start else '',
                user.subscription_end.isoformat() if user.subscription_end else '',
                user.has_used_trial,
                user.account_active,
                user.created_at.isoformat() if user.created_at else '',
                user.last_login.isoformat() if user.last_login else ''
            ])
        
        # Create response
        output = si.getvalue()
        response = make_response(output)
        response.headers["Content-Disposition"] = "attachment; filename=users_database.csv"
        response.headers["Content-type"] = "text/csv"
        
        logger.info(f"Admin {current_user.username} downloaded {len(users)} users as CSV")
        return response
        
    except Exception as e:
        logger.error(f"Error downloading users CSV: {str(e)}")
        flash(f'Error downloading CSV: {str(e)}', 'danger')
        return redirect(url_for('admin_database'))

@app.route('/admin/database/users/upload-csv', methods=['POST'])
@login_required
def upload_users_csv():
    """Upload Users Database from CSV"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        import csv
        from io import StringIO
        from datetime import datetime as dt
        
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_database'))
        
        file = request.files['csv_file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin_database'))
        
        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'danger')
            return redirect(url_for('admin_database'))
        
        # Read CSV file
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        records_added = 0
        records_updated = 0
        records_skipped = 0
        
        for row in csv_reader:
            try:
                user_id = row.get('ID', '').strip()
                username = row.get('Username', '').strip()
                email = row.get('Email', '').strip()
                
                if not username:
                    records_skipped += 1
                    continue
                
                # Check if user exists by ID or username
                existing_user = None
                if user_id and user_id.isdigit():
                    existing_user = User.query.get(int(user_id))
                if not existing_user:
                    existing_user = User.query.filter_by(username=username).first()
                
                # Parse dates
                subscription_start = None
                subscription_end = None
                created_at = None
                last_login = None
                
                if row.get('Subscription Start'):
                    try:
                        subscription_start = dt.fromisoformat(row['Subscription Start']).date()
                    except:
                        pass
                
                if row.get('Subscription End'):
                    try:
                        subscription_end = dt.fromisoformat(row['Subscription End']).date()
                    except:
                        pass
                
                if row.get('Created At'):
                    try:
                        created_at = dt.fromisoformat(row['Created At'])
                    except:
                        pass
                
                if row.get('Last Login'):
                    try:
                        last_login = dt.fromisoformat(row['Last Login'])
                    except:
                        pass
                
                if existing_user:
                    # Update existing user (but not password or sensitive data)
                    existing_user.email = email if email else existing_user.email
                    existing_user.mobile = row.get('Mobile', '').strip() or existing_user.mobile
                    existing_user.role = row.get('Role', 'user').strip()
                    existing_user.subscription_period = row.get('Subscription Period', 'monthly').strip()
                    existing_user.subscription_start = subscription_start if subscription_start else existing_user.subscription_start
                    existing_user.subscription_end = subscription_end if subscription_end else existing_user.subscription_end
                    existing_user.has_used_trial = row.get('Has Used Trial', 'False').strip().lower() in ['true', '1', 'yes']
                    existing_user.account_active = row.get('Account Active', 'True').strip().lower() in ['true', '1', 'yes']
                    
                    records_updated += 1
                else:
                    # Create new user
                    new_user = User(
                        username=username,
                        email=email if email else None,
                        mobile=row.get('Mobile', '').strip() or None,
                        role=row.get('Role', 'user').strip(),
                        google_id=row.get('Google ID', '').strip() or None,
                        profile_image_url=row.get('Profile Image URL', '').strip() or None,
                        subscription_period=row.get('Subscription Period', 'monthly').strip(),
                        subscription_start=subscription_start,
                        subscription_end=subscription_end,
                        has_used_trial=row.get('Has Used Trial', 'False').strip().lower() in ['true', '1', 'yes'],
                        account_active=row.get('Account Active', 'True').strip().lower() in ['true', '1', 'yes'],
                        created_at=created_at if created_at else datetime.utcnow(),
                        last_login=last_login
                    )
                    db.session.add(new_user)
                    records_added += 1
                    
            except Exception as row_error:
                logger.error(f"Error processing row for user {username}: {str(row_error)}")
                records_skipped += 1
                continue
        
        db.session.commit()
        flash(f'CSV upload successful! Added: {records_added}, Updated: {records_updated}, Skipped: {records_skipped}', 'success')
        logger.info(f"Admin {current_user.username} uploaded users CSV - Added: {records_added}, Updated: {records_updated}, Skipped: {records_skipped}")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error uploading users CSV: {str(e)}")
        flash(f'Error uploading CSV: {str(e)}', 'danger')
    
    return redirect(url_for('admin_database'))

@app.route('/hist_data_365_download', methods=['GET'])
@login_required
def hist_data_365_download():
    """Page for downloading 365 candles data after HistData authentication"""
    # Check if user is authenticated for historical data (session or database)
    hist_access_token = get_hist_access_token()
    if not hist_access_token:
        flash('Please authenticate for historical data access first.', 'danger')
        return redirect(url_for('admin_panel'))
    
    return render_template('hist_data_365_download.html')

@app.route('/minute_hist_data_download', methods=['GET'])
@login_required
def minute_hist_data_download():
    """Page for downloading minute resolution historical data"""
    hist_access_token = get_hist_access_token()
    if not hist_access_token:
        flash('Please authenticate for historical data access first.', 'danger')
        return redirect(url_for('admin_panel'))
    
    return render_template('minute_hist_data_download.html')

@app.route('/api/hist_data_365/download', methods=['POST'])
@login_required
def download_hist_data_365():
    """Download configurable days of historical data for a specific symbol"""
    symbol = None  # Initialize to avoid unbound variable warnings
    try:
        data = request.get_json() or {}
        symbol = data.get('symbol', '').strip()
        days = data.get('days', 365)  # Default to 365 if not provided
        
        if not symbol:
            return jsonify({
                'status': 'error',
                'message': 'Symbol is required'
            }), 400
        
        # Validate days parameter
        if not isinstance(days, int) or days < 1 or days > 3650:
            return jsonify({
                'status': 'error',
                'message': 'Days must be an integer between 1 and 3650'
            }), 400
        
        # Check if historical data authentication is available (session or database)
        hist_access_token = get_hist_access_token()
        if not hist_access_token:
            return jsonify({
                'status': 'error',
                'message': 'Historical data authentication required'
            }), 401
        
        # Initialize Fyers API for historical data
        fyers = fyersModel.FyersModel(client_id=Config.FYERS_HIST_DATA_APP_ID, token=hist_access_token)
        
        # Convert clean symbol to full symbol format for Fyers API
        # Handle symbols that already have exchange prefix
        if ':' in symbol:
            # Symbol already has exchange prefix (e.g., BSE:SENSEX, NSE:RELIANCE)
            if 'SENSEX' in symbol.upper() or 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                full_symbol = f"{symbol}-INDEX" if not symbol.endswith('-INDEX') else symbol
            else:
                full_symbol = f"{symbol}-EQ" if not symbol.endswith('-EQ') else symbol
        else:
            # Clean symbol without exchange prefix
            if 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                full_symbol = f"NSE:{symbol}-INDEX"
            elif 'SENSEX' in symbol.upper():
                full_symbol = f"BSE:{symbol}-INDEX"
            else:
                full_symbol = f"NSE:{symbol}-EQ"
        
        # Get historical data for specified number of days
        from datetime import datetime, timedelta
        
        # Always end at last trading day to avoid incomplete current day data and weekends
        end_date = datetime.now()
        
        # Find the last trading day (skip weekends)
        while end_date.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
            end_date = end_date - timedelta(days=1)
        
        # Go back one more day to get the previous trading day's complete data
        end_date = end_date - timedelta(days=1)
        while end_date.weekday() >= 5:  # Skip weekends
            end_date = end_date - timedelta(days=1)
        
        # Try to find a valid trading day with data (handle market holidays)
        max_attempts = 10
        response = None
        
        for attempt in range(max_attempts):
            # Calculate start_date by going back the required number of trading days
            start_date = end_date
            trading_days_found = 0
            while trading_days_found < days - 1:
                start_date = start_date - timedelta(days=1)
                if start_date.weekday() < 5:  # Monday = 0, Friday = 4
                    trading_days_found += 1
            
            hist_data_request = {
                "symbol": full_symbol,
                "resolution": "D",  # Daily candles
                "date_format": "1",  # Unix timestamp
                "range_from": start_date.strftime("%Y-%m-%d"),
                "range_to": end_date.strftime("%Y-%m-%d"),
                "cont_flag": "1"
            }
            
            logger.info(f"🔍 API Request (attempt {attempt + 1}) for symbol: {symbol} → {full_symbol}, resolution: D, range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            logger.info(f"🔍 Full hist_data_request: {hist_data_request}")
            
            response = fyers.history(hist_data_request)
            
            # Check if we got valid data
            if isinstance(response, dict) and response.get('s') == 'ok' and response.get('candles'):
                logger.info(f"✅ Successfully fetched data for {symbol} with end_date {end_date.strftime('%Y-%m-%d')}")
                break
            elif isinstance(response, dict) and response.get('s') == 'no_data':
                # No data for this date (likely a market holiday), try previous day
                logger.warning(f"⚠️ No data for {symbol} on {end_date.strftime('%Y-%m-%d')} (market holiday?), trying previous day...")
                end_date = end_date - timedelta(days=1)
                while end_date.weekday() >= 5:  # Skip weekends
                    end_date = end_date - timedelta(days=1)
            else:
                # Other error, break and handle below
                break
        
        # Ensure response is a dictionary and handle API response
        if isinstance(response, dict) and response.get('s') == 'ok' and response.get('candles'):
            candles = response.get('candles', [])
            records_saved = 0
            
            # Save each candle to the HistData365 table
            for candle in candles:
                timestamp = datetime.fromtimestamp(candle[0])
                candle_data = HistData365()
                candle_data.symbol = symbol
                candle_data.date = timestamp.date()
                candle_data.datetime_stamp = timestamp
                candle_data.open = float(candle[1])
                candle_data.high = float(candle[2])
                candle_data.low = float(candle[3])
                candle_data.close = float(candle[4])
                candle_data.volume = int(candle[5])
                candle_data.timeframe = '1D'
                candle_data.source = 'fyers_hist_auth'
                candle_data.day_of_week = timestamp.strftime('%A')  # Monday, Tuesday, etc.
                
                # Check if this record already exists
                existing = HistData365.query.filter_by(
                    symbol=symbol,
                    date=timestamp.date(),
                    timeframe='1D'
                ).first()
                
                if not existing:
                    db.session.add(candle_data)
                    records_saved += 1
            
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Downloaded {records_saved} records for {symbol} ({days} days)',
                'records_saved': records_saved,
                'total_candles': len(candles),
                'days_requested': days
            })
        else:
            error_msg = response.get('message', 'Failed to fetch historical data') if isinstance(response, dict) else 'Invalid API response'
            # Log full response for debugging
            logger.error(f"Fyers API error for symbol {symbol}: {error_msg}")
            logger.error(f"Full API response: {response}")
            return jsonify({
                'status': 'error',
                'message': f'API Error: {error_msg}'
            }), 400
            
    except Exception as e:
        symbol_name = symbol if symbol else 'unknown symbol'
        days_str = str(days) if 'days' in locals() else '365'
        logger.error(f"Error downloading {days_str} days data for {symbol_name}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/api/hist_data_365/clear', methods=['POST'])
def clear_hist_data_365():
    """Clear all 365 days historical data"""
    try:
        # Delete all records from HistData365 table
        deleted_count = HistData365.query.delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Cleared {deleted_count} historical records',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error clearing 365 data: {str(e)}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500


# Minute Resolution Historical Data Download Endpoints
# Resolution mapping: resolution code -> (Model class, table name, display name)
MINUTE_RESOLUTIONS = {
    '1': (HistData1Min, 'hist_data_1min', '1-Minute'),
    '2': (HistData2Min, 'hist_data_2min', '2-Minute'),
    '3': (HistData3Min, 'hist_data_3min', '3-Minute'),
    '5': (HistData5Min, 'hist_data_5min', '5-Minute'),
    '10': (HistData10Min, 'hist_data_10min', '10-Minute'),
    '15': (HistData15Min, 'hist_data_15min', '15-Minute'),
    '20': (HistData20Min, 'hist_data_20min', '20-Minute'),
    '30': (HistData30Min, 'hist_data_30min', '30-Minute'),
    '45': (HistData45Min, 'hist_data_45min', '45-Minute'),
    '60': (HistData60Min, 'hist_data_60min', '60-Minute'),
    '120': (HistData120Min, 'hist_data_120min', '120-Minute'),
    '180': (HistData180Min, 'hist_data_180min', '180-Minute'),
    '240': (HistData240Min, 'hist_data_240min', '240-Minute'),
}

@app.route('/api/minute_hist_data/download', methods=['POST'])
@login_required
def download_minute_hist_data():
    """Universal endpoint for downloading minute resolution historical data"""
    symbol = None
    try:
        data = request.get_json() or {}
        symbol = data.get('symbol', '').strip()
        resolution = data.get('resolution', '').strip()
        from_date_str = data.get('from_date', '')
        to_date_str = data.get('to_date', '')
        
        if not symbol:
            return jsonify({'status': 'error', 'message': 'Symbol is required'}), 400
        
        if resolution not in MINUTE_RESOLUTIONS:
            return jsonify({'status': 'error', 'message': f'Invalid resolution. Must be one of: {", ".join(MINUTE_RESOLUTIONS.keys())}'}), 400
        
        # Parse dates
        from datetime import datetime, timedelta
        if from_date_str and to_date_str:
            try:
                start_date = datetime.strptime(from_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(to_date_str, '%Y-%m-%d')
                
                # Normalize weekend dates to weekdays
                # End date: walk back to Friday
                while end_date.weekday() >= 5:  # Saturday (5) or Sunday (6)
                    end_date = end_date - timedelta(days=1)
                
                # Start date: walk forward to Monday, but if that would pass end_date, walk back to Friday instead
                if start_date.weekday() >= 5:  # Saturday or Sunday
                    # Calculate days to Monday: Saturday needs +2, Sunday needs +1
                    days_to_monday = 2 if start_date.weekday() == 5 else 1
                    temp_start = start_date + timedelta(days=days_to_monday)
                    
                    if temp_start > end_date:
                        # Moving forward would pass end_date, so walk back to prior Friday
                        days_to_friday = start_date.weekday() - 4
                        start_date = start_date - timedelta(days=days_to_friday)
                    else:
                        start_date = temp_start
                    
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
        else:
            # Fallback to days parameter for backward compatibility
            days = data.get('days', 30)
            
            # Validate days parameter
            if not isinstance(days, int) or days < 1 or days > 365:
                return jsonify({'status': 'error', 'message': 'Days must be between 1 and 365'}), 400
            
            end_date = datetime.now()
            while end_date.weekday() >= 5:
                end_date = end_date - timedelta(days=1)
            start_date = end_date - timedelta(days=days)
        
        # Validate date range
        if start_date > end_date:
            return jsonify({'status': 'error', 'message': 'From date must be before To date'}), 400
        
        hist_access_token = get_hist_access_token()
        if not hist_access_token:
            return jsonify({'status': 'error', 'message': 'Historical data authentication required'}), 401
        
        fyers = fyersModel.FyersModel(client_id=Config.FYERS_HIST_DATA_APP_ID, token=hist_access_token)
        
        # Convert symbol to full format
        if ':' in symbol:
            if 'SENSEX' in symbol.upper() or 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                full_symbol = f"{symbol}-INDEX" if not symbol.endswith('-INDEX') else symbol
            else:
                full_symbol = f"{symbol}-EQ" if not symbol.endswith('-EQ') else symbol
        else:
            if 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                full_symbol = f"NSE:{symbol}-INDEX"
            elif 'SENSEX' in symbol.upper():
                full_symbol = f"BSE:{symbol}-INDEX"
            else:
                full_symbol = f"NSE:{symbol}-EQ"
        
        hist_data_request = {
            "symbol": full_symbol,
            "resolution": resolution,
            "date_format": "1",
            "range_from": start_date.strftime("%Y-%m-%d"),
            "range_to": end_date.strftime("%Y-%m-%d"),
            "cont_flag": "1"
        }
        
        logger.info(f"🔍 Minute data request for {symbol}: resolution={resolution}, range={start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        response = fyers.history(hist_data_request)
        
        if isinstance(response, dict) and response.get('s') == 'ok' and response.get('candles'):
            candles = response.get('candles', [])
            records_saved = 0
            
            ModelClass = MINUTE_RESOLUTIONS[resolution][0]
            
            for candle in candles:
                timestamp = datetime.fromtimestamp(candle[0])
                
                existing = ModelClass.query.filter_by(
                    symbol=symbol,
                    datetime_stamp=timestamp
                ).first()
                
                if not existing:
                    candle_data = ModelClass()
                    candle_data.symbol = symbol
                    candle_data.datetime_stamp = timestamp
                    candle_data.open = float(candle[1])
                    candle_data.high = float(candle[2])
                    candle_data.low = float(candle[3])
                    candle_data.close = float(candle[4])
                    candle_data.volume = int(candle[5])
                    candle_data.source = 'fyers_hist_auth'
                    db.session.add(candle_data)
                    records_saved += 1
            
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Downloaded {records_saved} {MINUTE_RESOLUTIONS[resolution][2]} candles for {symbol}',
                'records_saved': records_saved,
                'total_candles': len(candles),
                'resolution': resolution
            })
        else:
            error_msg = response.get('message', 'Failed to fetch data') if isinstance(response, dict) else 'Invalid response'
            logger.error(f"API error for {symbol} ({resolution}min): {error_msg}")
            return jsonify({'status': 'error', 'message': f'API Error: {error_msg}'}), 400
            
    except Exception as e:
        logger.error(f"Error downloading minute data: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/minute_hist_data/clear', methods=['POST'])
@login_required
def clear_minute_hist_data():
    """Universal endpoint for clearing minute resolution historical data"""
    try:
        data = request.get_json() or {}
        resolution = data.get('resolution', '').strip()
        
        if resolution not in MINUTE_RESOLUTIONS:
            return jsonify({'status': 'error', 'message': f'Invalid resolution'}), 400
        
        ModelClass = MINUTE_RESOLUTIONS[resolution][0]
        deleted_count = ModelClass.query.delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Cleared {deleted_count} {MINUTE_RESOLUTIONS[resolution][2]} records',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error clearing minute data: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Server error: {str(e)}'}), 500

@app.route('/admin/toggle-user/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot modify your own account'}), 400
    
    user.account_active = not user.account_active
    db.session.commit()
    
    return jsonify({
        'status': 'success', 
        'message': f'User {user.username} {"activated" if user.account_active else "deactivated"}'
    })

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Permanently delete a user"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot delete your own account'}), 400
    
    try:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} deleted user: {username} (ID: {user_id})")
        
        return jsonify({
            'status': 'success',
            'message': f'User {username} has been permanently deleted'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to delete user: {str(e)}'}), 500

@app.route('/admin/get-user/<int:user_id>', methods=['GET'])
@login_required
def get_user_data(user_id):
    """Get user data for editing"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    return jsonify({
        'status': 'success',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'mobile': user.mobile,
            'role': user.role,
            'subscription_period': user.subscription_period,
            'subscription_start': user.subscription_start.isoformat() if user.subscription_start else '',
            'subscription_end': user.subscription_end.isoformat() if user.subscription_end else '',
            'is_active': user.is_active
        }
    })

@app.route('/admin/edit-user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    """Edit user details"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    
    try:
        # Get form data
        email = request.form.get('email', '').strip()
        mobile = request.form.get('mobile', '').strip()
        subscription_period = request.form.get('subscription_period', 'monthly')
        subscription_start = request.form.get('subscription_start', '').strip()
        subscription_end = request.form.get('subscription_end', '').strip()
        role = request.form.get('role', user.role)
        
        # Validate email uniqueness (if provided and different from current)
        if email and email != user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return jsonify({'status': 'error', 'message': 'Email already exists'}), 400
        
        # Update user data
        user.email = email if email else None
        user.mobile = mobile if mobile else None
        user.subscription_period = subscription_period
        user.role = role
        
        # Parse and set subscription dates
        from datetime import datetime as dt
        if subscription_start:
            user.subscription_start = dt.strptime(subscription_start, '%Y-%m-%d').date()
        else:
            user.subscription_start = None
            
        if subscription_end:
            user.subscription_end = dt.strptime(subscription_end, '%Y-%m-%d').date()
        else:
            user.subscription_end = None
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'User {user.username} updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/create-user', methods=['POST'])
@login_required
def create_user():
    """Create a new user or admin"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    try:
        # Get form data
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        mobile = request.form.get('mobile', '').strip()
        role = request.form.get('role', 'user')
        subscription_period = request.form.get('subscription_period', 'monthly')
        subscription_start = request.form.get('subscription_start', '').strip()
        subscription_end = request.form.get('subscription_end', '').strip()
        
        # Validate required fields
        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
        
        # Check if email already exists (if provided)
        if email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                return jsonify({'status': 'error', 'message': 'Email already exists'}), 400
        
        # Create new user
        new_user = User()
        new_user.username = username
        new_user.role = role
        new_user.email = email if email else None
        new_user.mobile = mobile if mobile else None
        new_user.subscription_period = subscription_period
        new_user.set_password(password)
        
        # Parse and set subscription dates
        from datetime import datetime as dt
        if subscription_start:
            new_user.subscription_start = dt.strptime(subscription_start, '%Y-%m-%d').date()
        if subscription_end:
            new_user.subscription_end = dt.strptime(subscription_end, '%Y-%m-%d').date()
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'{role.title()} "{username}" created successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/transfer-data', methods=['POST'])
@login_required
def transfer_current_day_data():
    """Transfer current day OHLC data from daily_ohlc_data to historical_data (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    try:
        from datetime import date, datetime
        from sqlalchemy import text
        
        today = date.today()
        
        # Get current day OHLC data from daily_ohlc_data table
        query = text("""
            SELECT symbol, full_symbol, trading_date, open_price, high_price, 
                   low_price, close_price, volume
            FROM daily_ohlc_data 
            WHERE trading_date = :trading_date
        """)
        
        current_day_data = db.session.execute(query, {'trading_date': today}).fetchall()
        
        if not current_day_data:
            return jsonify({
                'status': 'error', 
                'message': f'No OHLC data found for {today}'
            }), 404
        
        transferred_count = 0
        
        # Transfer each record to historical_data
        for record in current_day_data:
            try:
                # Convert trading_date to datetime for candle_time (use market close time 15:30 IST)
                candle_time = datetime.combine(record.trading_date, datetime.min.time().replace(hour=15, minute=30))
                
                # Use PostgreSQL UPSERT to avoid conflicts in historical_data
                insert_query = text("""
                    INSERT INTO historical_data 
                    (symbol, full_symbol, resolution, open_price, high_price, low_price, close_price, volume, candle_time)
                    VALUES (:symbol, :full_symbol, :resolution, :open_price, :high_price, :low_price, :close_price, :volume, :candle_time)
                    ON CONFLICT (symbol, resolution, candle_time) 
                    DO UPDATE SET 
                        full_symbol = EXCLUDED.full_symbol,
                        open_price = EXCLUDED.open_price,
                        high_price = EXCLUDED.high_price,
                        low_price = EXCLUDED.low_price,
                        close_price = EXCLUDED.close_price,
                        volume = EXCLUDED.volume
                """)
                
                db.session.execute(insert_query, {
                    'symbol': record.symbol,
                    'full_symbol': record.full_symbol,
                    'resolution': '1D',  # Daily resolution
                    'open_price': float(record.open_price),
                    'high_price': float(record.high_price),
                    'low_price': float(record.low_price),
                    'close_price': float(record.close_price),
                    'volume': int(record.volume) if record.volume else 0,
                    'candle_time': candle_time
                })
                
                transferred_count += 1
                
            except Exception as e:
                logger.error(f"Error transferring data for {record.symbol}: {str(e)}")
                continue
        
        # Commit all transfers
        db.session.commit()
        
        logger.info(f"Successfully transferred {transferred_count} records from daily_ohlc_data to historical_data for {today}")
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully transferred current day OHLC data to historical backup',
            'records_transferred': transferred_count,
            'transfer_date': today.strftime('%Y-%m-%d'),
            'total_records_found': len(current_day_data)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error transferring current day data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/transfer-weekly-data', methods=['POST'])
@login_required
def transfer_weekly_data():
    """Transfer daily OHLC data to weekly data"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    try:
        # Initialize OHLC storage
        from ohlc_storage import OHLCStorage
        ohlc_storage = OHLCStorage(db.session)
        
        # Perform the weekly data aggregation
        records_created = ohlc_storage.create_weekly_data_from_daily()
        
        logger.info(f"Admin {current_user.username} triggered weekly data transfer: {records_created} records created")
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully created {records_created} weekly records',
            'records_created': records_created
        })
        
    except Exception as e:
        logger.error(f"Error transferring weekly data: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error transferring data: {str(e)}'
        }), 500

@app.route('/admin/initialize-stock-symbols', methods=['POST'])
@login_required
def initialize_stock_symbols():
    """Initialize stock_data table with all NIFTY50_SYMBOLS"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    try:
        symbols_created = 0
        symbols_updated = 0
        
        # Get all symbols from config
        all_symbols = Config.NIFTY50_SYMBOLS
        
        for full_symbol in all_symbols:
            # Extract clean symbol name
            clean_symbol = full_symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            # Check if symbol already exists
            existing = StockData.query.filter_by(symbol=clean_symbol).first()
            
            if not existing:
                # Create new stock data entry with default values
                stock_data = StockData()
                stock_data.symbol = clean_symbol
                stock_data.full_symbol = full_symbol
                stock_data.ltp = 0.0
                stock_data.change = 0.0
                stock_data.change_percent = 0.0
                stock_data.volume = 0
                
                db.session.add(stock_data)
                symbols_created += 1
            else:
                # Update existing symbol with correct full_symbol if needed
                if existing.full_symbol != full_symbol:
                    existing.full_symbol = full_symbol
                    symbols_updated += 1
        
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} initialized stock symbols: {symbols_created} created, {symbols_updated} updated")
        
        return jsonify({
            'status': 'success',
            'message': f'Stock symbols initialized: {symbols_created} created, {symbols_updated} updated',
            'symbols_created': symbols_created,
            'symbols_updated': symbols_updated,
            'total_symbols': len(all_symbols)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error initializing stock symbols: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error initializing symbols: {str(e)}'
        }), 500

@app.route('/admin/data-summary', methods=['GET'])
@login_required
def get_data_summary():
    """Get summary statistics for daily and weekly OHLC data"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    try:
        from ohlc_storage import OHLCStorage
        from sqlalchemy import text
        
        # Get daily records count
        daily_count = db.session.execute(text("SELECT COUNT(*) as count FROM daily_ohlc_data")).fetchone()
        daily_records = daily_count.count if daily_count else 0
        
        # Get weekly records count
        weekly_count = db.session.execute(text("SELECT COUNT(*) as count FROM weekly_ohlc_data")).fetchone()
        weekly_records = weekly_count.count if weekly_count else 0
        
        # Get additional weekly data summary
        ohlc_storage = OHLCStorage(db.session)
        weekly_summary = ohlc_storage.get_weekly_data_summary()
        
        return jsonify({
            'status': 'success',
            'daily_records': daily_records,
            'weekly_records': weekly_records,
            'weekly_summary': weekly_summary
        })
        
    except Exception as e:
        logger.error(f"Error fetching data summary: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error fetching data summary: {str(e)}'
        }), 500

@app.route('/api/rvol-data')
@login_required
def get_rvol_data():
    """Calculate and return 5-day RVOL data for all symbols"""
    try:
        from datetime import date, timedelta
        from sqlalchemy import text, func
        
        # Get last 5 trading days
        end_date = date.today()
        start_date = end_date - timedelta(days=10)  # Get more days to ensure we have 5 trading days
        
        # Query last 5 days of volume data from hist_data_365
        query = text("""
            WITH last_5_days AS (
                SELECT symbol, COALESCE(volume, 0) as volume, date as trading_date,
                       ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365 
                WHERE timeframe = '1D' 
                  AND date >= :start_date 
                  AND date <= :end_date
                  AND COALESCE(volume, 0) > 0
            )
            SELECT symbol,
                   AVG(volume) as avg_5day_volume,
                   COUNT(*) as days_count
            FROM last_5_days 
            WHERE rn <= 5  -- Only last 5 trading days
            GROUP BY symbol
            HAVING COUNT(*) >= 2  -- At least 2 days of data for meaningful average
        """)
        
        historical_volumes = db.session.execute(query, {
            'start_date': start_date,
            'end_date': end_date
        }).fetchall()
        
        if not historical_volumes:
            return jsonify({
                'status': 'error',
                'message': 'No historical volume data available for RVOL calculation'
            })
        
        # Get current live volume data from WebSocket
        global websocket_manager
        rvol_data = []
        
        for record in historical_volumes:
            symbol = record.symbol
            avg_5day_volume = float(record.avg_5day_volume)
            days_count = record.days_count
            
            # Get current volume from WebSocket data
            current_volume = 0
            full_symbol = f"NSE:{symbol}-EQ"
            
            if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                if full_symbol in websocket_manager.stock_data:
                    current_volume = websocket_manager.stock_data[full_symbol].get('volume', 0)
                elif symbol in websocket_manager.stock_data:
                    current_volume = websocket_manager.stock_data[symbol].get('volume', 0)
            
            # Calculate RVOL ratio (include all stocks even if current volume is 0)
            if avg_5day_volume > 0:
                if current_volume > 0:
                    rvol_ratio = current_volume / avg_5day_volume
                else:
                    rvol_ratio = 0.0  # Show 0 RVOL for stocks not trading yet
                
                # Determine color based on thresholds
                if rvol_ratio >= 2.0:
                    color = '#dc3545'  # Red - Extremely high volume
                    status = 'Extremely High'
                elif rvol_ratio >= 1.5:
                    color = '#ffc107'  # Yellow - High volume
                    status = 'High'
                elif rvol_ratio >= 0.7:
                    color = '#28a745'  # Green - Normal volume
                    status = 'Normal'
                else:
                    color = '#6c757d'  # Gray - Low/No volume
                    status = 'Low' if current_volume > 0 else 'Not Trading'
                
                rvol_data.append({
                    'symbol': symbol,
                    'current_volume': current_volume,
                    'avg_5day_volume': int(avg_5day_volume),
                    'rvol_ratio': round(rvol_ratio, 2),
                    'color': color,
                    'status': status,
                    'days_count': days_count
                })
        
        # Sort by RVOL ratio descending (highest volume activity first)
        rvol_data.sort(key=lambda x: x['rvol_ratio'], reverse=True)
        
        logger.info(f"Calculated RVOL data for {len(rvol_data)} symbols")
        
        return jsonify({
            'status': 'success',
            'data': rvol_data,
            'total_symbols': len(rvol_data),
            'calculation_date': end_date.strftime('%Y-%m-%d')
        })
        
    except Exception as e:
        logger.error(f"Error calculating RVOL data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/heatmap-data')
@login_required
def get_heatmap_data():
    """Get data for MGHeatmap page - F&O stocks only (excluding indices)"""
    try:
        from datetime import date, timedelta
        from sqlalchemy import text
        
        global websocket_manager
        
        if not websocket_manager or not websocket_manager.is_connected:
            return jsonify({
                'status': 'disconnected',
                'message': 'WebSocket not connected',
                'data': []
            })
        
        latest_data = websocket_manager.get_latest_data()
        
        end_date = date.today()
        start_date = end_date - timedelta(days=10)
        
        query = text("""
            WITH last_5_days AS (
                SELECT symbol, COALESCE(volume, 0) as volume,
                       ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365 
                WHERE timeframe = '1D' 
                  AND date >= :start_date 
                  AND date <= :end_date
                  AND COALESCE(volume, 0) > 0
            )
            SELECT symbol, AVG(volume) as avg_5day_volume
            FROM last_5_days 
            WHERE rn <= 5
            GROUP BY symbol
            HAVING COUNT(*) >= 2
        """)
        
        historical_volumes = db.session.execute(query, {
            'start_date': start_date,
            'end_date': end_date
        }).fetchall()
        
        volume_map = {record.symbol: float(record.avg_5day_volume) for record in historical_volumes}
        
        heatmap_data = []
        
        for full_symbol in Config.FNO_STOCKS:
            if full_symbol in latest_data:
                stock = latest_data[full_symbol]
                symbol = stock.get('symbol', '')
                ltp = stock.get('ltp', 0)
                open_price = stock.get('open_price', 0)
                high_price = stock.get('high_price', 0)
                low_price = stock.get('low_price', 0)
                volume = stock.get('volume', 0)
                change = stock.get('change', 0)
                change_percent = stock.get('change_percent', 0)
                
                pct_from_open = ((ltp - open_price) / open_price * 100) if open_price > 0 else 0
                pct_from_high = ((ltp - high_price) / high_price * 100) if high_price > 0 else 0
                pct_from_low = ((ltp - low_price) / low_price * 100) if low_price > 0 else 0
                
                avg_volume = volume_map.get(symbol, 0)
                rvol_ratio = (volume / avg_volume) if avg_volume > 0 else 0
                
                o_equals_h = abs(open_price - high_price) < (open_price * 0.001) if open_price > 0 else False
                o_equals_l = abs(open_price - low_price) < (open_price * 0.001) if open_price > 0 else False
                
                heatmap_data.append({
                    'symbol': symbol,
                    'ltp': round(ltp, 2),
                    'change': round(change, 2),
                    'change_percent': round(change_percent, 2),
                    'pct_from_open': round(pct_from_open, 2),
                    'pct_from_high': round(pct_from_high, 2),
                    'pct_from_low': round(pct_from_low, 2),
                    'rvol': round(rvol_ratio, 2),
                    'o_equals_h': o_equals_h,
                    'o_equals_l': o_equals_l,
                    'volume': volume
                })
        
        return jsonify({
            'status': 'success',
            'data': heatmap_data,
            'total_symbols': len(heatmap_data)
        })
        
    except Exception as e:
        logger.error(f"Error fetching heatmap data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/mgheatmap')
@login_required
def mgheatmap():
    """MGHeatmap page - Card-based heatmap view of F&O stocks"""
    # Check subscription status
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access the heatmap.', 'warning')
        return redirect(url_for('account'))
    
    return render_template('mgheatmap.html')

@app.route('/mg-linecharts')
@login_required
def mg_linecharts():
    """MG Line Charts page - 5-day line charts for F&O stocks"""
    # Check subscription status
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access the line charts.', 'warning')
        return redirect(url_for('account'))
    
    return render_template('mg_linecharts.html')

@app.route('/volume-profile')
@login_required
def volume_profile():
    """Volume Profile page - 5-Day Volume Analysis for all F&O stocks"""
    # Check subscription status
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access volume profile.', 'warning')
        return redirect(url_for('account'))
    
    return render_template('volume_profile.html')

@app.route('/technical-indicators')
@login_required
def technical_indicators_page():
    """Technical Indicators page - RSI, MACD, Stochastic, ADX analysis"""
    # Check subscription status - only allow access if user has active subscription
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access technical indicators.', 'warning')
        return redirect(url_for('account'))
    
    return render_template('technical_indicators.html')

@app.route('/api/technical-indicators-data')
@login_required
def get_technical_indicators():
    """Calculate and return technical indicators for all stocks with caching"""
    # All subscribed users can access technical indicators
    if not current_user.is_subscription_active():
        return jsonify({'status': 'error', 'message': 'Active subscription required.'}), 403
    
    try:
        from datetime import date, timedelta
        from sqlalchemy import text
        
        global websocket_manager, technical_indicators_cache
        
        current_time = time.time()
        cache_age = current_time - technical_indicators_cache['timestamp'] if technical_indicators_cache['timestamp'] else float('inf')
        
        # If cache is fresh (< 60 seconds), use cached calculations and only update live prices
        if technical_indicators_cache['data'] and cache_age < technical_indicators_cache['ttl_seconds']:
            # Get live WebSocket data
            latest_data = websocket_manager.get_latest_data() if websocket_manager and websocket_manager.is_connected else {}
            
            # Update cached data with live prices
            updated_data = []
            for stock in technical_indicators_cache['data']:
                # Find matching WebSocket data
                db_symbol = stock['symbol']
                live_stock_data = None
                for key in latest_data:
                    clean_ws_symbol = key.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                    if clean_ws_symbol == db_symbol:
                        live_stock_data = latest_data[key]
                        break
                
                # Update live fields only
                if live_stock_data:
                    # Use WebSocket data directly - dashboard %change is always correct
                    stock['ltp'] = round(live_stock_data.get('ltp', stock['ltp']), 2)
                    # Update change_percent only if WebSocket has it (0 is valid!)
                    if 'change_percent' in live_stock_data:
                        stock['change_percent'] = round(live_stock_data['change_percent'], 2)
                    
                    # Update RVOL with live volume if available
                    current_volume = live_stock_data.get('volume', 0)
                    if current_volume > 0 and stock.get('rvol') and stock['rvol'] != '-':
                        # RVOL already calculated from historical, just update if needed
                        pass
                
                updated_data.append(stock)
            
            # Return cached data with updated live prices
            overbought = [d for d in updated_data if d['rsi'] and d['rsi'] > 70]
            slight_bullish = [d for d in updated_data if d['rsi'] and 60 <= d['rsi'] <= 70]
            neutral = [d for d in updated_data if (d['rsi'] and 40 < d['rsi'] < 60) or (d['rsi'] is None)]
            slight_bearish = [d for d in updated_data if d['rsi'] and 30 <= d['rsi'] <= 40]
            oversold = [d for d in updated_data if d['rsi'] and d['rsi'] < 30]
            
            response = jsonify({
                'status': 'success',
                'all_data': updated_data,
                'overbought': overbought,
                'slight_bullish': slight_bullish,
                'neutral': neutral,
                'slight_bearish': slight_bearish,
                'oversold': oversold,
                'total_count': len(updated_data),
                'cached': True,
                'cache_age': round(cache_age, 1)
            })
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        
        # Cache expired or missing - recalculate everything
        logger.info("Technical Indicators: Cache expired, recalculating...")
        
        # Get all F&O symbols using the chart symbols function instead
        # This returns simple symbol names that match the database
        symbols_list = get_fo_symbols_for_chart()
        
        logger.info(f"Technical Indicators: Processing {len(symbols_list)} symbols")
        
        # Get the latest available date from CPR levels (not today)
        latest_cpr = db.session.query(CprLevel.date).order_by(CprLevel.date.desc()).first()
        latest_level_date = latest_cpr.date if latest_cpr else date.today()
        
        # Fetch RVOL data using the same method as dashboard (from /api/rvol-data)
        end_date = date.today()
        start_date = end_date - timedelta(days=10)
        
        rvol_query = text("""
            WITH last_5_days AS (
                SELECT symbol, COALESCE(volume, 0) as volume, date as trading_date,
                       ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365 
                WHERE timeframe = '1D' 
                  AND date >= :start_date 
                  AND date <= :end_date
                  AND COALESCE(volume, 0) > 0
            )
            SELECT symbol,
                   AVG(volume) as avg_5day_volume,
                   MAX(volume) as latest_volume,
                   COUNT(*) as days_count
            FROM last_5_days 
            WHERE rn <= 5
            GROUP BY symbol
            HAVING COUNT(*) >= 2
        """)
        
        rvol_data = db.session.execute(rvol_query, {
            'start_date': start_date,
            'end_date': end_date
        }).fetchall()
        rvol_map = {r.symbol: {'avg': float(r.avg_5day_volume), 'current': float(r.latest_volume)} for r in rvol_data}
        
        # Fetch CPR levels for the latest available date
        cpr_levels = CprLevel.query.filter_by(date=latest_level_date).all()
        cpr_map = {c.symbol: c for c in cpr_levels}
        
        # Fetch Camarilla levels for the latest available date
        camarilla_levels = CamarillaLevels.query.filter_by(date=latest_level_date).all()
        camarilla_map = {c.symbol: c for c in camarilla_levels}
        
        # Fetch Fibonacci levels for the latest available date
        fibonacci_levels = FibonacciLevel.query.filter_by(date=latest_level_date).all()
        fibonacci_map = {f.symbol: f for f in fibonacci_levels}
        
        # Get WebSocket data for current volume and LTP
        latest_data = websocket_manager.get_latest_data() if websocket_manager and websocket_manager.is_connected else {}
        
        # Fetch initial change_percent from hist_data_365 (same as dashboard /api/initial-data)
        from sqlalchemy import func
        subquery = db.session.query(
            HistData365.symbol,
            func.max(HistData365.date).label('max_date')
        ).filter(
            and_(
                HistData365.timeframe == '1D',
                HistData365.date >= start_date,
                HistData365.date <= end_date
            )
        ).group_by(HistData365.symbol).subquery()
        
        recent_hist_data = db.session.query(HistData365).join(
            subquery,
            and_(
                HistData365.symbol == subquery.c.symbol,
                HistData365.date == subquery.c.max_date,
                HistData365.timeframe == '1D'
            )
        ).all()
        
        # Create map of symbol -> change_percent from hist_data_365
        hist_change_map = {}
        for record in recent_hist_data:
            if record.open and record.close and record.open > 0:
                change = record.close - record.open
                change_percent = (change / record.open * 100)
                hist_change_map[record.symbol] = round(change_percent, 2)
        
        indicators_data = []
        
        for db_symbol in symbols_list:
            display_name = db_symbol  # Use the same symbol for display
            
            # Get ALL available historical data for this stock (no date restriction)
            # This ensures we use all the data we have, not just last 30 calendar days
            historical_data = HistData365.query.filter(
                HistData365.symbol == db_symbol,
                HistData365.close.isnot(None),
                HistData365.close > 0
            ).order_by(HistData365.date.asc()).all()
            
            # Check if we have enough data for technical indicators (minimum 25 trading days needed for MACD)
            has_enough_data = len(historical_data) >= 25
            
            # Extract price arrays
            closes = [d.close for d in historical_data] if historical_data else []
            highs = [d.high for d in historical_data] if historical_data else []
            lows = [d.low for d in historical_data] if historical_data else []
            
            # Get current price (LTP) from live WebSocket data FIRST
            # WebSocket stores data with full symbol format (NSE:SYMBOL-EQ), match to clean symbol
            live_stock_data = None
            for key in latest_data:
                # Extract clean symbol from WebSocket key (NSE:SYMBOL-EQ -> SYMBOL)
                clean_ws_symbol = key.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                if clean_ws_symbol == db_symbol:
                    live_stock_data = latest_data[key]
                    break
            
            # Fallback: if no match found, use empty dict
            if not live_stock_data:
                live_stock_data = {}
            
            # Include today's current live price in technical indicator calculations (only if we have enough data)
            if has_enough_data and live_stock_data and live_stock_data.get('ltp'):
                current_ltp = live_stock_data.get('ltp')
                current_high = live_stock_data.get('high', current_ltp)
                current_low = live_stock_data.get('low', current_ltp)
                
                # Append today's current prices to arrays for RSI/MACD/Stochastic/ADX calculation
                closes.append(current_ltp)
                highs.append(current_high)
                lows.append(current_low)
            
            # Calculate indicators WITH today's current price included (only if we have enough data)
            if has_enough_data:
                rsi = TechnicalIndicators.calculate_rsi(closes, 14)
                macd_data = TechnicalIndicators.calculate_macd(closes, 12, 26, 9)
                stoch_data = TechnicalIndicators.calculate_stochastic(highs, lows, closes, 14, 3)
                adx_data = TechnicalIndicators.calculate_adx(highs, lows, closes, 14)
            else:
                # Set default N/A values when insufficient data
                rsi = None
                macd_data = {'macd': None, 'signal': None, 'histogram': None}
                stoch_data = {'k': None, 'd': None}
                adx_data = {'adx': None, 'di_plus': None, 'di_minus': None}
            
            # Get change_percent from WebSocket (same as dashboard)
            if live_stock_data and live_stock_data.get('ltp'):
                current_price = live_stock_data.get('ltp', closes[-1] if closes else 0)
                # Use WebSocket change_percent if present in data (0 is a valid value!)
                if 'change_percent' in live_stock_data:
                    change_percent = live_stock_data['change_percent']
                else:
                    # Fallback to hist_data_365 only if WebSocket doesn't have change_percent key
                    change_percent = hist_change_map.get(db_symbol, 0)
            else:
                # No WebSocket data - use historical data
                current_price = closes[-1] if closes else 0
                change_percent = hist_change_map.get(db_symbol, 0)
            
            # Get individual statuses (only if we have enough data)
            if has_enough_data:
                rsi_status = TechnicalIndicators.get_rsi_status(rsi)
                macd_status = TechnicalIndicators.get_macd_status(macd_data['macd'], macd_data['signal'])
                stoch_status = TechnicalIndicators.get_stochastic_status(stoch_data['k'])
                adx_status = TechnicalIndicators.get_adx_status(adx_data['adx'], adx_data['di_plus'], adx_data['di_minus'])
            else:
                rsi_status = 'N/A'
                macd_status = 'N/A'
                stoch_status = 'N/A'
                adx_status = 'N/A'
            
            # Calculate overall rank status based on all indicators (only if we have enough data)
            # Core indicators score (primary weight)
            score = 0
            
            # Only calculate score if we have enough data
            if has_enough_data:
                # RSI scoring: Overbought = +1 (strong momentum), Slight Bullish = +0.5, Neutral = 0, Slight Bearish = -0.5, Oversold = -1 (weak momentum)
                if rsi_status == 'Overbought':
                    score += 1
                elif rsi_status == 'Neutral to Slight Bullish':
                    score += 0.5
                elif rsi_status == 'Neutral to Slightly Bearish':
                    score -= 0.5
                elif rsi_status == 'Oversold':
                    score -= 1
                
                # MACD scoring: Bullish = +1, Bearish = -1
                if macd_status == 'Bullish':
                    score += 1
                elif macd_status == 'Bearish':
                    score -= 1
                
                # Stochastic scoring: Overbought = +1 (strong momentum), Oversold = -1 (weak momentum), Neutral = 0
                if stoch_status == 'Overbought':
                    score += 1
                elif stoch_status == 'Oversold':
                    score -= 1
                
                # ADX scoring: Strong Bullish = +1, Weak Bullish = +0.5, Strong Bearish = -1, Weak Bearish = -0.5
                if 'Strong Bullish' in adx_status:
                    score += 1
                elif 'Weak Bullish' in adx_status:
                    score += 0.5
                elif 'Strong Bearish' in adx_status:
                    score -= 1
                elif 'Weak Bearish' in adx_status:
                    score -= 0.5
            
            # % Change scoring: +0.5 point for every +1% increase, -0.5 point for every -1% decrease
            # Round to nearest 0.5 increment
            if change_percent != 0:
                change_score = round(change_percent * 0.5 * 2) / 2  # Round to nearest 0.5
                score += change_score  # +3% = +1.5 points, +3.8% = +2.0 points
            
            # RVOL scoring: +0.5 point per 1x volume if % change is positive, -0.5 point per 1x volume if % change is negative
            # Round to nearest 0.5 increment
            rvol_ratio = 0
            if db_symbol in rvol_map:
                rvol_info = rvol_map[db_symbol]
                avg_volume = rvol_info.get('avg', 0)
                
                # Use live volume from WebSocket if available
                if live_stock_data and live_stock_data.get('volume'):
                    current_volume = live_stock_data.get('volume', 0)
                else:
                    current_volume = rvol_info.get('current', 0)
                
                if avg_volume > 0:
                    rvol_ratio = current_volume / avg_volume
                    rvol_score = round(rvol_ratio * 0.5 * 2) / 2  # Round to nearest 0.5: 1.7x = +0.5, 2.3x = +1.0
                    
                    if change_percent > 0:
                        # Positive day: high volume is bullish
                        score += rvol_score
                    elif change_percent < 0:
                        # Negative day: high volume is bearish
                        score -= rvol_score
            
            # CPR range scoring: +0.5 for each R level crossed, -0.5 for each S level crossed
            if db_symbol in cpr_map:
                cpr = cpr_map[db_symbol]
                if current_price > cpr.r3:
                    score += 1.5  # Above R3 = 3 R levels crossed
                elif current_price > cpr.r2:
                    score += 1.0  # R2-R3 = 2 R levels crossed
                elif current_price > cpr.r1:
                    score += 0.5  # R1-R2 = 1 R level crossed
                elif current_price < cpr.s3:
                    score -= 1.5  # Below S3 = 3 S levels crossed
                elif current_price < cpr.s2:
                    score -= 1.0  # S2-S3 = 2 S levels crossed
                elif current_price < cpr.s1:
                    score -= 0.5  # S1-S2 = 1 S level crossed
                # TC-R1, TC-BC, BC-S1 zone = 0 (neutral)
            
            # Camarilla range scoring: +0.5 for each R level crossed, -0.5 for each S level crossed
            if db_symbol in camarilla_map:
                cam = camarilla_map[db_symbol]
                if current_price > cam.r5:
                    score += 2.5  # Above R5 = 5 R levels crossed
                elif current_price > cam.r4:
                    score += 2.0  # R4-R5 = 4 R levels crossed
                elif current_price > cam.r3:
                    score += 1.5  # R3-R4 = 3 R levels crossed
                elif current_price > cam.r2:
                    score += 1.0  # R2-R3 = 2 R levels crossed
                elif current_price > cam.r1:
                    score += 0.5  # R1-R2 = 1 R level crossed
                elif current_price < cam.s5:
                    score -= 2.5  # Below S5 = 5 S levels crossed
                elif current_price < cam.s4:
                    score -= 2.0  # S4-S5 = 4 S levels crossed
                elif current_price < cam.s3:
                    score -= 1.5  # S3-S4 = 3 S levels crossed
                elif current_price < cam.s2:
                    score -= 1.0  # S2-S3 = 2 S levels crossed
                elif current_price < cam.s1:
                    score -= 0.5  # S1-S2 = 1 S level crossed
                # Pivot-R1, Pivot-S1 zone = 0 (neutral)
            
            # Fibonacci range scoring: +0.5 for each R level crossed, -0.5 for each S level crossed
            if db_symbol in fibonacci_map:
                fib = fibonacci_map[db_symbol]
                if current_price > fib.r3_161:
                    score += 1.5  # Above R3 = 3 R levels crossed
                elif current_price > fib.r2_123:
                    score += 1.0  # R2-R3 = 2 R levels crossed
                elif current_price > fib.r1_61:
                    score += 0.5  # R1-R2 = 1 R level crossed
                elif current_price < fib.s3_161:
                    score -= 1.5  # Below S3 = 3 S levels crossed
                elif current_price < fib.s2_123:
                    score -= 1.0  # S2-S3 = 2 S levels crossed
                elif current_price < fib.s1_61:
                    score -= 0.5  # S1-S2 = 1 S level crossed
                # PP-R1, PP-S1 zone = 0 (neutral)
            
            # Cap score to -15 to +15 range (increased due to cumulative CPR/Cam/Fib scoring)
            score = max(-15, min(15, score))
            
            # Round score to 1 decimal place for display
            score = round(score, 1)
            
            # Determine overall rank status (7 levels for more granular analysis)
            # Score range: -15 to +15 (all factors combined and capped)
            if has_enough_data:
                if score >= 6:
                    overall_status = 'Very Strong Bullish'
                elif score >= 3:
                    overall_status = 'Strong Bullish'
                elif score >= 1:
                    overall_status = 'Bullish'
                elif score > -1:
                    overall_status = 'Neutral'
                elif score > -3:
                    overall_status = 'Bearish'
                elif score > -6:
                    overall_status = 'Strong Bearish'
                else:
                    overall_status = 'Very Strong Bearish'
            else:
                overall_status = 'N/A'
                score = None  # Set score to None when no data
            
            # Calculate RVOL with 'x' suffix (use live volume from WebSocket ONLY - like dashboard)
            rvol_value = "-"
            if db_symbol in rvol_map and live_stock_data and live_stock_data.get('volume'):
                rvol_info = rvol_map[db_symbol]
                avg_volume = rvol_info.get('avg', 0)
                current_volume = live_stock_data.get('volume', 0)
                
                # Only show RVOL when we have live current day volume (market open)
                if avg_volume > 0 and current_volume > 0:
                    rvol_ratio = round(current_volume / avg_volume, 1)
                    rvol_value = f"{rvol_ratio}x"
            
            # Get CPR range position (like "Above R3", "R1-R2", "TC-BC", etc.)
            cpr_range = "-"
            if db_symbol in cpr_map:
                cpr = cpr_map[db_symbol]
                if current_price > cpr.r3:
                    cpr_range = "Above R3"
                elif current_price > cpr.r2:
                    cpr_range = "R2-R3"
                elif current_price > cpr.r1:
                    cpr_range = "R1-R2"
                elif current_price > cpr.tc:
                    cpr_range = "TC-R1"
                elif current_price > cpr.bc:
                    cpr_range = "TC-BC"
                elif current_price > cpr.s1:
                    cpr_range = "BC-S1"
                elif current_price > cpr.s2:
                    cpr_range = "S1-S2"
                elif current_price > cpr.s3:
                    cpr_range = "S2-S3"
                else:
                    cpr_range = "Below S3"
            
            # Get Camarilla range position
            camarilla_range = "-"
            if db_symbol in camarilla_map:
                cam = camarilla_map[db_symbol]
                if current_price > cam.r5:
                    camarilla_range = "Above R5"
                elif current_price > cam.r4:
                    camarilla_range = "R4-R5"
                elif current_price > cam.r3:
                    camarilla_range = "R3-R4"
                elif current_price > cam.r2:
                    camarilla_range = "R2-R3"
                elif current_price > cam.r1:
                    camarilla_range = "R1-R2"
                elif current_price > cam.pivot:
                    camarilla_range = "P-R1"
                elif current_price > cam.s1:
                    camarilla_range = "S1-P"
                elif current_price > cam.s2:
                    camarilla_range = "S2-S1"
                elif current_price > cam.s3:
                    camarilla_range = "S3-S2"
                elif current_price > cam.s4:
                    camarilla_range = "S4-S3"
                elif current_price > cam.s5:
                    camarilla_range = "S5-S4"
                else:
                    camarilla_range = "Below S5"
            
            # Get Fibonacci range position
            fibonacci_range = "-"
            if db_symbol in fibonacci_map:
                fib = fibonacci_map[db_symbol]
                if current_price > fib.r3_161:
                    fibonacci_range = "Above R3"
                elif current_price > fib.r2_123:
                    fibonacci_range = "R2-R3"
                elif current_price > fib.r1_61:
                    fibonacci_range = "R1-R2"
                elif current_price > fib.pp:
                    fibonacci_range = "PP-R1"
                elif current_price > fib.s1_61:
                    fibonacci_range = "S1-PP"
                elif current_price > fib.s2_123:
                    fibonacci_range = "S2-S1"
                elif current_price > fib.s3_161:
                    fibonacci_range = "S3-S2"
                else:
                    fibonacci_range = "Below S3"
            
            indicators_data.append({
                'symbol': display_name,
                'change_percent': round(change_percent, 2),
                'ltp': round(current_price, 2),
                'rsi': rsi,
                'rsi_status': rsi_status,
                'macd': macd_data['macd'],
                'macd_signal': macd_data['signal'],
                'macd_histogram': macd_data['histogram'],
                'macd_status': macd_status,
                'stoch_k': stoch_data['k'],
                'stoch_d': stoch_data['d'],
                'stoch_status': stoch_status,
                'adx': adx_data['adx'],
                'di_plus': adx_data['di_plus'],
                'di_minus': adx_data['di_minus'],
                'adx_status': adx_status,
                'rank_score': score,
                'rank_status': overall_status,
                'rvol': rvol_value,
                'cpr_range': cpr_range,
                'camarilla_range': camarilla_range,
                'fibonacci_range': fibonacci_range
            })
        
        # Categorize by RSI into 5 categories
        overbought = [d for d in indicators_data if d['rsi'] and d['rsi'] > 70]
        slight_bullish = [d for d in indicators_data if d['rsi'] and 60 <= d['rsi'] <= 70]
        neutral = [d for d in indicators_data if (d['rsi'] and 40 < d['rsi'] < 60) or (d['rsi'] is None)]  # Include N/A stocks
        slight_bearish = [d for d in indicators_data if d['rsi'] and 30 <= d['rsi'] <= 40]
        oversold = [d for d in indicators_data if d['rsi'] and d['rsi'] < 30]
        
        # Cache the calculated indicators for 60 seconds
        technical_indicators_cache['data'] = indicators_data.copy()
        technical_indicators_cache['timestamp'] = time.time()
        logger.info(f"Technical Indicators: Cached {len(indicators_data)} stocks at {technical_indicators_cache['timestamp']}")
        
        response = jsonify({
            'status': 'success',
            'all_data': indicators_data,
            'overbought': overbought,
            'slight_bullish': slight_bullish,
            'neutral': neutral,
            'slight_bearish': slight_bearish,
            'oversold': oversold,
            'total_count': len(indicators_data),
            'cached': False,
            'recalculated': True
        })
        # Prevent browser caching to ensure fresh data
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error calculating technical indicators: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linechart-indices')
@login_required
def get_linechart_indices():
    """Get 5-day historical data for indices for line charts"""
    try:
        from datetime import date, timedelta
        from sqlalchemy import text
        
        global websocket_manager
        
        # Get last 5 trading days data for indices
        end_date = date.today()
        start_date = end_date - timedelta(days=10)
        
        # List of all indices to display (22 indices) - using DB symbols
        index_list = [
            'NIFTY50', 'NIFTYBANK', 'FINNIFTY', 'MIDCPNIFTY', 'BSE:SENSEX',
            'NIFTYIT', 'NIFTYFMCG', 'NIFTYPHARMA', 'NIFTYAUTO', 'NIFTYMETAL',
            'NIFTYREALTY', 'NIFTYPSE', 'NIFTYPVTBANK', 'NIFTYMEDIA', 'NIFTYINFRA',
            'NIFTYENERGY', 'NIFTYCOMMODITIES', 'NIFTYCPSE', 'NIFTYMIDCAP50', 
            'NIFTYSMLCAP100', 'NIFTYNXT50', 'INDIAVIX'
        ]
        
        query = text("""
            WITH ranked_data AS (
                SELECT 
                    symbol,
                    date,
                    datetime_stamp,
                    open,
                    high,
                    low,
                    close,
                    volume,
                    ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365
                WHERE timeframe = '1D'
                  AND date >= :start_date
                  AND date <= :end_date
                  AND symbol = ANY(:index_list)
            )
            SELECT symbol, date, datetime_stamp, open, high, low, close, volume
            FROM ranked_data
            WHERE rn <= 5
            ORDER BY symbol, date ASC
        """)
        
        result = db.session.execute(query, {'start_date': start_date, 'end_date': end_date, 'index_list': index_list})
        
        # Organize data by symbol
        indices_data = {}
        
        for row in result:
            symbol = row.symbol
            
            if symbol not in indices_data:
                indices_data[symbol] = []
            
            indices_data[symbol].append({
                'date': row.date.isoformat(),
                'datetime': row.datetime_stamp.isoformat() if row.datetime_stamp else None,
                'open': float(row.open),
                'high': float(row.high),
                'low': float(row.low),
                'close': float(row.close),
                'volume': int(row.volume)
            })
        
        # Display name mapping for indices
        display_names = {
            'NIFTYBANK': 'BANKNIFTY',
            'BSE:SENSEX': 'BSE-SENSEX'
        }
        
        # Calculate LTP and % change for each index
        chart_data = []
        latest_data = websocket_manager.get_latest_data() if websocket_manager and websocket_manager.is_connected else {}
        
        for symbol, history in indices_data.items():
            if len(history) >= 1:
                oldest_close = history[0]['close']
                ltp = latest_data.get(symbol, {}).get('ltp', history[-1]['close'])
                pct_change = ((ltp - oldest_close) / oldest_close * 100) if oldest_close > 0 else 0
                
                # Use display name if available, otherwise use symbol
                display_symbol = display_names.get(symbol, symbol)
                
                chart_data.append({
                    'symbol': display_symbol,
                    'db_symbol': symbol,  # Keep for sorting
                    'ltp': round(ltp, 2),
                    'pct_change_5d': round(pct_change, 2),
                    'history': history
                })
        
        # Sort by index_list order using db_symbol
        chart_data.sort(key=lambda x: index_list.index(x['db_symbol']) if x['db_symbol'] in index_list else 999)
        
        # Remove db_symbol from response
        for item in chart_data:
            del item['db_symbol']
        
        return jsonify({
            'status': 'success',
            'data': chart_data,
            'total_symbols': len(chart_data)
        })
        
    except Exception as e:
        logger.error(f"Error fetching index line chart data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linechart-data')
@login_required
def get_linechart_data():
    """Get 5-day historical data for all F&O stocks for line charts"""
    try:
        from datetime import date, timedelta
        from sqlalchemy import text
        
        global websocket_manager
        
        # Get last 5 trading days data
        end_date = date.today()
        start_date = end_date - timedelta(days=10)  # Look back 10 days to ensure we get 5 trading days
        
        # Query to get last 5 days of data for each symbol
        query = text("""
            WITH ranked_data AS (
                SELECT 
                    symbol,
                    date,
                    datetime_stamp,
                    open,
                    high,
                    low,
                    close,
                    volume,
                    ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365
                WHERE timeframe = '1D'
                  AND date >= :start_date
                  AND date <= :end_date
            )
            SELECT symbol, date, datetime_stamp, open, high, low, close, volume
            FROM ranked_data
            WHERE rn <= 5
            ORDER BY symbol, date ASC
        """)
        
        result = db.session.execute(query, {'start_date': start_date, 'end_date': end_date})
        
        # Organize data by symbol
        stocks_data = {}
        fo_symbols = get_fo_symbols_for_chart()
        
        for row in result:
            symbol = row.symbol
            
            # Skip if not in F&O symbols list or is an index
            if symbol not in fo_symbols or 'NIFTY' in symbol or 'BANKNIFTY' in symbol or 'MIDCPNIFTY' in symbol or 'FINNIFTY' in symbol or 'SENSEX' in symbol:
                continue
            
            if symbol not in stocks_data:
                stocks_data[symbol] = []
            
            stocks_data[symbol].append({
                'date': row.date.isoformat(),
                'datetime': row.datetime_stamp.isoformat() if row.datetime_stamp else None,
                'open': float(row.open),
                'high': float(row.high),
                'low': float(row.low),
                'close': float(row.close),
                'volume': int(row.volume)
            })
        
        # Calculate LTP and % change from 5 days ago for each stock
        chart_data = []
        latest_data = websocket_manager.get_latest_data() if websocket_manager and websocket_manager.is_connected else {}
        
        for symbol, history in stocks_data.items():
            if len(history) >= 1:
                # Get oldest close (5 days ago or earliest available)
                oldest_close = history[0]['close']
                
                # Get LTP from websocket or latest close
                ltp = latest_data.get(symbol, {}).get('ltp', history[-1]['close'])
                
                # Calculate % change from earliest available day
                pct_change = ((ltp - oldest_close) / oldest_close * 100) if oldest_close > 0 else 0
                
                chart_data.append({
                    'symbol': symbol,
                    'ltp': round(ltp, 2),
                    'pct_change_5d': round(pct_change, 2),
                    'history': history
                })
        
        # Sort by symbol
        chart_data.sort(key=lambda x: x['symbol'])
        
        return jsonify({
            'status': 'success',
            'data': chart_data,
            'total_symbols': len(chart_data)
        })
        
    except Exception as e:
        logger.error(f"Error fetching line chart data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/initial-data')
@login_required
def get_initial_data():
    """Get initial data from most recent historical records to populate dashboard before live data"""
    try:
        from datetime import date, timedelta
        from sqlalchemy import desc, func
        
        # Use hist_data_365 table which has the actual data (same source as RVOL)
        end_date = date.today()
        start_date = end_date - timedelta(days=7)  # Look back 7 days for recent data
        
        # Get the most recent data for each symbol from hist_data_365
        subquery = db.session.query(
            HistData365.symbol,
            func.max(HistData365.date).label('max_date')
        ).filter(
            and_(
                HistData365.timeframe == '1D',
                HistData365.date >= start_date,
                HistData365.date <= end_date
            )
        ).group_by(HistData365.symbol).subquery()
        
        # Get the latest record for each symbol
        recent_data = db.session.query(HistData365).join(
            subquery,
            and_(
                HistData365.symbol == subquery.c.symbol,
                HistData365.date == subquery.c.max_date,
                HistData365.timeframe == '1D'
            )
        ).order_by(HistData365.symbol).limit(200).all()
        
        # Format data for frontend consumption
        initial_stocks = []
        processed_symbols = set()
        
        for record in recent_data:
            if record.symbol not in processed_symbols:
                # Simple change calculation from open to close
                change = (record.close - record.open) if record.open and record.close else 0
                change_percent = (change / record.open * 100) if record.open and record.open > 0 else 0
                
                stock_data = {
                    'symbol': record.symbol,
                    'full_symbol': f"NSE:{record.symbol}-EQ",
                    'ltp': record.close or 0,
                    'open_price': record.open or 0,
                    'high_price': record.high or 0,
                    'low_price': record.low or 0,
                    'close_price': record.close or 0,
                    'volume': record.volume or 0,
                    'change': round(change, 2),
                    'change_percent': round(change_percent, 2),
                    'timestamp': record.date.isoformat(),
                    'is_historical': True  # Flag to indicate this is historical data
                }
                initial_stocks.append(stock_data)
                processed_symbols.add(record.symbol)
        
        # Sort by symbol for consistent ordering
        initial_stocks = sorted(initial_stocks, key=lambda x: x['symbol'])
        
        logger.info(f"Retrieved initial data for {len(initial_stocks)} stocks from hist_data_365 table")
        
        return jsonify({
            'status': 'success',
            'data': initial_stocks,
            'message': f'Loaded previous day data for {len(initial_stocks)} stocks'
        })
        
    except Exception as e:
        logger.error(f"Error getting initial data: {str(e)}")
        # Return empty data gracefully to prevent frontend issues
        return jsonify({
            'status': 'success',
            'data': [],
            'message': 'Live data will load when WebSocket connection is established'
        })


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    global historical_manager, websocket_manager
    
    # Check subscription status - only allow access if user has active subscription
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access the dashboard.', 'warning')
        return redirect(url_for('account'))
    
    if not session.get('authenticated'):
        # ALL logged-in users can use shared Fyers authentication for live data
        token_result = fyers_auth.get_valid_token()
        if token_result['status'] == 'success':
            # Auto-authenticate ALL users with the shared system token
            session['access_token'] = token_result['access_token']
            session['authenticated'] = True
            
            # Initialize historical data manager
            historical_manager = HistoricalDataManager(token_result['access_token'])
            
            # Initialize WebSocket manager for live data using singleton  
            websocket_manager = get_websocket_manager()
            
            logger.info(f"User {current_user.username} auto-authenticated with shared system token for live streaming access")
            
            # Start background historical data fetcher for admin users (only if needed)
            if current_user.is_admin():
                start_background_historical_fetcher_for_admin()
        else:
            # Only show this for admin - regular users will still get live data if available
            if current_user.is_admin():
                logger.info(f"Admin {current_user.username} needs to set up Fyers API authentication for the system")
            else:
                logger.info(f"User {current_user.username} can access dashboard - live data available when admin sets up authentication")
    
    # Ensure managers are initialized even if already authenticated
    if not historical_manager and session.get('access_token'):
        historical_manager = HistoricalDataManager(session['access_token'])
    
    # Get WebSocket manager using centralized singleton (handles token refresh automatically)
    if session.get('access_token'):
        websocket_manager = get_websocket_manager()
        # Explicitly log the WebSocket assignment for debugging
        logger.info(f"🔗 WebSocket manager retrieved via singleton: {websocket_manager is not None}")
    
    # Technical analysis initialization disabled to prevent memory issues on login
    # Users can manually trigger technical analysis calculations if needed
    logger.info(f"User {current_user.username} accessing dashboard. Technical analysis can be manually triggered if needed.")
    
    # Pass authentication status to template  
    api_authenticated = session.get('authenticated', False)
    has_token = session.get('access_token') is not None
    
    return render_template('dashboard.html', 
                         is_admin=current_user.is_admin(),
                         api_authenticated=api_authenticated,
                         has_token=has_token)

@app.route('/all-charts')
@login_required
def all_charts():
    """All stocks 100-day chart analysis page"""
    # Check subscription status
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access charts.', 'warning')
        return redirect(url_for('account'))
    
    return render_template('all_charts.html')

@app.route('/live-chart')
@login_required
def live_chart():
    """Live streaming chart page with 5-minute timeframe - Admin only"""
    global websocket_manager
    
    # Check admin access - Admin users have unrestricted access
    if not current_user.is_admin():
        flash('Live chart access is restricted to admin users only.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Auto-authenticate with shared system token if not already authenticated
    if not session.get('authenticated'):
        token_result = fyers_auth.get_valid_token()
        if token_result['status'] == 'success':
            session['access_token'] = token_result['access_token']
            session['authenticated'] = True
            logger.info(f"User {current_user.username} auto-authenticated for live chart access")
    
    # Initialize WebSocket manager if available
    if session.get('access_token'):
        websocket_manager = get_websocket_manager()
    
    # Get list of F&O symbols for stock selection dropdown
    fo_symbols = get_fo_symbols_for_chart()
    
    api_authenticated = session.get('authenticated', False)
    has_token = session.get('access_token') is not None
    
    return render_template('live_chart.html',
                         is_admin=current_user.is_admin(),
                         api_authenticated=api_authenticated,
                         has_token=has_token,
                         fo_symbols=fo_symbols)

@app.route('/weekly-dashboard')
@login_required
def weekly_dashboard():
    """Weekly dashboard page - uses weekly OHLC data instead of daily"""
    global historical_manager, websocket_manager
    
    # Check subscription status
    if not current_user.is_subscription_active():
        flash('Please subscribe to a plan or start a free trial to access the weekly dashboard.', 'warning')
        return redirect(url_for('account'))
    
    if not session.get('authenticated'):
        # ALL logged-in users can use shared Fyers authentication for live data
        token_result = fyers_auth.get_valid_token()
        if token_result['status'] == 'success':
            # Auto-authenticate ALL users with the shared system token
            session['access_token'] = token_result['access_token']
            session['authenticated'] = True
            
            # Initialize historical data manager
            historical_manager = HistoricalDataManager(token_result['access_token'])
            
            # Initialize WebSocket manager for live data using singleton  
            websocket_manager = get_websocket_manager()
            
            logger.info(f"User {current_user.username} auto-authenticated with shared system token for weekly dashboard access")
            
            # Start background historical data fetcher for admin users (only if needed)
            if current_user.is_admin():
                start_background_historical_fetcher_for_admin()
        else:
            # Only show this for admin - regular users will still get live data if available
            if current_user.is_admin():
                logger.info(f"Admin {current_user.username} needs to set up Fyers API authentication for the system")
            else:
                logger.info(f"User {current_user.username} can access weekly dashboard - live data available when admin sets up authentication")
    
    # Ensure managers are initialized even if already authenticated
    if not historical_manager and session.get('access_token'):
        historical_manager = HistoricalDataManager(session['access_token'])
    
    # Get WebSocket manager using centralized singleton (handles token refresh automatically)
    if session.get('access_token'):
        websocket_manager = get_websocket_manager()
        # Explicitly log the WebSocket assignment for debugging
        logger.info(f"🔗 WebSocket manager retrieved via singleton: {websocket_manager is not None}")
    
    # Technical analysis initialization disabled to prevent memory issues on login
    # Users can manually trigger technical analysis calculations if needed
    logger.info(f"User {current_user.username} accessing weekly dashboard. Technical analysis can be manually triggered if needed.")
    
    # Pass authentication status to template  
    api_authenticated = session.get('authenticated', False)
    has_token = session.get('access_token') is not None
    
    return render_template('weekly_dashboard.html', 
                         is_admin=current_user.is_admin(),
                         api_authenticated=api_authenticated,
                         has_token=has_token)

@app.route('/start_websocket')
def start_websocket():
    """Start WebSocket connection"""
    global websocket_manager
    
    try:
        if not session.get('authenticated'):
            return jsonify({
                'status': 'error',
                'message': 'Not authenticated'
            }), 401
        
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({
                'status': 'error',
                'message': 'No access token found'
            }), 400
        
        # Get WebSocket manager using centralized singleton
        websocket_manager = get_websocket_manager()
        
        # Check if WebSocket is available and connected
        if websocket_manager and (websocket_manager.is_connected or websocket_manager.connect()):
            return jsonify({
                'status': 'success',
                'message': 'WebSocket connection initiated'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to start WebSocket connection'
            }), 500
            
    except Exception as e:
        logger.error(f"Error starting WebSocket: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/websocket_status')
def websocket_status():
    """Get WebSocket connection status"""
    global websocket_manager
    
    if websocket_manager is None:
        return jsonify({
            'status': 'disconnected',
            'is_connected': False,
            'last_update': None,
            'symbol_count': 0
        })
    
    return jsonify(websocket_manager.get_connection_status())

@app.route('/websocket_disconnect_stats')
@login_required
def websocket_disconnect_stats():
    """Get detailed WebSocket disconnection statistics - Admin only"""
    ws_manager = get_websocket_manager()
    
    if ws_manager is None:
        return jsonify({
            'error': 'WebSocket manager not initialized',
            'total_disconnections': 0,
            'total_downtime_seconds': 0
        })
    
    return jsonify(ws_manager.get_disconnection_stats())

@app.route('/stock_data')
def stock_data():
    """Get latest stock data with OHLC and uniform symbol ordering + real-time alerts"""
    global websocket_manager
    
    if websocket_manager is None:
        return jsonify({'status': 'disconnected', 'data': {}, 'alerts': []})
    
    latest_data = websocket_manager.get_latest_data()
    # Get real-time alerts for instant delivery
    alerts = websocket_manager.get_new_alerts()
    
    # Create a mapping of symbols to data for uniform ordering
    symbol_to_data = {}
    for symbol, stock_data in latest_data.items():
        symbol_to_data[symbol] = stock_data
    
    # Order data according to Config.NIFTY50_SYMBOLS (Index first, then F&O alphabetically)
    enriched_data = []
    for full_symbol in Config.NIFTY50_SYMBOLS:
        if full_symbol in symbol_to_data:
            enriched_data.append(symbol_to_data[full_symbol])
    
    response = jsonify({
        'status': 'connected',
        'data': enriched_data,
        'alerts': alerts,
        'symbol_count': len(enriched_data)
    })
    
    # Add cache-busting headers to force refresh
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/alerts')
def get_alerts():
    """Get new high/low alerts from WebSocket manager"""
    websocket_manager = get_websocket_manager()
    
    if websocket_manager is None or not websocket_manager.is_connected:
        return jsonify({'status': 'disconnected', 'alerts': []})
    
    alerts = websocket_manager.get_new_alerts()
    
    response = jsonify({
        'status': 'connected',
        'alerts': alerts,
        'count': len(alerts)
    })
    
    # Add cache-busting headers to force refresh
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/api/stocks')
def api_stocks():
    """Simple API endpoint for current stock data with uniform symbol ordering (optimized)"""
    try:
        # Optimized single query using LEFT JOIN to get stock data with hist counts
        from sqlalchemy import text
        combined_query = text("""
            SELECT 
                s.symbol,
                s.ltp,
                s.change,
                s.change_percent,
                s.volume,
                s.timestamp,
                COALESCE(h.record_count, 0) as hist_record_count
            FROM stock_data s
            LEFT JOIN (
                SELECT symbol, COUNT(*) as record_count 
                FROM hist_data_365 
                GROUP BY symbol
            ) h ON s.symbol = h.symbol
        """)
        
        result = db.session.execute(combined_query).fetchall()
        
        # Create a mapping of symbols to records for uniform ordering
        symbol_to_record = {}
        for row in result:
            symbol_to_record[row.symbol] = row
        
        # Order data according to Config.NIFTY50_SYMBOLS (Index first, then F&O alphabetically)
        stock_list = []
        for full_symbol in Config.NIFTY50_SYMBOLS:
            # Extract clean symbol name from full symbol
            clean_symbol = full_symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            if clean_symbol in symbol_to_record:
                stock = symbol_to_record[clean_symbol]
                
                # Fix full_symbol format - ensure correct NSE:SYMBOL-EQ format
                if 'NIFTY' in clean_symbol.upper() or 'VIX' in clean_symbol.upper():
                    corrected_full_symbol = f"NSE:{clean_symbol}-INDEX"
                elif 'SENSEX' in clean_symbol.upper():
                    corrected_full_symbol = f"BSE:{clean_symbol}-INDEX"
                else:
                    corrected_full_symbol = f"NSE:{clean_symbol}-EQ"
                
                stock_list.append({
                    'symbol': clean_symbol,
                    'full_symbol': corrected_full_symbol,
                    'ltp': float(stock.ltp) if stock.ltp else 0.0,
                    'hist_record_count': int(stock.hist_record_count),
                    'change': float(stock.change) if stock.change else 0.0,
                    'change_percent': float(stock.change_percent) if stock.change_percent else 0.0,
                    'volume': int(stock.volume) if stock.volume else 0,
                    'status': 'active' if stock.ltp and stock.ltp > 0 else 'inactive',
                    'last_update': stock.timestamp.isoformat() if stock.timestamp else None
                })
        
        response = jsonify({
            'status': 'success',
            'stocks': stock_list,
            'count': len(stock_list)
        })
        
        # Add cache-busting headers to force refresh
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting stock data: {str(e)}")
        return jsonify({
            'status': 'error', 
            'message': str(e),
            'stocks': [],
            'count': 0
        })

@app.route('/api/data')
def get_live_data():
    """API endpoint for polling live data"""
    global websocket_manager
    
    try:
        # Use centralized WebSocket manager singleton (handles auto-initialization)
        websocket_manager = get_websocket_manager()
        
        if websocket_manager is not None:
            # Get any new messages and alerts for real-time streaming
            messages = websocket_manager.get_new_messages()
            alerts = websocket_manager.get_new_alerts()
            status = websocket_manager.get_connection_status()
            
            
            response = jsonify({
                'status': 'success',
                'messages': messages,
                'alerts': alerts,
                'connection_status': status,
                'timestamp': time.time()
            })
            
            # Add CORS headers
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
            
            return response
        else:
            response = jsonify({
                'status': 'disconnected',
                'messages': [],
                'alerts': [],
                'connection_status': {'is_connected': False, 'status': 'no_manager'},
                'timestamp': time.time()
            })
            
            # Add CORS headers
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
            
            return response
    except Exception as e:
        logger.error(f"Error in get_live_data: {str(e)}")
        response = jsonify({
            'status': 'error',
            'messages': [],
            'alerts': [],
            'error': str(e),
            'timestamp': time.time()
        })
        
        # Add CORS headers
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        
        return response

@app.route('/api/sparkline-data')
def get_sparkline_data():
    """Get 5-day intraday sparkline data for multiple symbols efficiently"""
    try:
        symbols = request.args.get('symbols', '')
        if not symbols:
            return jsonify({'status': 'error', 'message': 'No symbols provided'}), 400
        
        symbol_list = [s.strip() for s in symbols.split(',') if s.strip()]
        if not symbol_list:
            return jsonify({'status': 'error', 'message': 'Invalid symbols'}), 400
        
        # Fetch last 5 trading days of 5-minute intraday data
        from datetime import datetime, timedelta
        from sqlalchemy import bindparam
        five_days_ago = datetime.now() - timedelta(days=7)  # 7 calendar days to ensure 5 trading days
        
        query = text("""
            SELECT symbol, close, datetime_stamp
            FROM hist_data_5min
            WHERE symbol IN :symbols
            AND close IS NOT NULL
            AND datetime_stamp >= :start_date
            ORDER BY symbol, datetime_stamp ASC
        """).bindparams(bindparam('symbols', expanding=True))
        
        result = db.session.execute(query, {
            'symbols': symbol_list,  # Pass list directly, not tuple
            'start_date': five_days_ago
        })
        
        # Organize data by symbol with timestamps
        sparkline_data = {}
        for row in result:
            symbol = row[0]
            close = float(row[1]) if row[1] else 0
            timestamp = int(row[2].timestamp() * 1000)  # Convert to milliseconds
            
            if symbol not in sparkline_data:
                sparkline_data[symbol] = []
            sparkline_data[symbol].append({
                'timestamp': timestamp,
                'price': close
            })
        
        return jsonify({
            'status': 'success',
            'data': sparkline_data
        })
        
    except Exception as e:
        logger.error(f"Error fetching sparkline data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ===============================
# WEEKLY API ROUTES
# ===============================

@app.route('/api/weekly/initial-data')
@login_required
def get_weekly_initial_data():
    """Get initial weekly data from most recent weekly records to populate weekly dashboard"""
    try:
        from sqlalchemy import and_, func
        
        # Get the most recent weekly data for all symbols
        subquery = db.session.query(
            WeeklyOHLCData.symbol,
            func.max(WeeklyOHLCData.week_end_date).label('max_week')
        ).group_by(WeeklyOHLCData.symbol).subquery()
        
        # Get INDEX symbols first (always include them)
        index_data = db.session.query(WeeklyOHLCData).join(
            subquery,
            and_(
                WeeklyOHLCData.symbol == subquery.c.symbol,
                WeeklyOHLCData.week_end_date == subquery.c.max_week
            )
        ).filter(WeeklyOHLCData.symbol.in_(Config.INDEX_SYMBOLS)).all()
        
        # Get F&O stocks data (limited to prevent timeouts)
        fno_data = db.session.query(WeeklyOHLCData).join(
            subquery,
            and_(
                WeeklyOHLCData.symbol == subquery.c.symbol,
                WeeklyOHLCData.week_end_date == subquery.c.max_week
            )
        ).filter(WeeklyOHLCData.symbol.in_(Config.FNO_STOCKS)).limit(50).all()
        
        # Combine both datasets
        recent_data = index_data + fno_data
        
        # Format data for frontend consumption
        initial_stocks = []
        for record in recent_data:
            clean_symbol = record.symbol
            
            # Simple change calculation from open to close
            change = record.close_price - record.open_price
            change_percent = (change / record.open_price * 100) if record.open_price > 0 else 0
            
            stock_data = {
                'symbol': clean_symbol,
                'full_symbol': record.full_symbol,
                'ltp': record.close_price,  # Use weekly close as LTP
                'open_price': record.open_price,
                'high_price': record.high_price,
                'low_price': record.low_price,
                'close_price': record.close_price,
                'volume': record.volume,
                'change': change,
                'change_percent': change_percent,
                'timestamp': record.week_end_date.isoformat(),
                'is_weekly': True,  # Flag to indicate this is weekly data
                'week_start': record.week_start_date.isoformat(),
                'week_end': record.week_end_date.isoformat(),
                'trading_days': record.trading_days_count
            }
            initial_stocks.append(stock_data)
        
        logger.info(f"Retrieved weekly initial data for {len(initial_stocks)} stocks from weekly records")
        
        return jsonify({
            'status': 'success',
            'data': initial_stocks,
            'message': f'Loaded weekly data for {len(initial_stocks)} stocks',
            'data_type': 'weekly'
        })
        
    except Exception as e:
        logger.error(f"Error getting weekly initial data: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'data_type': 'weekly'
        }), 500

@app.route('/api/weekly/stocks')
def api_weekly_stocks():
    """API endpoint for weekly stock data with uniform symbol ordering"""
    try:
        # Get weekly data from database - most recent week for each symbol
        from sqlalchemy import func
        
        subquery = db.session.query(
            WeeklyOHLCData.symbol,
            func.max(WeeklyOHLCData.week_end_date).label('max_week')
        ).group_by(WeeklyOHLCData.symbol).subquery()
        
        weekly_stocks = db.session.query(WeeklyOHLCData).join(
            subquery,
            and_(
                WeeklyOHLCData.symbol == subquery.c.symbol,
                WeeklyOHLCData.week_end_date == subquery.c.max_week
            )
        ).all()
        
        # Get weekly data record counts for each symbol
        from sqlalchemy import text
        weekly_counts_query = text("""
            SELECT symbol, COUNT(*) as record_count 
            FROM weekly_ohlc_data 
            GROUP BY symbol
        """)
        try:
            weekly_counts_result = db.session.execute(weekly_counts_query).fetchall()
            weekly_counts = {row.symbol: row.record_count for row in weekly_counts_result}
        except Exception as e:
            logger.error(f"Error getting weekly counts: {e}")
            weekly_counts = {}
        
        # Convert to dictionaries for JSON response
        stocks_data = []
        for stock in weekly_stocks:
            change = stock.close_price - stock.open_price
            change_percent = (change / stock.open_price * 100) if stock.open_price > 0 else 0
            
            stocks_data.append({
                'symbol': stock.symbol,
                'full_symbol': stock.full_symbol,
                'ltp': stock.close_price,
                'open_price': stock.open_price,
                'high_price': stock.high_price,
                'low_price': stock.low_price,
                'close_price': stock.close_price,
                'volume': stock.volume,
                'change': change,
                'change_percent': change_percent,
                'week_start': stock.week_start_date.isoformat(),
                'week_end': stock.week_end_date.isoformat(),
                'trading_days': stock.trading_days_count,
                'weekly_record_count': weekly_counts.get(stock.symbol, 0),
                'data_type': 'weekly'
            })
        
        # Sort symbols alphabetically for consistent ordering
        stocks_data.sort(key=lambda x: x['symbol'])
        
        logger.info(f"API weekly stocks response: {len(stocks_data)} stocks")
        
        return jsonify({
            'status': 'success',
            'data': stocks_data,
            'total_symbols': len(stocks_data),
            'data_type': 'weekly'
        })
        
    except Exception as e:
        logger.error(f"Error in API weekly stocks: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'data': [],
            'data_type': 'weekly'
        }), 500

@app.route('/api/weekly/data')
def get_weekly_live_data():
    """API endpoint for weekly data (returns static weekly data, no live updates)"""
    try:
        # For weekly dashboard, we return the most recent weekly data
        # Note: Weekly data is static and doesn't have real-time updates
        
        return jsonify({
            'status': 'success',
            'messages': [],  # No real-time messages for weekly data
            'alerts': [],    # No real-time alerts for weekly data
            'connection_status': {'is_connected': False, 'status': 'weekly_mode'},
            'timestamp': time.time(),
            'data_type': 'weekly',
            'note': 'Weekly dashboard uses static weekly OHLC data'
        })
        
    except Exception as e:
        logger.error(f"Error in get_weekly_live_data: {str(e)}")
        return jsonify({
            'status': 'error',
            'messages': [],
            'alerts': [],
            'error': str(e),
            'timestamp': time.time(),
            'data_type': 'weekly'
        }), 500

# ===============================
# WATCHLIST API ROUTES
# ===============================

@app.route('/api/watchlist', methods=['GET'])
@login_required
def get_watchlist():
    """Get user's watchlist"""
    try:
        watchlist_items = Watchlist.query.filter_by(user_id=current_user.id).order_by(Watchlist.created_at.desc()).all()
        
        return jsonify({
            'status': 'success',
            'watchlist': [item.to_dict() for item in watchlist_items],
            'count': len(watchlist_items)
        })
    except Exception as e:
        logger.error(f"Error getting watchlist: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/watchlist/add', methods=['POST'])
@login_required
def add_to_watchlist():
    """Add stock to user's watchlist"""
    try:
        data = request.get_json()
        symbol = data.get('symbol', '').strip()
        full_symbol = data.get('full_symbol', '').strip()
        display_name = data.get('display_name', '').strip()
        notes = data.get('notes', '').strip()
        current_ltp = data.get('current_ltp')  # Current LTP when adding
        investment_amount = data.get('investment_amount')  # No default - user must set manually
        selection_method = data.get('selection_method', '').strip()  # Selection method
        
        if not symbol or not full_symbol:
            return jsonify({'status': 'error', 'message': 'Symbol and full_symbol are required'}), 400
        
        # Check if already exists
        existing = Watchlist.query.filter_by(user_id=current_user.id, symbol=symbol).first()
        if existing:
            return jsonify({'status': 'error', 'message': 'Stock is already in your watchlist'}), 400
        
        # Create new watchlist item
        watchlist_item = Watchlist(
            user_id=current_user.id,
            symbol=symbol,
            full_symbol=full_symbol,
            display_name=display_name if display_name else None,
            notes=notes if notes else None,
            added_ltp=current_ltp if current_ltp else None,
            investment_amount=investment_amount if investment_amount else None,
            selection_method=selection_method if selection_method else None
        )
        
        db.session.add(watchlist_item)
        db.session.commit()
        
        logger.info(f"User {current_user.username} added {symbol} to watchlist")
        
        return jsonify({
            'status': 'success',
            'message': f'{symbol} added to watchlist',
            'item': watchlist_item.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding to watchlist: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/watchlist/remove', methods=['DELETE'])
@login_required
def remove_from_watchlist():
    """Remove stock from user's watchlist"""
    try:
        data = request.get_json()
        symbol = data.get('symbol', '').strip()
        
        if not symbol:
            return jsonify({'status': 'error', 'message': 'Symbol is required'}), 400
        
        # Find and remove the item
        watchlist_item = Watchlist.query.filter_by(user_id=current_user.id, symbol=symbol).first()
        if not watchlist_item:
            return jsonify({'status': 'error', 'message': 'Stock not found in watchlist'}), 404
        
        db.session.delete(watchlist_item)
        db.session.commit()
        
        logger.info(f"User {current_user.username} removed {symbol} from watchlist")
        
        return jsonify({
            'status': 'success',
            'message': f'{symbol} removed from watchlist'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing from watchlist: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/watchlist/update', methods=['PUT'])
@login_required
def update_watchlist_item():
    """Update watchlist item (notes, display name, investment amount)"""
    try:
        data = request.get_json()
        symbol = data.get('symbol', '').strip()
        display_name = data.get('display_name', '').strip()
        notes = data.get('notes', '').strip()
        investment_amount = data.get('investment_amount')
        position_type = data.get('position_type', '').strip()
        selection_method = data.get('selection_method')
        
        if not symbol:
            return jsonify({'status': 'error', 'message': 'Symbol is required'}), 400
        
        # Find the item
        watchlist_item = Watchlist.query.filter_by(user_id=current_user.id, symbol=symbol).first()
        if not watchlist_item:
            return jsonify({'status': 'error', 'message': 'Stock not found in watchlist'}), 404
        
        # Update fields
        if display_name is not None:
            watchlist_item.display_name = display_name if display_name else None
        if notes is not None:
            watchlist_item.notes = notes if notes else None
        if investment_amount is not None:
            watchlist_item.investment_amount = investment_amount
        if position_type and position_type in ['Long', 'Short']:
            watchlist_item.position_type = position_type
        if selection_method is not None:
            watchlist_item.selection_method = selection_method.strip() if selection_method else None
        
        db.session.commit()
        
        logger.info(f"User {current_user.username} updated watchlist item {symbol}")
        
        return jsonify({
            'status': 'success',
            'message': f'{symbol} watchlist item updated',
            'item': watchlist_item.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating watchlist item: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ltp-break-levels', methods=['GET'])
@login_required
def get_ltp_break_levels():
    """Get LTP break analysis levels using LIVE WebSocket data"""
    try:
        # Get all stock data with historical levels
        stocks = StockData.query.all()
        
        # Get live data from WebSocket manager
        live_data = {}
        if websocket_manager and hasattr(websocket_manager, 'stock_data'):
            live_data = websocket_manager.stock_data.copy()
            logger.info(f"🔴 LIVE DATA: Using real-time WebSocket feed with {len(live_data)} symbols")
        else:
            logger.warning("⚠️ WebSocket manager not available, falling back to database LTP")
        
        levels_data = {}
        for stock in stocks:
            if stock.pdh or stock.pdl or stock.wkh or stock.wkl:
                # Get LIVE LTP from WebSocket feed instead of stale database value
                live_ltp = None
                
                # Try multiple symbol formats to match WebSocket data
                symbol_variations = [
                    stock.symbol,  # Direct symbol match
                    stock.full_symbol,  # Full symbol match  
                    stock.symbol.replace('-EQ', ''),  # Clean symbol
                    f"NSE:{stock.symbol}",  # NSE prefixed
                    f"NSE:{stock.symbol}-EQ"  # NSE with EQ suffix
                ]
                
                for symbol_variant in symbol_variations:
                    if symbol_variant in live_data:
                        live_ltp = live_data[symbol_variant].get('ltp', 0.0)
                        logger.debug(f"✅ Found live LTP for {stock.symbol}: {live_ltp} (matched as {symbol_variant})")
                        break
                
                # Fallback to database LTP if no live data found
                if live_ltp is None or live_ltp == 0.0:
                    live_ltp = stock.ltp
                    logger.debug(f"⚠️ Using database LTP for {stock.symbol}: {live_ltp}")
                
                # Calculate break analysis using LIVE LTP
                breaks = []
                if live_ltp and stock.pdh and live_ltp > stock.pdh:
                    breaks.append('PDH')
                if live_ltp and stock.pdl and live_ltp < stock.pdl:
                    breaks.append('PDL')
                if live_ltp and stock.wkh and live_ltp > stock.wkh:
                    breaks.append('WKH')
                if live_ltp and stock.wkl and live_ltp < stock.wkl:
                    breaks.append('WKL')
                
                levels_data[stock.symbol] = {
                    'symbol': stock.symbol,
                    'ltp': round(live_ltp, 2) if live_ltp else None,
                    'pdh': round(stock.pdh, 2) if stock.pdh else None,
                    'pdl': round(stock.pdl, 2) if stock.pdl else None,
                    'wkh': round(stock.wkh, 2) if stock.wkh else None,
                    'wkl': round(stock.wkl, 2) if stock.wkl else None,
                    'breaks': breaks,
                    'break_count': len(breaks),
                    'levels_updated_at': stock.levels_updated_at.isoformat() if stock.levels_updated_at else None,
                    'data_source': 'live' if live_ltp != stock.ltp else 'database'
                }
        
        logger.info(f"🔴 LTP Break API: Returned {len(levels_data)} symbols with live WebSocket data")
        
        return jsonify({
            'status': 'success',
            'levels': levels_data,
            'count': len(levels_data),
            'live_symbols': len(live_data),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting LTP break levels: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'levels': {},
            'count': 0
        }), 500

@app.route('/api/volume-profile/<symbol>', methods=['GET'])
@login_required
def get_volume_profile(symbol):
    """Get 5-day volume profile data for a specific symbol (excluding indexes) - OPTIMIZED"""
    try:
        # Exclude index symbols
        if 'INDEX' in symbol or symbol.endswith('-INDEX') or 'NIFTY' in symbol or 'SENSEX' in symbol:
            return jsonify({'status': 'error', 'message': 'Index symbols are not supported for volume profile'}), 400
        
        # Clean symbol format
        clean_symbol = symbol.replace('NSE:', '').replace('-EQ', '')
        
        # Quick check - if no data available, return simplified structure
        # Get 3 days of historical data instead of 5 for faster response
        from datetime import datetime, timedelta
        import pytz
        
        # Use IST timezone
        ist = pytz.timezone('Asia/Kolkata')
        end_date = datetime.now(ist).date()
        start_date = end_date - timedelta(days=5)  # Reduced from 7 to 5 days
        
        # Optimized query - limit to 3 records for faster response
        historical_data = HistData365.query.filter(
            HistData365.symbol == clean_symbol,
            HistData365.date >= start_date,
            HistData365.date <= end_date
        ).order_by(HistData365.date.desc()).limit(3).all()
        
        if not historical_data:
            # Return simplified structure for missing data
            return jsonify({
                'status': 'success',
                'symbol': clean_symbol,
                'volume_profile': [],
                'important_levels': {
                    'vpoc': 0,
                    'value_area_high': 0,
                    'value_area_low': 0
                },
                'daily_candles': [],
                'current_ltp': 0,
                'total_volume': 0,
                'data_source': 'no_data'
            }), 200
        
        # Simplified volume profile calculation for better performance
        total_volume = 0
        price_levels = {}
        
        for day_data in historical_data:
            try:
                # Basic validation
                high = float(day_data.high)
                low = float(day_data.low)
                volume = int(day_data.volume)
                
                if high <= 0 or low <= 0 or volume <= 0:
                    continue
                
                # Simplified price levels (reduced complexity)
                price_range = high - low
                if price_range > 0:
                    # Use fewer levels for faster calculation
                    num_levels = min(5, max(3, int(price_range / (price_range * 0.02))))  # 2% levels, max 5
                    level_size = price_range / num_levels
                    volume_per_level = volume / num_levels
                    
                    for i in range(num_levels):
                        level_price = round(low + (i * level_size), 2)
                        price_levels[level_price] = price_levels.get(level_price, 0) + volume_per_level
                        total_volume += volume_per_level
                        
            except (ValueError, TypeError) as e:
                logger.warning(f"Volume Profile: Invalid data for {clean_symbol}: {str(e)}")
                continue
        
        # Convert to simplified list (max 10 levels for performance)
        volume_data = []
        sorted_levels = sorted(price_levels.items(), key=lambda x: x[1], reverse=True)[:10]  # Top 10 only
        
        for price, vol in sorted_levels:
            volume_data.append({
                'price': price,
                'volume': int(vol),
                'volume_percent': round((vol / total_volume * 100), 2) if total_volume > 0 else 0
            })
        
        # Sort by price
        volume_data.sort(key=lambda x: x['price'])
        
        # Simplified important levels calculation
        vpoc_price = 0
        value_area_high = 0
        value_area_low = 0
        
        if volume_data:
            vpoc = max(volume_data, key=lambda x: x['volume'])
            vpoc_price = vpoc['price']
            
            # Simplified value area (just use top 70% of levels)
            prices = [item['price'] for item in volume_data]
            value_area_high = max(prices)
            value_area_low = min(prices)
        
        # Get current LTP (simplified)
        current_ltp = 0
        if websocket_manager and clean_symbol in websocket_manager.stock_data:
            current_ltp = websocket_manager.stock_data[clean_symbol].get('ltp', 0)
        
        # Simplified daily candle data
        daily_candles = []
        for day_data in historical_data[:3]:  # Only last 3 days
            try:
                daily_candles.append({
                    'date': day_data.date.strftime('%Y-%m-%d'),
                    'open': round(float(day_data.open), 2),
                    'high': round(float(day_data.high), 2),
                    'low': round(float(day_data.low), 2),
                    'close': round(float(day_data.close), 2),
                    'volume': int(day_data.volume)
                })
            except (ValueError, TypeError):
                continue
        
        return jsonify({
            'status': 'success',
            'symbol': clean_symbol,
            'volume_profile': volume_data,
            'important_levels': {
                'vpoc': vpoc_price,
                'value_area_high': value_area_high,
                'value_area_low': value_area_low
            },
            'current_ltp': current_ltp,
            'total_volume': int(total_volume),
            'daily_candles': daily_candles,
            'days_analyzed': len(historical_data),
            'data_source': 'database_optimized'
        })
        
    except Exception as e:
        logger.error(f"Volume Profile Error for {symbol}: {str(e)}")
        # Return graceful error response instead of 500 to prevent network errors
        return jsonify({
            'status': 'success',
            'symbol': symbol.replace('NSE:', '').replace('-EQ', ''),
            'volume_profile': [],
            'important_levels': {'vpoc': 0, 'value_area_high': 0, 'value_area_low': 0},
            'daily_candles': [],
            'current_ltp': 0,
            'total_volume': 0,
            'data_source': 'error_fallback',
            'error_message': str(e)
        }), 200

@app.route('/api/volume-profile/stocks', methods=['GET'])
@login_required
def get_volume_profile_stocks():
    """Get list of available stocks for volume profile (all 228 F&O stocks excluding indexes)"""
    try:
        from config import Config
        
        # Get all F&O stocks from config (excludes indexes)
        fno_stocks = Config.FNO_STOCKS
        
        stock_list = []
        for full_symbol in fno_stocks:
            # Extract symbol from NSE:SYMBOL-EQ format (preserve hyphens in symbol names)
            symbol = full_symbol.split(':')[1].replace('-EQ', '')
            
            # Skip index symbols
            if 'NIFTY' in symbol or 'SENSEX' in symbol or 'INDEX' in symbol:
                continue
                
            stock_list.append({
                'symbol': symbol,
                'display_name': symbol,
                'full_symbol': full_symbol
            })
        
        # Sort alphabetically
        stock_list.sort(key=lambda x: x['symbol'])
        
        return jsonify({
            'status': 'success',
            'stocks': stock_list,
            'count': len(stock_list)
        })
        
    except Exception as e:
        logger.error(f"Error getting volume profile stocks: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/volume-profile/all', methods=['GET'])
@login_required
def get_all_volume_profiles():
    """Get ALL volume profile data for all F&O stocks in ONE query - SUPER FAST"""
    try:
        from config import Config
        from datetime import datetime, timedelta, date
        from sqlalchemy import text
        
        # Get all F&O stock symbols (exclude indexes)
        fno_stocks = Config.FNO_STOCKS
        clean_symbols = []
        for full_symbol in fno_stocks:
            # Extract symbol from NSE:SYMBOL-EQ format (preserve hyphens in symbol names like BAJAJ-AUTO)
            symbol = full_symbol.split(':')[1].replace('-EQ', '')
            if 'NIFTY' not in symbol and 'SENSEX' not in symbol and 'INDEX' not in symbol:
                clean_symbols.append(symbol)
        
        # Get last 5 trading days data for all stocks in ONE query
        end_date = date.today()
        start_date = end_date - timedelta(days=10)
        
        query = text("""
            WITH ranked_data AS (
                SELECT 
                    symbol,
                    date,
                    open,
                    high,
                    low,
                    close,
                    volume,
                    ROW_NUMBER() OVER (PARTITION BY symbol ORDER BY date DESC) as rn
                FROM hist_data_365
                WHERE timeframe = '1D'
                  AND date >= :start_date
                  AND date <= :end_date
                  AND symbol = ANY(:symbols)
            )
            SELECT symbol, date, open, high, low, close, volume
            FROM ranked_data
            WHERE rn <= 5
            ORDER BY symbol, date ASC
        """)
        
        result = db.session.execute(query, {'start_date': start_date, 'end_date': end_date, 'symbols': clean_symbols})
        
        # Organize data by symbol
        stocks_data = {}
        for row in result:
            symbol = row.symbol
            if symbol not in stocks_data:
                stocks_data[symbol] = []
            stocks_data[symbol].append({
                'date': row.date.isoformat(),
                'open': float(row.open),
                'high': float(row.high),
                'low': float(row.low),
                'close': float(row.close),
                'volume': int(row.volume)
            })
        
        # Calculate volume profile for each stock
        volume_profiles = {}
        for symbol, history in stocks_data.items():
            if not history:
                continue
            
            # Calculate volume profile levels
            price_levels = {}
            total_volume = 0
            
            for day in history:
                # Divide the day's range into price levels
                day_high = day['high']
                day_low = day['low']
                day_volume = day['volume']
                
                if day_high == day_low:
                    price_key = round(day_high, 2)
                    price_levels[price_key] = price_levels.get(price_key, 0) + day_volume
                    total_volume += day_volume
                else:
                    # Distribute volume across price levels
                    num_levels = 20
                    price_step = (day_high - day_low) / num_levels
                    volume_per_level = day_volume / num_levels
                    
                    for i in range(num_levels):
                        price = day_low + (i * price_step)
                        price_key = round(price, 2)
                        price_levels[price_key] = price_levels.get(price_key, 0) + volume_per_level
                        total_volume += volume_per_level
            
            # Sort by volume to find important levels
            sorted_levels = sorted(price_levels.items(), key=lambda x: x[1], reverse=True)
            
            # Find VPOC (Volume Point of Control) - price with highest volume
            vpoc = sorted_levels[0][0] if sorted_levels else 0
            
            # Calculate Value Area (70% of total volume centered around VPOC)
            target_volume = total_volume * 0.70
            value_area_prices = []
            accumulated_volume = 0
            
            # Start with VPOC and expand outward
            for price, volume in sorted_levels:
                value_area_prices.append(price)
                accumulated_volume += volume
                if accumulated_volume >= target_volume:
                    break
            
            # VAH = highest price in value area, VAL = lowest price in value area
            vah = max(value_area_prices) if value_area_prices else vpoc
            val = min(value_area_prices) if value_area_prices else vpoc
            
            # Create volume profile array - sort by PRICE (not volume) for chart display
            # Sort all levels by price ascending for proper Y-axis display
            price_sorted_levels = sorted(price_levels.items(), key=lambda x: x[0])
            
            # Create volume profile array with all price levels
            volume_profile = [
                {'price': price, 'volume': int(volume)}
                for price, volume in price_sorted_levels
            ]
            
            volume_profiles[symbol] = {
                'symbol': symbol,
                'volume_profile': volume_profile,
                'important_levels': {
                    'vpoc': vpoc,
                    'value_area_high': vah,
                    'value_area_low': val
                },
                'total_volume': int(total_volume),
                'days_count': len(history)
            }
        
        logger.info(f"Volume Profile: Loaded {len(volume_profiles)} stocks in single query")
        
        return jsonify({
            'status': 'success',
            'volume_profiles': volume_profiles,
            'count': len(volume_profiles)
        })
        
    except Exception as e:
        logger.error(f"Error getting all volume profiles: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/chart-100day/<symbol>', methods=['GET'])
@login_required
def get_100_day_chart(symbol):
    """Get 100-day chart data for a symbol"""
    try:
        from urllib.parse import unquote
        
        # Decode URL-encoded symbols (for M&M, L&TFH etc.)
        decoded_symbol = unquote(symbol)
        clean_symbol = decoded_symbol.replace('-EQ', '').replace('NSE:', '').strip()
        
        # Get 100 days of historical data
        historical_data = HistData365.query.filter_by(symbol=clean_symbol).order_by(HistData365.date.desc()).limit(100).all()
        
        if not historical_data:
            return jsonify({'status': 'error', 'message': f'No historical data found for {clean_symbol}'}), 404
        
        # Reverse to get chronological order
        historical_data = list(reversed(historical_data))
        
        # Prepare candlestick data
        chart_data = []
        for day_data in historical_data:
            chart_data.append({
                'date': day_data.date.strftime('%Y-%m-%d'),
                'open': float(day_data.open),
                'high': float(day_data.high),
                'low': float(day_data.low),
                'close': float(day_data.close),
                'volume': int(day_data.volume)
            })
        
        # Calculate statistics
        prices = [float(day.close) for day in historical_data]
        volumes = [int(day.volume) for day in historical_data]
        
        period_high = max(float(day.high) for day in historical_data)
        period_low = min(float(day.low) for day in historical_data)
        start_price = float(historical_data[0].close)
        end_price = float(historical_data[-1].close)
        price_change = end_price - start_price
        price_change_percent = (price_change / start_price * 100) if start_price > 0 else 0
        
        # Get current LTP
        current_ltp = 0
        ws_symbol_variants = [clean_symbol, f'NSE:{clean_symbol}-EQ', f'NSE:{clean_symbol}']
        for variant in ws_symbol_variants:
            if websocket_manager and variant in websocket_manager.stock_data:
                current_ltp = websocket_manager.stock_data[variant].get('ltp', 0)
                break
        
        # Calculate moving averages
        def calculate_sma(prices, period):
            if len(prices) < period:
                return None
            return sum(prices[-period:]) / period
        
        sma_20 = calculate_sma(prices, 20)
        sma_50 = calculate_sma(prices, 50)
        
        # Calculate Volume Profile Levels
        def calculate_volume_profile_levels(historical_data):
            """Calculate 3 volume profile-based levels from 100-day data"""
            
            # Calculate period high/low for this specific stock within function scope
            stock_period_high = max(float(day.high) for day in historical_data)
            stock_period_low = min(float(day.low) for day in historical_data)
            
            # Calculate VWAP (Volume Weighted Average Price)
            total_volume = 0
            total_price_volume = 0
            
            # Price-volume mapping for volume nodes
            price_ranges = {}
            
            for day_data in historical_data:
                volume = int(day_data.volume)
                typical_price = (float(day_data.high) + float(day_data.low) + float(day_data.close)) / 3
                
                # VWAP calculation
                total_volume += volume
                total_price_volume += typical_price * volume
                
                # Group prices into ranges for volume node analysis (use more specific grouping based on price range)
                price_multiplier = 10 if stock_period_high < 100 else (1 if stock_period_high < 1000 else 0.1)
                price_range = round(typical_price * price_multiplier) / price_multiplier
                if price_range in price_ranges:
                    price_ranges[price_range] += volume
                else:
                    price_ranges[price_range] = volume
            
            # Calculate VWAP and handle zero volume case
            if total_volume == 0:
                # If no volume data, use simple price average
                all_prices = [float(day.close) for day in historical_data]
                vwap = sum(all_prices) / len(all_prices) if all_prices else 0
            else:
                vwap = total_price_volume / total_volume
            
            # Find High Volume Node (highest volume concentration)
            if price_ranges:
                high_volume_price = max(price_ranges.keys(), key=lambda k: price_ranges[k])
                
                # Find Low Volume Node (support level - look for volume cluster below VWAP)
                below_vwap_prices = {k: v for k, v in price_ranges.items() if k < vwap}
                if below_vwap_prices:
                    low_volume_price = max(below_vwap_prices.keys(), key=lambda k: below_vwap_prices[k])
                else:
                    # Fallback to lowest significant volume cluster
                    sorted_by_volume = sorted(price_ranges.items(), key=lambda x: x[1], reverse=True)
                    low_volume_price = sorted_by_volume[min(2, len(sorted_by_volume)-1)][0]
            else:
                # Fallback calculations using stock-specific values - ensure proper support < resistance ordering
                price_range = stock_period_high - stock_period_low
                buffer = max(price_range * 0.02, 0.1)  # At least 2% range or 0.1 minimum buffer
                
                high_volume_price = stock_period_high + buffer    # Resistance above period high
                low_volume_price = stock_period_low - buffer      # Support below period low
                
                # Final safety check to ensure support < resistance
                if low_volume_price >= high_volume_price:
                    mid_point = (stock_period_high + stock_period_low) / 2
                    high_volume_price = mid_point + (price_range * 0.1 or 1.0)
                    low_volume_price = mid_point - (price_range * 0.1 or 1.0)
            
            return [
                {'label': 'Support', 'value': float(low_volume_price), 'color': 'rgba(75, 192, 192, 0.8)', 'type': 'support'},
                {'label': 'VWAP', 'value': float(vwap), 'color': 'rgba(255, 206, 84, 0.8)', 'type': 'pivot'},
                {'label': 'Resistance', 'value': float(high_volume_price), 'color': 'rgba(255, 99, 132, 0.8)', 'type': 'resistance'}
            ]
        
        volume_profile_levels = calculate_volume_profile_levels(historical_data)
        
        return jsonify({
            'status': 'success',
            'symbol': clean_symbol,
            'chart_data': chart_data,
            'volume_profile_levels': volume_profile_levels,
            'statistics': {
                'period_high': period_high,
                'period_low': period_low,
                'price_change': price_change,
                'price_change_percent': price_change_percent,
                'current_ltp': current_ltp,
                'sma_20': sma_20,
                'sma_50': sma_50,
                'total_volume': sum(volumes),
                'avg_volume': sum(volumes) / len(volumes) if volumes else 0
            },
            'days_analyzed': len(historical_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting 100-day chart for {symbol}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/chart-5min/<symbol>', methods=['GET'])
@login_required
def get_chart_5min_data(symbol):
    """Get 5-minute aggregated OHLCV chart data for a symbol"""
    try:
        from datetime import datetime, timedelta
        from urllib.parse import unquote
        
        # Decode URL-encoded symbols (for M&M, L&TFH etc.)
        decoded_symbol = unquote(symbol)
        clean_symbol = decoded_symbol.replace('-EQ', '').replace('NSE:', '').strip()
        
        logger.info(f"🕐 5-min Chart requested for symbol: {clean_symbol}")
        
        # Get WebSocket manager to check if we have live data aggregation
        global websocket_manager
        if websocket_manager is None:
            websocket_manager = get_websocket_manager()
        
        # Get real 1-minute historical data and aggregate to 5-minute candles
        candles_data = get_5min_aggregated_data(clean_symbol)
        
        if not candles_data:
            return jsonify({
                'status': 'error',
                'message': f'No 5-minute data available for {clean_symbol}'
            }), 404
        
        # Get current LTP from WebSocket if available
        current_ltp = None
        if websocket_manager and hasattr(websocket_manager, 'get_current_ltp'):
            current_ltp = websocket_manager.get_current_ltp(clean_symbol)
        
        # Calculate statistics
        if candles_data:
            latest_candle = candles_data[-1]
            period_high = max(candle['high'] for candle in candles_data)
            period_low = min(candle['low'] for candle in candles_data)
            
            # Price change calculation
            if len(candles_data) >= 2:
                price_change = latest_candle['close'] - candles_data[0]['open']
                price_change_percent = (price_change / candles_data[0]['open']) * 100
            else:
                price_change = 0
                price_change_percent = 0
            
            # Calculate simple moving average (20 periods)
            sma_20 = None
            if len(candles_data) >= 20:
                sma_20 = sum(candle['close'] for candle in candles_data[-20:]) / 20
            
            # Use current LTP if available, otherwise latest close
            current_price = current_ltp if current_ltp else latest_candle['close']
            
            return jsonify({
                'status': 'success',
                'symbol': clean_symbol,
                'timeframe': '5min',
                'candles': candles_data,
                'statistics': {
                    'period_high': period_high,
                    'period_low': period_low,
                    'current_ltp': current_price,
                    'price_change': price_change,
                    'price_change_percent': price_change_percent,
                    'sma_20': sma_20,
                    'total_volume': sum(candle['volume'] for candle in candles_data),
                    'avg_volume': sum(candle['volume'] for candle in candles_data) / len(candles_data),
                    'candles_count': len(candles_data)
                },
                'last_updated': datetime.utcnow().isoformat(),
                'data_source': 'fyers_historical_1min_aggregated'  # Real 1-min data aggregated to 5-min
            })
        
        return jsonify({
            'status': 'error',
            'message': 'No data available'
        }), 404
        
    except Exception as e:
        logger.error(f"Error getting 5-min chart for {symbol}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def get_5min_aggregated_data(symbol):
    """Get 5-minute OHLCV data from hist_data_5min table"""
    try:
        from datetime import datetime, timedelta
        
        logger.info(f"📊 Retrieving 5-min data from hist_data_5min table for: {symbol}")
        
        # Query all available data from hist_data_5min table
        stored_candles = HistData5Min.query.filter(
            HistData5Min.symbol == symbol
        ).order_by(HistData5Min.datetime_stamp.asc()).all()
        
        if stored_candles and len(stored_candles) > 0:
            logger.info(f"✅ Found {len(stored_candles)} candles in hist_data_5min for {symbol}")
            # Convert database records to chart format
            five_min_candles = []
            for candle in stored_candles:
                five_min_candles.append({
                    'time': int(candle.datetime_stamp.timestamp() * 1000),
                    'open': float(candle.open),
                    'high': float(candle.high),
                    'low': float(candle.low),
                    'close': float(candle.close),
                    'volume': int(candle.volume)
                })
            
            # Return up to 8000 candles for performance
            final_candles = five_min_candles[-8000:] if len(five_min_candles) > 8000 else five_min_candles
            logger.info(f"📊 Retrieved {len(final_candles)} 5-min candles from hist_data_5min for {symbol}")
            return final_candles
        else:
            logger.warning(f"⚠️ No data found in hist_data_5min for {symbol}, returning empty array")
            return []
        
    except Exception as e:
        logger.error(f"Error getting data from hist_data_5min for {symbol}: {str(e)}")
        # Return empty array if database query fails
        return []

def store_real_5min_data_for_symbol(symbol):
    """Store real 5-minute historical data for a single symbol"""
    try:
        from datetime import datetime, timedelta
        
        logger.info(f"🔄 Fetching real historical data for {symbol}")
        
        # Get historical data manager
        hist_manager = get_historical_data_manager()
        if not hist_manager:
            logger.error(f"❌ Historical data manager not available for {symbol}")
            return False
        
        # Calculate date range - get last 100 days (respects API limits)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=100)
        
        # Convert symbol to Fyers format
        fyers_symbol = f"NSE:{symbol}-EQ"
        
        logger.info(f"📈 Fetching native 5-min data for {fyers_symbol} from {start_time} to {end_time}")
        
        # Fetch native 5-minute historical data (more efficient than aggregating 1-minute)
        five_min_data = hist_manager.fetch_historical_data(
            symbol=fyers_symbol,
            resolution='5',  # Native 5-minute resolution
            range_from=start_time,
            range_to=end_time
        )
        
        if not five_min_data:
            logger.warning(f"⚠️ No 5-min data returned for {symbol}")
            return False
        
        # Use native 5-minute candles directly (no aggregation needed)
        five_min_candles = five_min_data
        
        # Store in database - Five minute candle data for live charts
        stored_count = 0
        logger.info(f"🔄 Processing {len(five_min_candles)} candles for {symbol} (LIVE CHART DATA)")
        
        if not five_min_candles:
            logger.warning(f"❌ No candles to process for {symbol}")
            return False
            
        # Debug: Check first candle format
        logger.info(f"🔍 First candle format for {symbol}: {type(five_min_candles[0])}, sample: {five_min_candles[0]}")
        
        for i, candle in enumerate(five_min_candles):
            try:
                # Handle Fyers API format [timestamp, open, high, low, close, volume] 
                if isinstance(candle, list) and len(candle) >= 6:
                    timestamp, open_price, high_price, low_price, close_price, volume = candle[:6]
                    logger.debug(f"✅ Parsed candle {i+1}/{len(five_min_candles)}: {timestamp}, O:{open_price}, H:{high_price}, L:{low_price}, C:{close_price}, V:{volume}")
                else:
                    logger.error(f"❌ Unexpected candle format for {symbol} at index {i}: {type(candle)}, data: {candle}")
                    continue
                
                # Convert timestamp to datetime (handle both seconds and milliseconds)
                try:
                    if timestamp > 1e12:  # Milliseconds
                        candle_time = datetime.fromtimestamp(timestamp / 1000)
                    else:  # Seconds
                        candle_time = datetime.fromtimestamp(timestamp)
                    logger.debug(f"✅ Converted timestamp {timestamp} to {candle_time}")
                except Exception as ts_error:
                    logger.error(f"❌ Failed to convert timestamp {timestamp} for {symbol}: {str(ts_error)}")
                    continue
                
                # Validate price data
                if not all(isinstance(x, (int, float)) and x >= 0 for x in [open_price, high_price, low_price, close_price, volume]):
                    logger.error(f"❌ Invalid price data for {symbol} at {candle_time}: O:{open_price}, H:{high_price}, L:{low_price}, C:{close_price}, V:{volume}")
                    continue
                
                # Check if candle already exists (for 5-minute LIVE CHART data)
                existing = FiveMinCandleData.query.filter(
                    FiveMinCandleData.symbol == symbol,
                    FiveMinCandleData.candle_time == candle_time
                ).first()
                
                if not existing:
                    new_candle = FiveMinCandleData(
                        symbol=symbol,
                        full_symbol=fyers_symbol,
                        open_price=float(open_price),
                        high_price=float(high_price),
                        low_price=float(low_price),
                        close_price=float(close_price),
                        volume=int(volume),
                        candle_time=candle_time,
                        day_of_week=candle_time.strftime('%A')
                    )
                    db.session.add(new_candle)
                    stored_count += 1
                    
                    if stored_count <= 3 or stored_count % 500 == 0:  # Log first few and every 500th
                        logger.info(f"📊 Stored candle {stored_count} for {symbol}: {candle_time} OHLC({open_price}, {high_price}, {low_price}, {close_price})")
                else:
                    logger.debug(f"⚠️ Candle already exists for {symbol} at {candle_time}")
                    
            except Exception as candle_error:
                logger.error(f"❌ Error storing candle {i+1} for {symbol}: {str(candle_error)}, candle data: {candle}")
                continue
        
        # Commit the changes to five_min_candle_data table (LIVE CHART DATA)
        try:
            db.session.commit()
            logger.info(f"✅ Successfully stored {stored_count} 5-min candles for {symbol} in five_min_candle_data table (LIVE CHART DATA)")
            return True
        except Exception as commit_error:
            logger.error(f"❌ Failed to commit 5-min data for {symbol}: {str(commit_error)}")
            db.session.rollback()
            return False
        
    except Exception as e:
        logger.error(f"Error storing real data for {symbol}: {str(e)}")
        db.session.rollback()
        return False

def populate_5min_historical_data():
    """Populate HistoricalData table with 5-minute candles for all F&O symbols"""
    try:
        from datetime import datetime, timedelta
        
        logger.info("🔄 Starting 5-min historical data population...")
        
        # Get all F&O symbols from stock data
        fo_stocks = StockData.query.filter(StockData.symbol.isnot(None)).all()
        symbols_to_process = [stock.symbol for stock in fo_stocks if stock.symbol]
        
        logger.info(f"📊 Processing {len(symbols_to_process)} symbols for 5-min data storage")
        
        # Get historical data manager
        hist_manager = get_historical_data_manager()
        if not hist_manager:
            logger.error("❌ Historical data manager not available")
            return False
        
        success_count = 0
        error_count = 0
        
        # Process each symbol
        for symbol in symbols_to_process[:10]:  # Process first 10 symbols for now
            try:
                logger.info(f"📈 Processing 5-min data for {symbol}")
                
                # Calculate date range - get last 5 days
                end_time = datetime.now()
                start_time = end_time - timedelta(days=5)
                
                # Convert symbol to Fyers format
                fyers_symbol = f"NSE:{symbol}-EQ"
                
                # Fetch 1-minute historical data
                minute_data = hist_manager.fetch_historical_data(
                    symbol=fyers_symbol,
                    resolution='1',  # 1-minute resolution
                    range_from=start_time,
                    range_to=end_time
                )
                
                if not minute_data:
                    logger.warning(f"⚠️ No minute data for {symbol}")
                    error_count += 1
                    continue
                
                # Aggregate to 5-minute candles
                five_min_candles = aggregate_to_5min(minute_data)
                
                if not five_min_candles:
                    logger.warning(f"⚠️ No 5-min candles generated for {symbol}")
                    error_count += 1
                    continue
                
                # Store in database
                stored_count = 0
                for candle in five_min_candles:
                    try:
                        candle_time = datetime.fromtimestamp(candle['time'] / 1000)
                        
                        # Check if candle already exists
                        existing = HistoricalData.query.filter(
                            HistoricalData.symbol == symbol,
                            HistoricalData.resolution == '5',
                            HistoricalData.candle_time == candle_time
                        ).first()
                        
                        if not existing:
                            new_candle = HistoricalData(
                                symbol=symbol,
                                full_symbol=fyers_symbol,
                                resolution='5',
                                open_price=candle['open'],
                                high_price=candle['high'],
                                low_price=candle['low'],
                                close_price=candle['close'],
                                volume=candle['volume'],
                                candle_time=candle_time,
                                day_of_week=candle_time.strftime('%A')
                            )
                            db.session.add(new_candle)
                            stored_count += 1
                    except Exception as candle_error:
                        logger.error(f"Error storing candle for {symbol}: {str(candle_error)}")
                
                # Commit the changes for this symbol
                db.session.commit()
                logger.info(f"✅ Stored {stored_count} 5-min candles for {symbol}")
                success_count += 1
                
            except Exception as symbol_error:
                logger.error(f"Error processing {symbol}: {str(symbol_error)}")
                db.session.rollback()
                error_count += 1
        
        logger.info(f"🎯 5-min data population completed: {success_count} success, {error_count} errors")
        return True
        
    except Exception as e:
        logger.error(f"Error in 5-min data population: {str(e)}")
        db.session.rollback()
        return False

@app.route('/admin/populate-5min-data', methods=['POST'])
@login_required
def populate_5min_data_endpoint():
    """Admin endpoint to populate 5-minute historical data"""
    try:
        success = populate_5min_historical_data()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': '5-minute historical data population completed'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to populate 5-minute historical data'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in populate 5-min data endpoint: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def aggregate_to_5min(minute_data):
    """Aggregate 1-minute candle data to 5-minute candles"""
    try:
        if not minute_data:
            return []
        
        five_min_candles = []
        current_candle = None
        candle_start_time = None
        
        for candle in minute_data:
            # Parse candle: [timestamp, open, high, low, close, volume]
            timestamp = candle[0]
            open_price = float(candle[1])
            high_price = float(candle[2])
            low_price = float(candle[3])
            close_price = float(candle[4])
            volume = int(candle[5]) if len(candle) > 5 else 0
            
            # Convert timestamp to datetime and round to 5-minute boundary
            candle_time = datetime.fromtimestamp(timestamp)
            minute = candle_time.minute
            rounded_minute = (minute // 5) * 5  # Round down to nearest 5-minute boundary
            five_min_time = candle_time.replace(minute=rounded_minute, second=0, microsecond=0)
            
            # Check if we need to start a new 5-minute candle
            if candle_start_time is None or five_min_time != candle_start_time:
                # Save previous candle if exists
                if current_candle is not None:
                    five_min_candles.append(current_candle)
                
                # Start new 5-minute candle
                candle_start_time = five_min_time
                current_candle = {
                    'time': int(five_min_time.timestamp() * 1000),  # Unix timestamp in ms
                    'open': open_price,
                    'high': high_price,
                    'low': low_price,
                    'close': close_price,
                    'volume': volume
                }
            else:
                # Update existing 5-minute candle
                if current_candle:
                    current_candle['high'] = max(current_candle['high'], high_price)
                    current_candle['low'] = min(current_candle['low'], low_price)
                    current_candle['close'] = close_price  # Latest close price
                    current_candle['volume'] += volume
        
        # Add the last candle
        if current_candle is not None:
            five_min_candles.append(current_candle)
        
        # Sort by time and keep last 100 candles
        five_min_candles.sort(key=lambda x: x['time'])
        return five_min_candles[-100:] if len(five_min_candles) > 100 else five_min_candles
        
    except Exception as e:
        logger.error(f"Error aggregating to 5-min candles: {str(e)}")
        return []

def generate_5min_sample_data(symbol):
    """Generate sample 5-minute OHLCV data for testing - will be replaced with real aggregation"""
    from datetime import datetime, timedelta
    import random
    
    try:
        # Get base price from recent stock data
        stock_data = StockData.query.filter(
            StockData.symbol.ilike(f'%{symbol}%')
        ).first()
        
        base_price = float(stock_data.ltp) if stock_data and stock_data.ltp else 1000.0
        
        # Generate 5 days of 5-minute candles (minimum 5 days as requested)
        candles = []
        current_time = datetime.now() - timedelta(days=5)
        
        # Calculate realistic number of candles for 5 days (trading hours + extended hours)
        # 5 days * 16 hours/day (including pre/post market) * 12 candles/hour = 960 candles
        total_candles = 960
        
        for i in range(total_candles):
            # Calculate OHLCV for this 5-minute period
            if i == 0:
                open_price = base_price
            else:
                open_price = candles[-1]['close']
            
            # Add some realistic volatility
            volatility = base_price * 0.002  # 0.2% volatility per 5-min candle
            high_price = open_price + random.uniform(0, volatility)
            low_price = open_price - random.uniform(0, volatility)
            close_price = low_price + random.uniform(0, high_price - low_price)
            
            # Generate volume (higher during market hours)
            hour = current_time.hour
            if 9 <= hour <= 15:  # Market hours
                base_volume = random.randint(50000, 200000)
            else:
                base_volume = random.randint(5000, 25000)
            
            candles.append({
                'time': int(current_time.timestamp() * 1000),  # Unix timestamp in ms
                'open': round(open_price, 2),
                'high': round(high_price, 2),
                'low': round(low_price, 2),
                'close': round(close_price, 2),
                'volume': base_volume
            })
            
            current_time += timedelta(minutes=5)
        
        logger.info(f"🔢 Generated {len(candles)} 5-min candles for {symbol}")
        return candles
        
    except Exception as e:
        logger.error(f"Error generating sample data for {symbol}: {str(e)}")
        # Return basic sample data if database lookup fails
        return [
            {
                'time': int((datetime.now() - timedelta(minutes=5)).timestamp() * 1000),
                'open': 1000.0,
                'high': 1005.0,
                'low': 995.0,
                'close': 1002.0,
                'volume': 100000
            }
        ]

@app.route('/api/technical-levels/<symbol>', methods=['GET'])
@login_required
def get_technical_levels(symbol):
    """Get technical analysis levels for a symbol (Camarilla, CPR, Fibonacci)"""
    try:
        from datetime import datetime, date
        from urllib.parse import unquote
        
        # Decode URL-encoded symbols (for M&M, L&TFH etc.)
        decoded_symbol = unquote(symbol)
        clean_symbol = decoded_symbol.replace('-EQ', '').replace('NSE:', '').strip()
        today = date.today()
        
        levels = {}
        
        # Get Camarilla levels (latest available)
        camarilla = CamarillaLevels.query.filter_by(symbol=clean_symbol).order_by(CamarillaLevels.date.desc()).first()
        if camarilla:
            levels['camarilla'] = {
                'type': 'Camarilla',
                'levels': [
                    {'label': 'R5', 'value': float(camarilla.r5), 'color': 'rgba(255, 99, 132, 0.8)', 'type': 'resistance'},
                    {'label': 'R4', 'value': float(camarilla.r4), 'color': 'rgba(255, 99, 132, 0.7)', 'type': 'resistance'},
                    {'label': 'R3', 'value': float(camarilla.r3), 'color': 'rgba(255, 99, 132, 0.6)', 'type': 'resistance'},
                    {'label': 'R2', 'value': float(camarilla.r2), 'color': 'rgba(255, 99, 132, 0.5)', 'type': 'resistance'},
                    {'label': 'R1', 'value': float(camarilla.r1), 'color': 'rgba(255, 99, 132, 0.4)', 'type': 'resistance'},
                    {'label': 'PP', 'value': float(camarilla.pivot), 'color': 'rgba(255, 206, 84, 0.8)', 'type': 'pivot'},
                    {'label': 'S1', 'value': float(camarilla.s1), 'color': 'rgba(75, 192, 192, 0.4)', 'type': 'support'},
                    {'label': 'S2', 'value': float(camarilla.s2), 'color': 'rgba(75, 192, 192, 0.5)', 'type': 'support'},
                    {'label': 'S3', 'value': float(camarilla.s3), 'color': 'rgba(75, 192, 192, 0.6)', 'type': 'support'},
                    {'label': 'S4', 'value': float(camarilla.s4), 'color': 'rgba(75, 192, 192, 0.7)', 'type': 'support'},
                    {'label': 'S5', 'value': float(camarilla.s5), 'color': 'rgba(75, 192, 192, 0.8)', 'type': 'support'}
                ]
            }
        
        # Get CPR levels (latest available)
        cpr = CprLevel.query.filter_by(symbol=clean_symbol).order_by(CprLevel.date.desc()).first()
        if cpr:
            levels['cpr'] = {
                'type': 'CPR',
                'levels': [
                    {'label': 'R3', 'value': float(cpr.r3), 'color': 'rgba(153, 102, 255, 0.8)', 'type': 'resistance'},
                    {'label': 'R2', 'value': float(cpr.r2), 'color': 'rgba(153, 102, 255, 0.6)', 'type': 'resistance'},
                    {'label': 'R1', 'value': float(cpr.r1), 'color': 'rgba(153, 102, 255, 0.4)', 'type': 'resistance'},
                    {'label': 'TC', 'value': float(cpr.tc), 'color': 'rgba(255, 159, 64, 0.8)', 'type': 'pivot'},
                    {'label': 'PP', 'value': float(cpr.pp), 'color': 'rgba(255, 159, 64, 1.0)', 'type': 'pivot'},
                    {'label': 'BC', 'value': float(cpr.bc), 'color': 'rgba(255, 159, 64, 0.8)', 'type': 'pivot'},
                    {'label': 'S1', 'value': float(cpr.s1), 'color': 'rgba(54, 162, 235, 0.4)', 'type': 'support'},
                    {'label': 'S2', 'value': float(cpr.s2), 'color': 'rgba(54, 162, 235, 0.6)', 'type': 'support'},
                    {'label': 'S3', 'value': float(cpr.s3), 'color': 'rgba(54, 162, 235, 0.8)', 'type': 'support'}
                ]
            }
        
        # Get Fibonacci levels (latest available)
        fibonacci = FibonacciLevel.query.filter_by(symbol=clean_symbol).order_by(FibonacciLevel.date.desc()).first()
        if fibonacci:
            levels['fibonacci'] = {
                'type': 'Fibonacci',
                'levels': [
                    {'label': 'R3', 'value': float(fibonacci.r3_161), 'color': 'rgba(255, 99, 71, 0.8)', 'type': 'resistance'},
                    {'label': 'R2', 'value': float(fibonacci.r2_123), 'color': 'rgba(255, 99, 71, 0.6)', 'type': 'resistance'},
                    {'label': 'R1', 'value': float(fibonacci.r1_61), 'color': 'rgba(255, 99, 71, 0.4)', 'type': 'resistance'},
                    {'label': 'PP', 'value': float(fibonacci.pp), 'color': 'rgba(238, 130, 238, 0.8)', 'type': 'pivot'},
                    {'label': '50%', 'value': float(fibonacci.level_50), 'color': 'rgba(138, 43, 226, 0.6)', 'type': 'pivot'},
                    {'label': 'S1', 'value': float(fibonacci.s1_61), 'color': 'rgba(32, 178, 170, 0.4)', 'type': 'support'},
                    {'label': 'S2', 'value': float(fibonacci.s2_123), 'color': 'rgba(32, 178, 170, 0.6)', 'type': 'support'},
                    {'label': 'S3', 'value': float(fibonacci.s3_161), 'color': 'rgba(32, 178, 170, 0.8)', 'type': 'support'}
                ]
            }
        
        return jsonify({
            'status': 'success',
            'symbol': clean_symbol,
            'levels': levels
        })
        
    except Exception as e:
        logger.error(f"Error getting technical levels for {symbol}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/update-historical-levels', methods=['POST'])
@login_required
def update_historical_levels():
    """Calculate and update historical levels (PDH, PDL, WKH, WKL) for all symbols"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    result = _update_historical_levels_internal()
    return jsonify(result)

@app.route('/initialize-breaks-data', methods=['GET'])
def initialize_breaks_data():
    """Initialize historical levels for breaks table - public endpoint"""
    result = _update_historical_levels_internal()
    return jsonify(result)

def _update_historical_levels_internal():
    """Internal function to update historical levels"""
    try:
        from datetime import datetime, timedelta
        
        # Get current date
        current_date = datetime.utcnow().date()
        
        # Get previous trading day (skip weekends)
        previous_day = current_date - timedelta(days=1)
        while previous_day.weekday() >= 5:  # Skip Saturday (5) and Sunday (6)
            previous_day -= timedelta(days=1)
        
        updated_count = 0
        errors = []
        
        # Get all stock symbols
        stocks = StockData.query.all()
        
        for stock in stocks:
            try:
                # Get previous day's high and low (PDH, PDL) from hist_data_365
                prev_day_data = HistData365.query.filter(
                    HistData365.symbol == stock.symbol,
                    HistData365.date == previous_day
                ).first()
                
                # Get weekly high and low (WKH, WKL) from weekly_ohlc_data
                # Get current week's data first
                weekly_data = WeeklyOHLCData.query.filter(
                    WeeklyOHLCData.symbol == stock.symbol,
                    WeeklyOHLCData.week_start_date <= current_date,
                    WeeklyOHLCData.week_end_date >= current_date
                ).first()
                
                # If no current week data, get most recent weekly data
                if not weekly_data:
                    weekly_data = WeeklyOHLCData.query.filter(
                        WeeklyOHLCData.symbol == stock.symbol
                    ).order_by(WeeklyOHLCData.week_start_date.desc()).first()
                
                # Update the stock record with calculated levels
                stock.pdh = prev_day_data.high if prev_day_data else None
                stock.pdl = prev_day_data.low if prev_day_data else None
                stock.wkh = float(weekly_data.high_price) if weekly_data else None
                stock.wkl = float(weekly_data.low_price) if weekly_data else None
                
                stock.levels_updated_at = datetime.utcnow()
                updated_count += 1
                
            except Exception as e:
                error_msg = f"Error updating levels for {stock.symbol}: {str(e)}"
                logger.warning(error_msg)
                errors.append(error_msg)
                continue
        
        # Commit all changes
        db.session.commit()
        
        # Refresh WebSocket manager cache with new break levels
        global websocket_manager
        if websocket_manager:
            websocket_manager.refresh_break_levels_cache()
        
        logger.info(f"Updated historical levels for {updated_count} symbols")
        
        return {
            'status': 'success',
            'message': f'Updated historical levels for {updated_count} symbols',
            'updated_count': updated_count,
            'errors': errors,
            'error_count': len(errors)
        }
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating historical levels: {str(e)}")
        return {
            'status': 'error',
            'message': f'Error updating historical levels: {str(e)}'
        }

# Initialize historical levels flag
_historical_levels_initialized = False

def initialize_historical_levels():
    """Initialize historical levels once"""
    global _historical_levels_initialized
    if not _historical_levels_initialized:
        try:
            logger.info("🔄 Initializing historical levels on startup...")
            result = _update_historical_levels_internal()
            if result['status'] == 'success':
                logger.info(f"✅ Historical levels initialized: {result['updated_count']} symbols updated")
            else:
                logger.warning(f"⚠️ Historical levels initialization failed: {result['message']}")
            _historical_levels_initialized = True
        except Exception as e:
            logger.error(f"❌ Error initializing historical levels: {str(e)}")

@app.route('/admin/stop-streaming', methods=['POST'])
@login_required
def stop_streaming():
    """Stop WebSocket live streaming (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    global websocket_manager
    try:
        if websocket_manager:
            websocket_manager.disconnect()
            logger.info("Live streaming stopped by admin")
            return jsonify({'status': 'success', 'message': 'Live streaming stopped'})
        else:
            return jsonify({'status': 'error', 'message': 'No active streaming connection'})
    except Exception as e:
        logger.error(f"Error stopping streaming: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/start-streaming', methods=['POST'])
@login_required 
def start_streaming():
    """Start WebSocket live streaming (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    
    global websocket_manager
    try:
        # Check if already connected
        if websocket_manager and websocket_manager.is_connected:
            return jsonify({'status': 'success', 'message': 'Live streaming already active'})
        
        # Get access token from session
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'status': 'error', 'message': 'No access token available'})
        
        # Get WebSocket manager using centralized singleton
        websocket_manager = get_websocket_manager()
        
        # Ensure WebSocket is connected
        if websocket_manager:
            websocket_manager.connect()
        logger.info("Live streaming started by admin")
        return jsonify({'status': 'success', 'message': 'Live streaming started'})
    except Exception as e:
        logger.error(f"Error starting streaming: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    """Logout user and redirect to login"""
    # Note: WebSocket connection uses database tokens and should remain active
    # for all users regardless of individual logout events. The WebSocket manager
    # is shared globally and serves real-time data to all connected users.
    
    # Deactivate current user session before logout
    user_session_id = session.get('user_session_id')
    if user_session_id:
        try:
            user_session = UserSession.query.filter_by(
                session_id=user_session_id,
                is_active=True
            ).first()
            
            if user_session:
                user_session.is_active = False
                db.session.commit()
                logger.info(f"Deactivated session {user_session_id} for user {current_user.username} during logout")
                
        except Exception as e:
            logger.error(f"Error deactivating user session during logout: {str(e)}")
            db.session.rollback()
    
    # Logout user using Flask-Login
    logout_user()
    
    # Clear session but don't deactivate stored tokens  
    # This allows user to log back in without new token authentication
    session.clear()
    
    flash('You have been logged out', 'info')
    response = make_response(redirect(url_for('landing')))
    # Delete the remember me cookie
    response.set_cookie('remember_token', '', expires=0)
    response.set_cookie('session', '', expires=0)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/historical/fetch', methods=['POST'])
def fetch_historical():
    """Fetch historical data for symbols"""
    
    # Auto-authenticate if we have a valid token (like the api/data endpoint)
    if not session.get('authenticated'):
        token_result = fyers_auth.get_valid_token()
        if token_result['status'] == 'success':
            session['access_token'] = token_result['access_token']
            session['authenticated'] = True
        else:
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    global historical_manager
    # Always get the latest valid token from database for reliability
    token_result = fyers_auth.get_valid_token()
    if token_result['status'] == 'success':
        fresh_token = token_result['access_token']
        # Update session with valid token
        session['access_token'] = fresh_token
        # Reinitialize historical manager with fresh token
        historical_manager = HistoricalDataManager(fresh_token)
    elif session.get('access_token'):
        # Fallback to session token if stored token is not available
        historical_manager = HistoricalDataManager(session['access_token'])
    
    if not historical_manager:
        return jsonify({'status': 'error', 'message': 'Historical manager not initialized'}), 400
    
    try:
        data = request.get_json() or {}
        symbols = data.get('symbols', Config.NIFTY50_SYMBOLS)
        resolution = data.get('resolution', '1D')
        days_back = data.get('days_back', 30)
        
        # Validate resolution
        valid_resolutions = ['1', '5', '15', '30', '60', '240', '1D']
        if resolution not in valid_resolutions:
            return jsonify({
                'status': 'error', 
                'message': f'Invalid resolution. Valid options: {valid_resolutions}'
            }), 400
        
        # For admin auto-initialization, enable historical data fetching
        if data.get('auto_admin', False):
            # Limited historical fetch for admin auto-calculations
            limited_symbols = symbols[:10]  # Process first 10 symbols to avoid memory issues
            results = {}
            
            for symbol in limited_symbols:
                try:
                    from datetime import datetime, timedelta
                    now = datetime.now()
                    range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
                    range_from = range_to - timedelta(days=days_back)
                    
                    candles = historical_manager.fetch_historical_data(symbol, resolution, range_from, range_to)
                    if candles:
                        stored_count = historical_manager.store_historical_data(symbol, resolution, candles)
                        success = stored_count > 0
                    else:
                        success = False
                    results[symbol] = success
                except Exception as e:
                    logger.error(f"Error fetching historical data for {symbol}: {str(e)}")
                    results[symbol] = False
            
            return jsonify({
                'status': 'success',
                'message': f'Limited historical data fetched for admin calculations',
                'results': results
            })
        
        # Memory-safe batch processing for historical data - reduced batch size for better memory handling
        batch_size = data.get('batch_size', 5)  # Process 5 symbols at a time by default to prevent memory issues
        start_index = data.get('start_index', 0)  # Starting index for batch processing
        
        # Helper function to normalize symbol format for consistent comparison
        def normalize_symbol(symbol):
            return symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
        
        # Get symbols that don't have historical data yet (stored in display format)
        existing_symbols = set()
        try:
            existing_result = db.session.query(HistoricalData.symbol).distinct().all()
            existing_symbols = {row[0] for row in existing_result}  # Already in display format
        except:
            existing_symbols = set()
        
        # Normalize input symbols to display format for comparison
        all_symbols_normalized = {normalize_symbol(symbol) for symbol in symbols}
        
        # Find missing symbols (in display format)
        missing_symbols_normalized = all_symbols_normalized - existing_symbols
        
        # Convert back to raw format for API calls and sort for deterministic batching
        symbol_map = {normalize_symbol(symbol): symbol for symbol in symbols}
        missing_symbols = sorted([symbol_map[norm_symbol] for norm_symbol in missing_symbols_normalized])
        
        if not missing_symbols:
            return jsonify({
                'status': 'success',
                'message': f'All {len(symbols)} symbols already have historical data',
                'total_symbols': len(symbols),
                'missing_symbols': 0,
                'results': {}
            })
        
        # Process batch of missing symbols
        end_index = min(start_index + batch_size, len(missing_symbols))
        batch_symbols = missing_symbols[start_index:end_index]
        
        # Define 'now' before it's used
        from datetime import datetime, timedelta
        now = datetime.now()
        
        # Show progress less frequently - only every 5 batches or for first/last batch
        batch_number = start_index//batch_size + 1
        total_batches = (len(missing_symbols) + batch_size - 1) // batch_size
        if batch_number == 1 or batch_number == total_batches or batch_number % 5 == 0:
            # Calculate expected date range for the batch
            range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
            range_from = range_to - timedelta(days=days_back)
            expected_candles = days_back  # Approximate candles for daily data
            logger.info(f"📈 Processing batch {batch_number}/{total_batches} (symbols {start_index+1}-{end_index} of {len(missing_symbols)}) | Date range: {range_from.strftime('%Y-%m-%d')} to {range_to.strftime('%Y-%m-%d')} | Expected ~{expected_candles} candles per symbol")
        
        results = {}
        successful_count = 0
        
        for symbol in batch_symbols:
            try:
                from datetime import datetime, timedelta
                now = datetime.now()
                range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
                range_from = range_to - timedelta(days=days_back)
                
                candles = historical_manager.fetch_historical_data(symbol, resolution, range_from, range_to)
                if candles:
                    candle_count = len(candles)
                    stored_count = historical_manager.store_historical_data(symbol, resolution, candles)
                    success = stored_count > 0
                    if success:
                        successful_count += 1
                        logger.debug(f"✅ {symbol}: {candle_count} candles fetched, {stored_count} stored ({range_from.strftime('%Y-%m-%d')} to {range_to.strftime('%Y-%m-%d')})")
                else:
                    logger.debug(f"❌ {symbol}: No candles received ({range_from.strftime('%Y-%m-%d')} to {range_to.strftime('%Y-%m-%d')})")
                    success = False
                results[symbol] = success
                
                # Longer delay between requests to prevent API throttling and reduce memory pressure
                import time
                time.sleep(0.5)  # Increased delay for better memory management
                
            except Exception as e:
                logger.error(f"Error fetching historical data for {symbol}: {str(e)}")
                results[symbol] = False
        
        # Calculate progress
        total_processed = end_index
        remaining_symbols = len(missing_symbols) - total_processed
        next_start_index = end_index if remaining_symbols > 0 else None
        
        # Calculate next batch symbols for frontend to show "Fetching" messages
        next_batch_symbols = []
        if next_start_index is not None:
            next_end_index = min(next_start_index + batch_size, len(missing_symbols))
            next_batch_symbols = missing_symbols[next_start_index:next_end_index]
        
        return jsonify({
            'status': 'success',
            'message': f'Batch completed: {successful_count}/{len(batch_symbols)} symbols successful',
            'total_symbols': len(symbols),
            'existing_symbols': len(existing_symbols),
            'missing_symbols_count': len(missing_symbols),  # Return count as number, not array
            'processed_in_batch': len(batch_symbols),
            'successful_in_batch': successful_count,
            'total_processed': total_processed,
            'remaining_symbols': remaining_symbols,
            'next_start_index': next_start_index,
            'progress_percentage': round((total_processed / len(missing_symbols)) * 100, 1),
            'current_symbols': batch_symbols,  # Current batch symbols for "Completed" messages
            'next_batch_symbols': next_batch_symbols,  # Next batch symbols for "Fetching" messages
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error fetching historical data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/historical/data/<symbol>')
def get_historical(symbol):
    """Get historical data for a symbol"""
    
    # Auto-authenticate if we have a valid token
    if not session.get('authenticated'):
        token_result = fyers_auth.get_valid_token()
        if token_result['status'] == 'success':
            session['access_token'] = token_result['access_token']
            session['authenticated'] = True
        else:
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    global historical_manager
    if not historical_manager and session.get('access_token'):
        # Initialize if not already done
        historical_manager = HistoricalDataManager(session['access_token'])
    
    if not historical_manager:
        return jsonify({'status': 'error', 'message': 'Historical manager not initialized'}), 400
    
    try:
        resolution = request.args.get('resolution', '1D')
        limit = int(request.args.get('limit', 100))
        
        data = historical_manager.get_historical_data(symbol, resolution, limit)
        
        return jsonify({
            'status': 'success',
            'symbol': symbol,
            'resolution': resolution,
            'data': data
        })
        
    except Exception as e:
        logger.error(f"Error getting historical data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/historical/logs')
def get_fetch_logs():
    """Get historical data fetch logs"""
    if not session.get('authenticated'):
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    global historical_manager
    if not historical_manager and session.get('access_token'):
        # Initialize if not already done
        historical_manager = HistoricalDataManager(session['access_token'])
    
    if not historical_manager:
        return jsonify({'status': 'error', 'message': 'Historical manager not initialized'}), 400
    
    try:
        limit = int(request.args.get('limit', 50))
        logs = historical_manager.get_fetch_logs(limit)
        
        return jsonify({
            'status': 'success',
            'logs': logs
        })
        
    except Exception as e:
        logger.error(f"Error getting fetch logs: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/force-camarilla-rebuild', methods=['POST'])
@login_required
def admin_force_camarilla_rebuild():
    """Admin endpoint to force Camarilla rebuild with new data source priority (admin access required)"""
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    try:
        from camarilla_calculator import CamarillaCalculator
        
        # Create local calculator instance since globals aren't initialized to save memory
        camarilla_calculator = CamarillaCalculator()
        
        # Get all symbols from historical data like the regular endpoint
        symbols_with_data = db.session.query(HistoricalData.symbol).distinct().all()
        symbols = [symbol[0] for symbol in symbols_with_data]
        
        if not symbols:
            return jsonify({'success': False, 'message': 'No symbols found in historical data'}), 400
        
        # Force rebuild all Camarilla levels with new data source priority
        results = camarilla_calculator.calculate_and_store_levels(symbols)
        
        if results:
            return jsonify({
                'success': True,
                'message': 'ADMIN: Emergency Camarilla rebuild completed using daily_ohlc_data priority',
                'emergency_rebuild': True
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to rebuild Camarilla levels'}), 500
        
    except Exception as e:
        logger.error(f"Error in admin force Camarilla rebuild: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/camarilla/calculate', methods=['POST'])
def calculate_camarilla_levels():
    """Calculate Camarilla levels for all stocks with historical data"""
    if not current_user.is_authenticated:
        return jsonify({'status': 'error', 'message': 'Please login first'}), 401
    
    try:
        from camarilla_calculator import CamarillaCalculator
        
        # Create local calculator instance since globals aren't initialized to save memory
        camarilla_calculator = CamarillaCalculator()
        
        # Get ALL symbols from WebSocket manager (all 228 symbols), not just HistoricalData (75 symbols)
        global websocket_manager
        if websocket_manager:
            # Use all symbols that WebSocket is tracking (228 symbols)
            symbols_from_websocket = list(websocket_manager.get_latest_data().keys())
            if symbols_from_websocket:
                # Clean symbols to display format for calculations
                symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in symbols_from_websocket]
                logger.info(f"Camarilla: Processing {len(symbols)} symbols from WebSocket manager")
            else:
                # Fallback to Config symbols if WebSocket not populated yet
                from config import Config
                symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                logger.info(f"Camarilla: WebSocket empty, using Config symbols: {len(symbols)}")
        else:
            # Final fallback to Config if no WebSocket
            from config import Config  
            symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
            logger.info(f"Camarilla: No WebSocket, using Config symbols: {len(symbols)}")
        
        if not symbols:
            return jsonify({
                'status': 'error',
                'message': 'No symbols available for calculation. Please ensure WebSocket is connected.'
            })
        
        # Calculate and store levels for symbols with historical data
        results = camarilla_calculator.calculate_and_store_levels(symbols)
        
        successful_count = len([k for k, v in results.items() if v])
        total_count = len(results)
        
        logger.info(f"Camarilla calculation completed: {successful_count}/{total_count} stocks successful")
        
        return jsonify({
            'status': 'success',
            'message': f'Calculated Camarilla levels for {successful_count}/{total_count} stocks. Live data continues normally.',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error calculating Camarilla levels: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/camarilla/data')
def get_camarilla_data():
    """Get all Camarilla levels data in uniform symbol order (Index first, then F&O alphabetically)"""
    # Allow public access for displaying Camarilla data
    # Authentication no longer required for viewing data
    # if not current_user.is_authenticated:
    #     return jsonify({'status': 'error', 'message': 'Please login to view data'}), 401
    
    try:
        from models import CamarillaLevels
        from config import Config
        global websocket_manager
        
        # Get latest Camarilla data for each symbol with error handling
        try:
            # Get the most recent record for each symbol
            subquery = db.session.query(
                CamarillaLevels.symbol,
                db.func.max(CamarillaLevels.updated_at).label('max_updated')
            ).group_by(CamarillaLevels.symbol).subquery()
            
            cam_records = db.session.query(CamarillaLevels).join(
                subquery,
                (CamarillaLevels.symbol == subquery.c.symbol) &
                (CamarillaLevels.updated_at == subquery.c.max_updated)
            ).all()
        except Exception as query_error:
            logger.error(f"Database query failed: {str(query_error)}")
            return jsonify({'status': 'error', 'message': 'Database query failed', 'data': []}), 500
        
        # Performance optimization: Cache WebSocket data once and reuse calculator
        cached_websocket_data = {}
        if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
            cached_websocket_data = websocket_manager.stock_data.copy()
        
        # Reuse single CamarillaCalculator instance for all records
        from camarilla_calculator import CamarillaCalculator
        camarilla_calc = CamarillaCalculator()
        
        # Create a mapping of symbols to records for uniform ordering
        symbol_to_record = {}
        for record in cam_records:
            symbol_to_record[record.symbol] = record
        
        # Order data according to Config.NIFTY50_SYMBOLS (Index first, then F&O alphabetically)
        cam_data = []
        for full_symbol in Config.NIFTY50_SYMBOLS:
            # Extract clean symbol name from full symbol
            clean_symbol = full_symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            if clean_symbol in symbol_to_record:
                record = symbol_to_record[clean_symbol]
                data = record.to_dict()
                
                # Fix full_symbol format - ensure correct NSE:SYMBOL-EQ format
                if 'NIFTY' in record.symbol.upper() or 'VIX' in record.symbol.upper():
                    corrected_full_symbol = f"NSE:{record.symbol}-INDEX"
                elif 'SENSEX' in record.symbol.upper():
                    corrected_full_symbol = f"BSE:{record.symbol}-INDEX"
                else:
                    corrected_full_symbol = f"NSE:{record.symbol}-EQ"
                
                # Override the database full_symbol with correct format
                data['full_symbol'] = corrected_full_symbol
                
                # Always include database current_ltp, then update with live data if available
                if not data.get('current_ltp'):
                    data['current_ltp'] = getattr(record, 'current_ltp', 0) or 0
                
                # Update with live WebSocket LTP if available (using cached data)
                if cached_websocket_data and corrected_full_symbol in cached_websocket_data:
                    live_ltp = cached_websocket_data[corrected_full_symbol].get('ltp')
                    if live_ltp:
                        data['current_ltp'] = live_ltp
                
                # Calculate break level in memory only (no database writes)
                if data['current_ltp'] and data['current_ltp'] > 0:
                    levels = {
                        'r5': record.r5, 'r4': record.r4, 'r3': record.r3, 'r2': record.r2, 'r1': record.r1,
                        's1': record.s1, 's2': record.s2, 's3': record.s3, 's4': record.s4, 's5': record.s5
                    }
                    data['break_level'] = camarilla_calc.determine_break_level(data['current_ltp'], levels)
                else:
                    data['break_level'] = record.break_level or 'None'
                
                cam_data.append(data)
        
        response = jsonify({
            'success': True,
            'data': cam_data
        })
        
        # Add cache-busting headers to force refresh
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting Camarilla data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/camarilla/update/<symbol>', methods=['POST'])
def update_camarilla_status(symbol):
    """Update current status for a specific symbol"""
    if not session.get('authenticated'):
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        current_ltp = data.get('ltp')
        
        if not current_ltp:
            return jsonify({'status': 'error', 'message': 'LTP is required'}), 400
        
        success = camarilla_calculator.update_current_status(symbol, float(current_ltp))
        
        if success:
            return jsonify({'status': 'success', 'message': 'Status updated'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to update status'}), 400
        
    except Exception as e:
        logger.error(f"Error updating Camarilla status: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/force-cpr-rebuild', methods=['POST'])
@login_required
def admin_force_cpr_rebuild():
    """Admin endpoint to force CPR rebuild with new data source priority (admin access required)"""
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    try:
        from cpr_calculator import CprCalculator
        global websocket_manager
        
        # Create local calculator instance since globals aren't initialized to save memory
        cpr_calculator = CprCalculator()
        
        # Force rebuild all CPR levels with new data source priority logic
        results = cpr_calculator.calculate_and_store_levels_batch(websocket_manager=websocket_manager)
        
        calculated_count = len([k for k, v in results.items() if v])
        total_symbols = len(results)
        
        return jsonify({
            'success': True,
            'message': f'ADMIN: Emergency CPR rebuild completed for {calculated_count}/{total_symbols} symbols using daily_ohlc_data priority',
            'count': calculated_count,
            'emergency_rebuild': True
        })
        
    except Exception as e:
        logger.error(f"Error in admin force CPR rebuild: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/calculate_cpr', methods=['POST'])
def calculate_cpr_levels():
    """Calculate CPR levels for all stocks with historical data"""
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin access required for calculations'}), 403
    
    # Allow any logged-in user to calculate CPR levels
    # if not session.get('authenticated'):
    #     return jsonify({'success': False, 'message': 'Fyers API authentication required for calculations'}), 401
    
    try:
        from cpr_calculator import CprCalculator
        global websocket_manager
        
        # Create local calculator instance since globals aren't initialized to save memory
        cpr_calculator = CprCalculator()
        
        # Use batch processing to calculate CPR levels - eliminates N+1 query pattern
        results = cpr_calculator.calculate_and_store_levels_batch(websocket_manager=websocket_manager)
        
        # Count successful calculations
        calculated_count = len([k for k, v in results.items() if v])
        total_symbols = len(results)
        
        if calculated_count == 0:
            return jsonify({
                'success': False,
                'message': 'No CPR levels could be calculated. Please ensure historical data is available.'
            }), 400
        
        # Get current CPR data for response
        try:
            from models import CprLevel
            from datetime import date
            today = date.today()
            cpr_records = CprLevel.query.filter_by(date=today).all()
            cpr_data = [record.to_dict() for record in cpr_records]
        except Exception as e:
            logger.warning(f"Error fetching CPR data for response: {str(e)}")
            cpr_data = []
        
        return jsonify({
            'success': True,
            'message': f'CPR levels calculated for {calculated_count}/{total_symbols} symbols using batch processing',
            'count': calculated_count,
            'data': cpr_data
        })
        
    except Exception as e:
        logger.error(f"Error calculating CPR levels: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get_cpr_data')
def get_cpr_data():
    """Get all CPR levels data in uniform symbol order (Index first, then F&O alphabetically)"""
    # Allow public access for displaying CPR data
    # Authentication no longer required for viewing data
    # if not current_user.is_authenticated:
    #     return jsonify({'success': False, 'message': 'Please login to view data'}), 401
    
    try:
        from models import CprLevel
        from config import Config
        from datetime import date
        global websocket_manager
        
        # PERFORMANCE FIX: Get only latest CPR data for each symbol (filter by today's date or most recent)
        subquery = db.session.query(
            CprLevel.symbol,
            db.func.max(CprLevel.date).label('max_date')
        ).group_by(CprLevel.symbol).subquery()
        
        cpr_records = db.session.query(CprLevel).join(
            subquery,
            (CprLevel.symbol == subquery.c.symbol) &
            (CprLevel.date == subquery.c.max_date)
        ).all()
        
        # Create a mapping of symbols to records for uniform ordering
        symbol_to_record = {}
        for record in cpr_records:
            symbol_to_record[record.symbol] = record
        
        # Order data according to Config.NIFTY50_SYMBOLS (Index first, then F&O alphabetically)
        cpr_data = []
        for full_symbol in Config.NIFTY50_SYMBOLS:
            # Extract clean symbol name from full symbol
            clean_symbol = full_symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            if clean_symbol in symbol_to_record:
                record = symbol_to_record[clean_symbol]
                data = record.to_dict()
                
                # Fix full_symbol format - ensure correct NSE:SYMBOL-EQ format
                if 'NIFTY' in record.symbol.upper() or 'VIX' in record.symbol.upper():
                    corrected_full_symbol = f"NSE:{record.symbol}-INDEX"
                elif 'SENSEX' in record.symbol.upper():
                    corrected_full_symbol = f"BSE:{record.symbol}-INDEX"
                else:
                    corrected_full_symbol = f"NSE:{record.symbol}-EQ"
                
                data['full_symbol'] = corrected_full_symbol
                
                # Update with current LTP if available (convert symbol format)  
                current_ltp = None
                if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                    # WebSocket stores data with full symbol format, database uses clean symbols
                    if corrected_full_symbol in websocket_manager.stock_data:
                        current_ltp = websocket_manager.stock_data[corrected_full_symbol].get('ltp')
                
                if current_ltp:
                    data['current_ltp'] = current_ltp
                    
                    # Update break level in real-time
                    # Determine break level directly from record data
                    break_level = None
                    if current_ltp > record.r3:
                        break_level = 'R3'
                    elif current_ltp > record.r2:
                        break_level = 'R2'
                    elif current_ltp > record.r1:
                        break_level = 'R1'
                    elif current_ltp > record.tc:
                        break_level = 'TC'
                    elif current_ltp < record.s3:
                        break_level = 'S3'
                    elif current_ltp < record.s2:
                        break_level = 'S2'
                    elif current_ltp < record.s1:
                        break_level = 'S1'
                    elif current_ltp < record.bc:
                        break_level = 'BC'
                    elif record.bc <= current_ltp <= record.tc:
                        break_level = 'CPR'
                    else:
                        break_level = None
                    
                    data['break_level'] = break_level
                
                cpr_data.append(data)
        
        response = jsonify({
            'success': True,
            'data': cpr_data
        })
        
        # Add cache-busting headers to force refresh
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting CPR data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/calculate_fibonacci', methods=['POST'])
def calculate_fibonacci_levels():
    """Calculate Fibonacci levels for all stocks with historical data"""
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Admin access required for calculations'}), 403
    
    try:
        from fibonacci_calculator import FibonacciCalculator
        global websocket_manager
        
        # Create local calculator instance since globals aren't initialized to save memory
        fibonacci_calculator = FibonacciCalculator()
        
        # Use batch processing to calculate Fibonacci levels - eliminates N+1 query pattern
        results = fibonacci_calculator.calculate_and_store_levels_batch(websocket_manager=websocket_manager)
        
        # Count successful calculations
        calculated_count = len([k for k, v in results.items() if v])
        total_symbols = len(results)
        
        if calculated_count == 0:
            return jsonify({
                'success': False,
                'message': 'No Fibonacci levels could be calculated. Please ensure historical data is available.'
            }), 400
        
        # Get current Fibonacci data for response
        try:
            from models import FibonacciLevel
            from datetime import date
            today = date.today()
            fib_records = FibonacciLevel.query.filter_by(date=today).all()
            fib_data = [record.to_dict() for record in fib_records]
        except Exception as e:
            logger.warning(f"Error fetching Fibonacci data for response: {str(e)}")
            fib_data = []
        
        return jsonify({
            'success': True,
            'message': f'Fibonacci levels calculated for {calculated_count}/{total_symbols} symbols using batch processing',
            'count': calculated_count,
            'data': fib_data
        })
        
    except Exception as e:
        logger.error(f"Error calculating Fibonacci levels: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get_fibonacci_data')
def get_fibonacci_data():
    """Get all Fibonacci levels data in uniform symbol order (Index first, then F&O alphabetically)"""
    # Allow public access for displaying Fibonacci data
    # Authentication no longer required for viewing data
    # if not current_user.is_authenticated:
    #     return jsonify({'success': False, 'message': 'Please login to view data'}), 401
    
    try:
        from models import FibonacciLevel
        from config import Config
        from datetime import date
        global websocket_manager
        
        # PERFORMANCE FIX: Get only latest Fibonacci data for each symbol (filter by date or most recent)
        subquery = db.session.query(
            FibonacciLevel.symbol,
            db.func.max(FibonacciLevel.date).label('max_date')
        ).group_by(FibonacciLevel.symbol).subquery()
        
        fib_records = db.session.query(FibonacciLevel).join(
            subquery,
            (FibonacciLevel.symbol == subquery.c.symbol) &
            (FibonacciLevel.date == subquery.c.max_date)
        ).all()
        
        # Create a mapping of symbols to records for uniform ordering
        symbol_to_record = {}
        for record in fib_records:
            symbol_to_record[record.symbol] = record
        
        # Order data according to Config.NIFTY50_SYMBOLS (Index first, then F&O alphabetically)
        fib_data = []
        for full_symbol in Config.NIFTY50_SYMBOLS:
            # Extract clean symbol name from full symbol
            clean_symbol = full_symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            if clean_symbol in symbol_to_record:
                record = symbol_to_record[clean_symbol]
                data = record.to_dict()
                
                # Fix full_symbol format - ensure correct NSE:SYMBOL-EQ format  
                if 'NIFTY' in record.symbol.upper() or 'VIX' in record.symbol.upper():
                    corrected_full_symbol = f"NSE:{record.symbol}-INDEX"
                elif 'SENSEX' in record.symbol.upper():
                    corrected_full_symbol = f"BSE:{record.symbol}-INDEX"
                else:
                    corrected_full_symbol = f"NSE:{record.symbol}-EQ"
                
                data['full_symbol'] = corrected_full_symbol
                
                # Update with current LTP if available (convert symbol format)
                current_ltp = None
                if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                    # WebSocket stores data with full symbol format, database uses clean symbols
                    if corrected_full_symbol in websocket_manager.stock_data:
                        current_ltp = websocket_manager.stock_data[corrected_full_symbol].get('ltp')
                    if current_ltp:
                        data['current_ltp'] = current_ltp
                        
                        # Update break level and trend in real-time
                        from fibonacci_calculator import fibonacci_calculator
                        break_level = fibonacci_calculator.determine_break_level(record.symbol, current_ltp)
                        data['break_level'] = break_level
                        # Trend direction removed as not displayed in table
                
                fib_data.append(data)
        
        response = jsonify({
            'success': True,
            'data': fib_data
        })
        
        # Add cache-busting headers to force refresh
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting Fibonacci data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


def init_database():
    """Initialize database tables and default users"""
    try:
        with app.app_context():
            db.create_all()
            
            # Create default admin user if it doesn't exist
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User()
                admin_user.username = 'admin'
                admin_user.role = 'admin'
                admin_user.email = 'marketguldasta@gmail.com'
                admin_user.mobile = '+1234567890'
                admin_user.subscription_period = 'lifetime'
                admin_user.set_password('Admin@2025')
                db.session.add(admin_user)
                logger.info("Created default admin user with email: marketguldasta@gmail.com")
            
            # Create default regular user if it doesn't exist
            regular_user = User.query.filter_by(username='user').first()
            if not regular_user:
                regular_user = User()
                regular_user.username = 'user'
                regular_user.role = 'user'
                regular_user.email = 'user@stockdashboard.com'
                regular_user.subscription_period = 'monthly'
                regular_user.set_password('password')
                db.session.add(regular_user)
                logger.info("Created default user: user/password")
            
            # Create 5 additional test users
            test_users = [
                {'username': 'user001', 'password': 'pass001', 'email': 'user001@stockdashboard.com'},
                {'username': 'user002', 'password': 'pass002', 'email': 'user002@stockdashboard.com'},
                {'username': 'user003', 'password': 'pass003', 'email': 'user003@stockdashboard.com'},
                {'username': 'user004', 'password': 'pass004', 'email': 'user004@stockdashboard.com'},
                {'username': 'user005', 'password': 'pass005', 'email': 'user005@stockdashboard.com'}
            ]
            
            for user_data in test_users:
                existing_user = User.query.filter_by(username=user_data['username']).first()
                if not existing_user:
                    new_user = User()
                    new_user.username = user_data['username']
                    new_user.role = 'user'
                    new_user.email = user_data['email']
                    new_user.subscription_period = 'monthly'
                    new_user.set_password(user_data['password'])
                    db.session.add(new_user)
                    logger.info(f"Created test user: {user_data['username']}/{user_data['password']}")
            
            db.session.commit()
            logger.info("Default users initialized")
            
            # Technical analysis initialization disabled to prevent memory issues on startup
            # Users can manually trigger technical analysis calculations if needed
            logger.info("App-wide technical analysis initialization skipped to prevent memory overload")
            
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")

# Define startup technical analysis function before database initialization
def startup_initialize_technical_data():
    """Initialize technical analysis data on app startup for all users"""
    logger.info("App startup technical data initialization...")
    
    try:
        # Check if any historical data exists
        historical_count = db.session.query(HistoricalData).filter_by(resolution='1D').count()
        logger.info(f"Current historical records: {historical_count}")
        
        # Only proceed with technical calculations if we have any historical data
        if historical_count > 0:
            logger.info("Historical data found, calculating technical levels...")
            
            # Technical analysis disabled - manual calculation only via admin Calculate buttons
            logger.info("Camarilla levels can be calculated manually via admin Calculate buttons.")
            
            # Technical analysis disabled - manual calculation only via admin Calculate buttons
            logger.info("CPR and Fibonacci levels can be calculated manually via admin Calculate buttons.")
            
        else:
            logger.info("No historical data available for technical calculations")
            logger.info("Technical levels will be calculated when historical data is available")
    
    except Exception as e:
        logger.warning(f"Startup technical data initialization error: {str(e)}")
        logger.info("App will continue without pre-calculated technical data")


# Background historical data fetching system
background_fetch_active = False
background_fetch_thread = None

def background_historical_data_fetcher():
    """Automatically fetch historical data for missing symbols in background"""
    global background_fetch_active
    background_fetch_active = True
    
    logger.info("🚀 Background historical data fetcher started")
    
    def normalize_symbol(symbol):
        """Normalize symbol to display format for consistent comparison"""
        return symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
    
    processed_count = 0
    # Critical: Wrap entire background worker in Flask app context
    with app.app_context():
        while background_fetch_active:
            try:
                # Get valid token for historical data fetching
                token_result = fyers_auth.get_valid_token()
                if token_result['status'] != 'success':
                    logger.warning("No valid token available, waiting...")
                    time.sleep(30)  # Wait before retry
                    continue
                
                access_token = token_result['access_token']
                hist_manager = HistoricalDataManager(access_token)
                
                # Get existing symbols from database (normalized format)
                existing_symbols = set()
                existing_records = db.session.query(HistoricalData.symbol).filter_by(resolution='1D').distinct().all()
                for record in existing_records:
                    existing_symbols.add(normalize_symbol(record[0]))
                
                # Get all F&O symbols and normalize them
                all_symbols = Config.NIFTY50_SYMBOLS
                normalized_all_symbols = [normalize_symbol(symbol) for symbol in all_symbols]
                symbol_mapping = {normalize_symbol(symbol): symbol for symbol in all_symbols}
                
                # Find missing symbols (normalized comparison)
                missing_normalized = [sym for sym in normalized_all_symbols if sym not in existing_symbols]
                
                if not missing_normalized:
                    logger.info("✅ All symbols have historical data! Background fetcher complete.")
                    break
                
                # Process one symbol at a time to avoid timeouts
                symbol_display = missing_normalized[0]
                symbol_raw = symbol_mapping[symbol_display]
                
                logger.info(f"📈 Fetching historical data for {symbol_display} ({processed_count + 1}/224)")
                
                # Fetch 30 days of historical data
                now = datetime.now()
                range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
                range_from = range_to - timedelta(days=30)
                
                # Fetch historical data
                candles = hist_manager.fetch_historical_data(
                    symbol_raw, '1D', range_from, range_to
                )
                
                if candles and len(candles) > 0:
                    # Store the data
                    stored_count = hist_manager.store_historical_data(symbol_raw, '1D', candles)
                    if stored_count > 0:
                        processed_count += 1
                        logger.info(f"✅ Successfully stored {stored_count} records for {symbol_display}")
                        
                        # Technical analysis disabled - manual calculation only via admin Calculate buttons
                        logger.info(f"📊 Historical data stored for {symbol_display}. Technical levels can be calculated manually via admin Calculate buttons.")
                    else:
                        logger.warning(f"❌ Failed to store data for {symbol_display}")
                else:
                    logger.warning(f"❌ No data received for {symbol_display}")
                
                # Progress update
                remaining = len(missing_normalized) - 1
                logger.info(f"📊 Progress: {processed_count} completed, {remaining} remaining")
                
                # Wait between requests to avoid API rate limits and reduce server load
                time.sleep(2)  # 2-second delay between symbols
                
            except Exception as e:
                logger.error(f"Background fetcher error: {str(e)}")
                time.sleep(5)  # Wait before retry on error
    
    logger.info(f"🎉 Background historical data fetcher completed! Processed {processed_count} symbols")

def start_background_historical_fetcher_for_admin():
    """Start the background historical data fetcher for admin users only if needed"""
    global background_fetch_thread, background_fetch_active
    
    # Check if background fetcher is already running
    if background_fetch_thread and background_fetch_thread.is_alive():
        logger.info("Background fetcher already running")
        return
    
    # Check if all symbols already have historical data
    def normalize_symbol(symbol):
        return symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
    
    try:
        # Get existing symbols from database (normalized format)
        existing_symbols = set()
        existing_records = db.session.query(HistoricalData.symbol).filter_by(resolution='1D').distinct().all()
        for record in existing_records:
            existing_symbols.add(normalize_symbol(record[0]))
        
        # Get all F&O symbols and normalize them  
        all_symbols = Config.NIFTY50_SYMBOLS
        normalized_all_symbols = [normalize_symbol(symbol) for symbol in all_symbols]
        
        # Find missing symbols
        missing_symbols = [sym for sym in normalized_all_symbols if sym not in existing_symbols]
        
        if not missing_symbols:
            logger.info("✅ All 224 symbols already have historical data! Background fetcher not needed.")
            return
        
        logger.info(f"📊 Found {len(missing_symbols)} symbols missing historical data. Starting background fetcher...")
        
    except Exception as e:
        logger.error(f"Error checking existing symbols: {str(e)}")
        logger.info("Starting background fetcher as a precaution...")
    
    # Check if we have a valid token before starting
    token_result = fyers_auth.get_valid_token()
    if token_result['status'] == 'success':
        background_fetch_thread = threading.Thread(
            target=background_historical_data_fetcher,
            daemon=True,  # Dies when main process dies
            name="HistoricalDataFetcher"
        )
        background_fetch_thread.start()
        logger.info("🚀 Background historical data fetcher thread started for admin user")
    else:
        logger.info("No valid token available - background fetcher will start after authentication")

def stop_background_historical_fetcher():
    """Stop the background historical data fetcher"""
    global background_fetch_active
    background_fetch_active = False
    logger.info("Background historical data fetcher stopped")

# Initialize database on startup
init_database()

# Database will be initialized when first needed


def initialize_technical_analysis():
    """Initialize technical analysis calculations for all users with data validation"""
    logger.info("Starting technical analysis initialization with data validation...")
    
    try:
        with app.app_context():
            # Step 1: Check if historical data exists, if not for admin users with tokens - fetch some
            historical_data_count = db.session.query(HistoricalData).filter_by(resolution='1D').count()
            logger.info(f"Found {historical_data_count} daily historical records in database")
            
            # For admin users with historical manager, ensure we have some recent data
            if current_user.is_admin() and historical_manager and historical_data_count < 50:
                logger.info("Admin user with low historical data count, fetching essential data...")
                try:
                    from datetime import datetime, timedelta
                    
                    # Fetch last 3 days for top symbols only (quick initialization)
                    essential_symbols = Config.NIFTY50_SYMBOLS[:20]  # Top 20 symbols only
                    fetch_results = historical_manager.fetch_bulk_historical_data(
                        essential_symbols, '1D', 3  # Just 3 days for quick init
                    )
                    fetch_count = len([v for v in fetch_results.values() if v])
                    logger.info(f"Essential data fetch: {fetch_count}/{len(essential_symbols)} symbols")
                except Exception as e:
                    logger.warning(f"Essential data fetch failed: {str(e)}")
            
            # Step 2: Calculate technical levels only if we have historical data
            symbols_with_data = db.session.query(HistoricalData.symbol).filter_by(resolution='1D').distinct().all()
            
            if symbols_with_data:
                logger.info(f"Calculating technical levels for {len(symbols_with_data)} symbols with historical data")
                
                # Technical analysis disabled - manual calculation only via admin Calculate buttons
                logger.info("Technical levels (Camarilla, CPR, Fibonacci) can be calculated manually via admin Calculate buttons.")
                
                # Calculate CPR levels using historical data
                from cpr_calculator import CprCalculator
                cpr_calculator = CprCalculator()
                cpr_count = 0
                
                for symbol_row in symbols_with_data:  # Process all symbols with historical data
                    symbol = symbol_row[0]
                    prev_ohlc = cpr_calculator.get_previous_day_ohlc(symbol)
                    if prev_ohlc:
                        levels = cpr_calculator.calculate_cpr_levels(
                            symbol, prev_ohlc['high'], prev_ohlc['low'], prev_ohlc['close']
                        )
                        if levels:
                            # Get current LTP if available
                            current_ltp = None
                            if websocket_manager and hasattr(websocket_manager, 'stock_data'):
                                full_symbol = f"NSE:{symbol}-EQ"
                                if full_symbol in websocket_manager.stock_data:
                                    current_ltp = websocket_manager.stock_data[full_symbol].get('ltp')
                            
                            if cpr_calculator.save_to_database(symbol, current_ltp):
                                cpr_count += 1
                
                logger.info(f"CPR levels calculated: {cpr_count}")
                
                # Calculate Fibonacci levels using historical data
                from fibonacci_calculator import FibonacciCalculator
                fib_calculator = FibonacciCalculator()
                fib_count = 0
                
                for symbol_row in symbols_with_data[:25]:  # Limit to 25 symbols
                    symbol = symbol_row[0]
                    prev_ohlc = fib_calculator.get_previous_day_ohlc(symbol)
                    if prev_ohlc:
                        levels = fib_calculator.calculate_fibonacci_levels(
                            symbol, prev_ohlc['high'], prev_ohlc['low'], prev_ohlc['close']
                        )
                        if levels:
                            current_ltp = None
                            if websocket_manager and hasattr(websocket_manager, 'stock_data'):
                                full_symbol = f"NSE:{symbol}-EQ"
                                if full_symbol in websocket_manager.stock_data:
                                    current_ltp = websocket_manager.stock_data[full_symbol].get('ltp')
                            
                            if fib_calculator.save_to_database(symbol, current_ltp):
                                fib_count += 1
                
                logger.info(f"Fibonacci levels calculated: {fib_count}")
                
            else:
                logger.info("No historical data available - technical calculations skipped")
                logger.info("Note: Users need Fyers API authentication to fetch historical data")
    
    except Exception as e:
        logger.error(f"Technical analysis initialization error: {str(e)}")


def auto_initialize_admin_features():
    """Auto-initialize technical analysis features for admin users"""
    logger.info("Starting auto-initialization of admin features...")
    
    try:
        def background_calculations():
            """Run calculations in background thread"""
            try:
                # Step 1: Auto-fetch historical data for calculations
                logger.info("Auto-fetching historical data...")
                global historical_manager
                if historical_manager:
                    try:
                        # Direct historical data fetching with app context
                        from datetime import datetime, timedelta
                        
                        # Use Flask app context for database operations
                        with app.app_context():
                            now = datetime.now()
                            range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
                            range_from = range_to - timedelta(days=5)
                            
                            # Use bulk fetching for much better performance  
                            fetch_results = historical_manager.fetch_bulk_historical_data(
                                Config.NIFTY50_SYMBOLS, '1D', 5
                            )
                            fetch_count = len([v for v in fetch_results.values() if v])
                            logger.info(f"Bulk fetch completed: {fetch_count}/{len(fetch_results)} symbols successful")
                    except Exception as e:
                        logger.warning(f"Historical data fetch failed: {str(e)}")
                
                # Step 2: Technical analysis disabled - manual calculation only via admin Calculate buttons
                logger.info("Technical levels (Camarilla, CPR, Fibonacci) can be calculated manually via admin Calculate buttons.")
                
                # Step 3: Technical analysis disabled - manual calculation only via admin Calculate buttons
                logger.info("CPR levels can be calculated manually via admin Calculate buttons.")
                if False:  # Disabled auto-calculation
                    from cpr_calculator import CprCalculator
                    cpr_calculator = CprCalculator()
                    cpr_count = 0
                    
                    # Get symbols with historical data available  
                    symbols_with_data = db.session.query(HistoricalData.symbol).distinct().all()
                    
                    for symbol_row in symbols_with_data:
                        symbol = symbol_row[0]
                        
                        # Get previous day's OHLC data from historical database
                        prev_ohlc = cpr_calculator.get_previous_day_ohlc(symbol)
                        if prev_ohlc:
                            # Calculate CPR using proper historical data
                            levels = cpr_calculator.calculate_cpr_levels(
                                symbol,
                                prev_ohlc['high'],
                                prev_ohlc['low'], 
                                prev_ohlc['close']
                            )
                            
                            if levels:
                                # Get current LTP from websocket if available
                                current_ltp = None
                                if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                                    full_symbol = f"NSE:{symbol}-EQ"
                                    if full_symbol in websocket_manager.stock_data:
                                        current_ltp = websocket_manager.stock_data[full_symbol].get('ltp')
                                
                                # Save to database with current LTP for break level calculation
                                if cpr_calculator.save_to_database(symbol, current_ltp):
                                    cpr_count += 1
                    
                    logger.info(f"CPR: {cpr_count} levels calculated using historical data")
                
                # Step 4: Technical analysis disabled - manual calculation only via admin Calculate buttons
                logger.info("Fibonacci levels can be calculated manually via admin Calculate buttons.")
                if False:  # Disabled auto-calculation
                    try:
                        fib_count = 0
                        symbols_with_data = db.session.query(HistoricalData.symbol).distinct().all()
                        
                        if symbols_with_data:
                            from fibonacci_calculator import FibonacciCalculator
                            fib_calculator = FibonacciCalculator()
                            
                            for symbol_row in symbols_with_data:
                                symbol = symbol_row[0]
                                # Get latest daily data for the symbol
                                latest_candle = db.session.query(HistoricalData).filter_by(
                                    symbol=symbol,
                                    resolution='1D'
                                ).order_by(HistoricalData.candle_time.desc()).first()
                                
                                if latest_candle:
                                    levels = fib_calculator.calculate_fibonacci_levels(
                                        symbol,
                                        latest_candle.high_price,
                                        latest_candle.low_price,
                                        latest_candle.close_price
                                    )
                                    
                                    if levels:
                                        # Get current LTP
                                        current_ltp = None
                                        if websocket_manager and websocket_manager.stock_data:
                                            full_symbol = f"NSE:{symbol}-EQ"
                                            if full_symbol in websocket_manager.stock_data:
                                                current_ltp = websocket_manager.stock_data[full_symbol].get('ltp')
                                        
                                        if fib_calculator.save_to_database(symbol, current_ltp):
                                            fib_count += 1
                            
                            logger.info(f"Fibonacci: {fib_count} levels calculated")
                        else:
                            logger.info("Fibonacci: No historical data available yet")
                    except Exception as e:
                        logger.error(f"Fibonacci calculation failed: {str(e)}")
                
                logger.info("Admin auto-initialization completed successfully")
                
            except Exception as e:
                logger.error(f"Background calculations failed: {str(e)}")
        
        # Run calculations in background thread to avoid blocking dashboard load
        import threading
        thread = threading.Thread(target=background_calculations, daemon=True)
        thread.start()
        
        logger.info("Admin auto-initialization started in background")
        
    except Exception as e:
        logger.error(f"Auto-initialization failed: {str(e)}")

# OHLC Storage Endpoints
@app.route('/save_eod_ohlc', methods=['POST'])
def save_eod_ohlc():
    """Manual EOD save - admin only with JSON-only responses"""
    logger.info("💾 EOD OHLC save endpoint accessed")
    
    # Custom authentication check that returns JSON instead of HTML redirect
    if not current_user.is_authenticated:
        logger.warning("❌ EOD save attempted without authentication")
        return jsonify({
            'status': 'error',
            'success': False,
            'message': 'Authentication required - please log in first',
            'error_code': 'NOT_AUTHENTICATED'
        }), 401
    
    # Check admin privileges
    if not current_user.is_admin():
        logger.warning(f"❌ EOD save attempted by non-admin user: {current_user.username}")
        return jsonify({
            'status': 'error',
            'success': False,
            'message': 'Admin privileges required for this operation',
            'error_code': 'ADMIN_REQUIRED',
            'current_user': current_user.username
        }), 403
    
    try:
        global ohlc_storage, websocket_manager, last_eod_save_time, last_eod_save_count
        from datetime import datetime, timedelta
        
        logger.info(f"🔧 Manual EOD save initiated by admin: {current_user.username}")
        
        # Get current time in IST
        ist_tz = pytz.timezone('Asia/Kolkata')
        ist_time = datetime.now(ist_tz)
        current_hour = ist_time.hour
        current_minute = ist_time.minute
        current_weekday = ist_time.weekday()  # Monday=0, Sunday=6
        
        # Check if market is closed (weekends, or after 15:30 IST, or before 09:15 IST)
        is_weekend = current_weekday >= 5  # Saturday=5, Sunday=6
        is_outside_market_hours = (current_hour > 15 or (current_hour == 15 and current_minute >= 30) or current_hour < 9 or (current_hour == 9 and current_minute < 15))
        market_closed = is_weekend or is_outside_market_hours
        
        # If market is closed, download data from previous trading day
        if market_closed:
            logger.info(f"🕐 Market is closed (current time: {ist_time.strftime('%H:%M IST')}). Downloading previous day's data...")
            
            # Check if historical data authentication is available
            hist_access_token = get_hist_access_token()
            if not hist_access_token:
                logger.error("❌ Historical data authentication required for EOD save when market is closed")
                return jsonify({
                    'status': 'error',
                    'success': False,
                    'message': 'Historical data authentication required. Please authenticate via Admin Panel > Historical Data Auth.',
                    'error_code': 'HIST_AUTH_REQUIRED'
                }), 401
            
            # Initialize Fyers API for historical data
            fyers = fyersModel.FyersModel(client_id=Config.FYERS_HIST_DATA_APP_ID, token=hist_access_token)
            
            # Initialize OHLC storage if needed
            if not ohlc_storage:
                ohlc_storage = OHLCStorage(db.session)
                logger.info("📊 OHLC storage initialized")
            
            # Calculate previous trading day
            prev_day = datetime.now() - timedelta(days=1)
            while prev_day.weekday() >= 5:  # Skip weekends
                prev_day = prev_day - timedelta(days=1)
            
            # Try to find a valid trading day with data
            max_attempts = 10
            stored_count = 0
            
            for attempt in range(max_attempts):
                target_date = prev_day.strftime("%Y-%m-%d")
                logger.info(f"📅 Attempting to download data for date: {target_date} (attempt {attempt + 1})")
                
                # Get all F&O symbols from Config
                symbols_to_fetch = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                
                if not symbols_to_fetch:
                    logger.error("❌ No stock symbols found in database")
                    break
                
                # Download data for each symbol
                success_count = 0
                for symbol in symbols_to_fetch:
                    try:
                        # Determine full symbol format
                        if 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                            full_symbol = f"NSE:{symbol}-INDEX"
                        elif 'SENSEX' in symbol.upper():
                            full_symbol = f"BSE:{symbol}-INDEX"
                        else:
                            full_symbol = f"NSE:{symbol}-EQ"
                        
                        hist_data_request = {
                            "symbol": full_symbol,
                            "resolution": "D",
                            "date_format": "1",
                            "range_from": target_date,
                            "range_to": target_date,
                            "cont_flag": "1"
                        }
                        
                        response = fyers.history(hist_data_request)
                        
                        if isinstance(response, dict) and response.get('s') == 'ok' and response.get('candles'):
                            candles = response.get('candles', [])
                            for candle in candles:
                                timestamp = datetime.fromtimestamp(candle[0])
                                
                                # Save to HistData365
                                candle_data = HistData365()
                                candle_data.symbol = symbol
                                candle_data.date = timestamp.date()
                                candle_data.datetime_stamp = timestamp
                                candle_data.open = float(candle[1])
                                candle_data.high = float(candle[2])
                                candle_data.low = float(candle[3])
                                candle_data.close = float(candle[4])
                                candle_data.volume = int(candle[5])
                                candle_data.timeframe = '1D'
                                candle_data.source = 'manual_eod_save'
                                candle_data.day_of_week = timestamp.strftime('%A')
                                
                                existing_hist = HistData365.query.filter_by(
                                    symbol=symbol,
                                    date=timestamp.date(),
                                    timeframe='1D'
                                ).first()
                                
                                if not existing_hist:
                                    db.session.add(candle_data)
                                    success_count += 1
                                
                                # ALSO Save to DailyOHLCData
                                existing_daily = DailyOHLCData.query.filter_by(
                                    symbol=symbol,
                                    trading_date=timestamp.date()
                                ).first()
                                
                                if not existing_daily:
                                    daily_ohlc = DailyOHLCData()
                                    daily_ohlc.symbol = symbol
                                    daily_ohlc.full_symbol = full_symbol
                                    daily_ohlc.trading_date = timestamp.date()
                                    daily_ohlc.day_of_week = timestamp.strftime('%A')
                                    daily_ohlc.open_price = float(candle[1])
                                    daily_ohlc.high_price = float(candle[2])
                                    daily_ohlc.low_price = float(candle[3])
                                    daily_ohlc.close_price = float(candle[4])
                                    daily_ohlc.volume = int(candle[5])
                                    db.session.add(daily_ohlc)
                            
                    except Exception as symbol_error:
                        logger.warning(f"Failed to fetch {symbol}: {str(symbol_error)}")
                        continue
                
                # Commit all data
                db.session.commit()
                stored_count = success_count
                
                if stored_count > 0:
                    logger.info(f"✅ Successfully downloaded {stored_count} records for {target_date}")
                    break
                else:
                    logger.warning(f"⚠️ No data for {target_date} (market holiday?), trying previous day...")
                    prev_day = prev_day - timedelta(days=1)
                    while prev_day.weekday() >= 5:
                        prev_day = prev_day - timedelta(days=1)
            
            last_eod_save_time = datetime.now(pytz.UTC)
            last_eod_save_count = stored_count
            
            return jsonify({
                'status': 'success',
                'success': True,
                'message': f'Successfully downloaded and saved {stored_count} records from previous trading day ({target_date})',
                'symbols_count': stored_count,
                'data_source': 'historical_api',
                'data_date': target_date,
                'save_time': {
                    'utc': last_eod_save_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'ist': ist_time.strftime('%Y-%m-%d %H:%M:%S IST')
                },
                'saved_by': current_user.username
            })
        
        # Market is open - use live WebSocket data
        logger.info(f"📊 Market is open (current time: {ist_time.strftime('%H:%M IST')}). Using live WebSocket data...")
        
        # Get WebSocket manager via singleton accessor
        websocket_manager = get_websocket_manager()
        if not websocket_manager:
            logger.error("❌ WebSocket manager not available")
            return jsonify({
                'status': 'error',
                'success': False,
                'message': 'WebSocket manager not available - live streaming not initialized',
                'error_code': 'NO_WEBSOCKET_MANAGER'
            }), 400
        
        if not hasattr(websocket_manager, 'stock_data') or not websocket_manager.stock_data:
            logger.error("❌ No WebSocket stock data available")
            return jsonify({
                'status': 'error',
                'success': False,
                'message': 'No live data available - start live streaming first',
                'error_code': 'NO_STOCK_DATA',
                'websocket_connected': websocket_manager.is_connected if hasattr(websocket_manager, 'is_connected') else False
            }), 400
        
        # Initialize OHLC storage if needed
        if not ohlc_storage:
            ohlc_storage = OHLCStorage(db.session)
            logger.info("📊 OHLC storage initialized")
        
        # Save current live data as OHLC
        available_symbols = len(websocket_manager.stock_data) if websocket_manager.stock_data else 0
        logger.info(f"💾 Attempting to save EOD data for {available_symbols} symbols")
        
        stored_count = ohlc_storage.save_current_live_data_as_ohlc(websocket_manager.stock_data)
        last_eod_save_time = datetime.now(pytz.UTC)
        last_eod_save_count = stored_count
        
        logger.info(f"✅ MANUAL EOD SAVE by {current_user.username}: Saved {stored_count} symbols at {ist_time.strftime('%H:%M:%S IST')} on {ist_time.strftime('%Y-%m-%d')}")
        
        return jsonify({
            'status': 'success',
            'success': True,
            'message': f'Successfully saved OHLC data for {stored_count} symbols',
            'symbols_count': stored_count,
            'available_symbols': available_symbols,
            'data_source': 'live_websocket',
            'save_time': {
                'utc': last_eod_save_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'ist': ist_time.strftime('%Y-%m-%d %H:%M:%S IST')
            },
            'saved_by': current_user.username
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error saving EOD OHLC: {error_msg}")
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f'Failed to save OHLC data: {error_msg}',
            'error_code': 'SAVE_FAILED'
        }), 500

@app.route('/scheduler_status')
def scheduler_status():
    """Get EOD scheduler status including next run time and last save info - Public endpoint for monitoring"""
    logger.info("📊 Scheduler status endpoint accessed")
    
    try:
        global scheduler_initialized, last_eod_save_time, last_eod_save_count, scheduler_thread
        
        # Get next scheduled job with safe handling
        jobs = schedule.jobs
        next_run = None
        if jobs:
            try:
                next_job = jobs[0]
                next_run_utc = next_job.next_run
                if next_run_utc:
                    # Convert to IST for display
                    ist_tz = pytz.timezone('Asia/Kolkata')
                    next_run_ist = next_run_utc.replace(tzinfo=pytz.UTC).astimezone(ist_tz)
                    next_run = {
                        'utc': next_run_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'ist': next_run_ist.strftime('%Y-%m-%d %H:%M:%S IST'),
                        'timestamp': next_run_utc.timestamp()
                    }
            except Exception as job_error:
                logger.warning(f"Error processing scheduled job info: {str(job_error)}")
                next_run = None
        
        # Safe thread status check - no OS process checks
        scheduler_thread_running = False
        scheduler_thread_status = "not_initialized"
        
        try:
            if scheduler_thread is not None:
                scheduler_thread_running = scheduler_thread.is_alive()
                scheduler_thread_status = "running" if scheduler_thread_running else "stopped"
            else:
                scheduler_thread_status = "not_initialized"
        except Exception as thread_error:
            logger.warning(f"Error checking thread status: {str(thread_error)}")
            scheduler_thread_running = False
            scheduler_thread_status = "error"
        
        # Current time in both timezones
        now_utc = datetime.now(pytz.UTC)
        now_ist = now_utc.astimezone(pytz.timezone('Asia/Kolkata'))
        
        response_data = {
            'status': 'success',
            'success': True,
            'scheduler_initialized': scheduler_initialized,
            'scheduler_running': scheduler_thread_running,
            'scheduler_thread_status': scheduler_thread_status,
            'total_jobs': len(jobs),
            'next_run': next_run,
            'current_time': {
                'utc': now_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'ist': now_ist.strftime('%Y-%m-%d %H:%M:%S IST')
            },
            'last_eod_save': {
                'time': last_eod_save_time.strftime('%Y-%m-%d %H:%M:%S UTC') if last_eod_save_time else None,
                'count': last_eod_save_count if last_eod_save_count is not None else 0
            },
            'message': f'Scheduler status retrieved successfully. Thread: {scheduler_thread_status}'
        }
        
        logger.info(f"✅ Scheduler status returned: {scheduler_thread_status}, Jobs: {len(jobs)}")
        return jsonify(response_data)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error getting scheduler status: {error_msg}")
        return jsonify({
            'status': 'error',
            'success': False,
            'message': f'Failed to get scheduler status: {error_msg}',
            'scheduler_initialized': False,
            'scheduler_running': False,
            'scheduler_thread_status': 'error'
        }), 500

@app.route('/ohlc_status')
def ohlc_status():
    """Get status of OHLC storage system"""
    try:
        global ohlc_storage
        if not ohlc_storage:
            ohlc_storage = OHLCStorage(db.session)
        
        # Get count of stored OHLC records
        from sqlalchemy import text
        query = text("SELECT COUNT(*) as count FROM daily_ohlc_data WHERE trading_date = CURRENT_DATE")
        result = db.session.execute(query).fetchone()
        today_count = result.count if result else 0
        
        # Get total count
        total_query = text("SELECT COUNT(*) as count FROM daily_ohlc_data")
        total_result = db.session.execute(total_query).fetchone()
        total_count = total_result.count if total_result else 0
        
        return jsonify({
            'success': True,
            'today_count': today_count,
            'total_count': total_count,
            'is_eod_time': ohlc_storage.is_market_eod_time() if ohlc_storage else False,
            'storage_initialized': ohlc_storage is not None
        })
        
    except Exception as e:
        logger.error(f"Error getting OHLC status: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/technical_analysis/from_stored_data', methods=['POST'])
@login_required
def calculate_technical_analysis_from_stored_data():
    """Calculate technical analysis from stored daily_ohlc_data when API rate limits prevent fresh data access"""
    try:
        if not current_user.is_admin():
            return jsonify({
                'status': 'error',
                'message': 'Admin access required'
            }), 403
        
        logger.info(f"🔧 Manual technical analysis from stored data initiated by admin: {current_user.username}")
        
        from datetime import date, timedelta
        
        # Create calculator instances locally since globals aren't initialized to save memory
        from camarilla_calculator import CamarillaCalculator
        camarilla_calculator = CamarillaCalculator()
        
        # Get WebSocket manager for current LTP
        websocket_manager = get_websocket_manager()
        
        # Get previous trading day (yesterday)
        yesterday = date.today() - timedelta(days=1)
        
        # Find the most recent trading day in our stored data using raw SQL
        from sqlalchemy import text
        
        latest_trading_day_query = text("""
            SELECT trading_date 
            FROM daily_ohlc_data 
            WHERE trading_date <= :yesterday 
            ORDER BY trading_date DESC 
            LIMIT 1
        """)
        
        latest_trading_day_result = db.session.execute(latest_trading_day_query, {'yesterday': yesterday}).fetchone()
        
        if not latest_trading_day_result:
            return jsonify({
                'status': 'error', 
                'message': 'No stored OHLC data available for technical analysis',
                'records_processed': 0
            }), 400
        
        target_date = latest_trading_day_result[0]
        logger.info(f"📊 Using stored OHLC data from: {target_date}")
        
        # Get all symbols with OHLC data for the target date using raw SQL
        ohlc_records_query = text("""
            SELECT symbol, full_symbol, trading_date, 
                   open_price, high_price, low_price, close_price, volume
            FROM daily_ohlc_data 
            WHERE trading_date = :target_date
        """)
        
        ohlc_records_result = db.session.execute(ohlc_records_query, {'target_date': target_date}).fetchall()
        
        if not ohlc_records_result:
            return jsonify({
                'status': 'error',
                'message': f'No OHLC data found for {target_date}',
                'records_processed': 0
            }), 400
        
        # Create symbol-OHLC mapping for batch processing
        symbol_ohlc_map = {}
        for record in ohlc_records_result:
            symbol_ohlc_map[record[0]] = {  # symbol is at index 0
                'high': record[4],    # high_price is at index 4
                'low': record[5],     # low_price is at index 5
                'close': record[6],   # close_price is at index 6
                'open': record[3],    # open_price is at index 3
                'volume': record[7],  # volume is at index 7
                'date': target_date   # add date field back for downstream processing
            }
        
        # Use batch processing similar to existing endpoints
        successful_calculations = 0
        errors = []
        
        try:
            # Process symbols using stored OHLC data
            for symbol, ohlc_data in symbol_ohlc_map.items():
                try:
                    # Get current LTP for all calculations
                    current_ltp = None
                    if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                        # Try different symbol formats
                        for fmt in [f"NSE:{symbol}-EQ", f"NSE:{symbol}-INDEX"]:
                            if fmt in websocket_manager.stock_data:
                                current_ltp = websocket_manager.stock_data[fmt].get('ltp')
                                break
                    
                    # Calculate and save Camarilla levels
                    camarilla_levels = camarilla_calculator.calculate_camarilla_levels(
                        float(ohlc_data['high']), float(ohlc_data['low']), float(ohlc_data['close'])
                    )
                    if camarilla_levels:
                        # Save to database manually
                        from models import CamarillaLevels
                        existing = CamarillaLevels.query.filter_by(symbol=symbol, date=date.today()).first()
                        
                        if existing:
                            # Update existing record
                            existing.prev_high = ohlc_data['high']
                            existing.prev_low = ohlc_data['low']
                            existing.prev_close = ohlc_data['close']
                            existing.r5 = camarilla_levels['r5']
                            existing.r4 = camarilla_levels['r4']
                            existing.r3 = camarilla_levels['r3']
                            existing.r2 = camarilla_levels['r2']
                            existing.r1 = camarilla_levels['r1']
                            existing.s1 = camarilla_levels['s1']
                            existing.s2 = camarilla_levels['s2']
                            existing.s3 = camarilla_levels['s3']
                            existing.s4 = camarilla_levels['s4']
                            existing.s5 = camarilla_levels['s5']
                            existing.pivot = camarilla_levels['pivot']
                            existing.current_ltp = current_ltp
                            from datetime import datetime, timezone
                            existing.updated_at = datetime.now(timezone.utc)
                        else:
                            # Create new record
                            new_camarilla = CamarillaLevels()
                            new_camarilla.symbol = symbol
                            new_camarilla.full_symbol = f"NSE:{symbol}-EQ"
                            new_camarilla.date = date.today()
                            new_camarilla.prev_high = ohlc_data['high']
                            new_camarilla.prev_low = ohlc_data['low']
                            new_camarilla.prev_close = ohlc_data['close']
                            new_camarilla.r5 = camarilla_levels['r5']
                            new_camarilla.r4 = camarilla_levels['r4']
                            new_camarilla.r3 = camarilla_levels['r3']
                            new_camarilla.r2 = camarilla_levels['r2']
                            new_camarilla.r1 = camarilla_levels['r1']
                            new_camarilla.s1 = camarilla_levels['s1']
                            new_camarilla.s2 = camarilla_levels['s2']
                            new_camarilla.s3 = camarilla_levels['s3']
                            new_camarilla.s4 = camarilla_levels['s4']
                            new_camarilla.s5 = camarilla_levels['s5']
                            new_camarilla.pivot = camarilla_levels['pivot']
                            new_camarilla.current_ltp = current_ltp
                            db.session.add(new_camarilla)
                    
                    # Calculate and save CPR levels - import proper class and create instance
                    from cpr_calculator import CprCalculator
                    cpr_calc = CprCalculator()
                    cpr_levels = cpr_calc.calculate_cpr_levels(symbol, float(ohlc_data['high']), float(ohlc_data['low']), float(ohlc_data['close']))
                    if cpr_levels:
                        cpr_calc.save_to_database(symbol, current_ltp)
                    
                    # Calculate and save Fibonacci levels - import proper class and create instance
                    from fibonacci_calculator import FibonacciCalculator
                    fib_calc = FibonacciCalculator()
                    fibonacci_levels = fib_calc.calculate_fibonacci_levels(symbol, float(ohlc_data['high']), float(ohlc_data['low']), float(ohlc_data['close']))
                    if fibonacci_levels:
                        fib_calc.save_to_database(symbol, current_ltp)
                    
                    successful_calculations += 1
                    
                except Exception as e:
                    error_msg = f"Error processing {symbol}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            # Commit all database changes
            db.session.commit()
        
        except Exception as e:
            logger.error(f"❌ Batch processing error: {str(e)}")
            errors.append(f"Batch processing error: {str(e)}")
            db.session.rollback()
        
        logger.info(f"✅ Technical analysis completed: {successful_calculations} symbols processed from stored OHLC data")
        
        return jsonify({
            'status': 'success',
            'message': f'Technical analysis calculated from stored OHLC data for {target_date}',
            'records_processed': successful_calculations,
            'total_available': len(symbol_ohlc_map),
            'source_date': target_date.isoformat(),
            'errors': errors[:5] if errors else []  # Limit error list
        })
        
    except Exception as e:
        logger.error(f"❌ Error calculating technical analysis from stored data: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to calculate technical analysis: {str(e)}',
            'records_processed': 0
        }), 500

def perform_eod_save():
    """Automatic EOD save function with timezone-aware logging"""
    global last_eod_save_time, last_eod_save_count
    try:
        with app.app_context():
            global ohlc_storage, websocket_manager
            if not ohlc_storage:
                ohlc_storage = OHLCStorage(db.session)
            
            # Get current time in IST for logging
            ist_tz = pytz.timezone('Asia/Kolkata')
            ist_time = datetime.now(ist_tz)
            
            if websocket_manager and hasattr(websocket_manager, 'stock_data'):
                saved_count = ohlc_storage.save_current_live_data_as_ohlc(websocket_manager.stock_data)
                last_eod_save_time = datetime.now(pytz.UTC)
                last_eod_save_count = saved_count
                logger.info(f"✅ AUTOMATIC EOD SAVE: Saved {saved_count} symbols at {ist_time.strftime('%H:%M:%S IST')} on {ist_time.strftime('%Y-%m-%d')}")
                return saved_count
            else:
                last_eod_save_time = datetime.now(pytz.UTC)
                last_eod_save_count = 0
                logger.warning(f"❌ EOD SAVE: No WebSocket data available at {ist_time.strftime('%H:%M:%S IST')}")
                return 0
                
    except Exception as e:
        last_eod_save_time = datetime.now(pytz.UTC)
        last_eod_save_count = 0
        logger.error(f"❌ EOD SAVE ERROR: {str(e)}")
        return 0

@app.route('/preview-instagram')
def preview_instagram():
    """Preview page for Instagram promotional images"""
    return render_template('preview_instagram.html')

@app.route('/generate-combined-instagram')
def generate_combined_instagram():
    """Generate a combined Instagram image with multiple platform features"""
    from PIL import Image, ImageDraw, ImageFont
    import io
    import base64
    
    try:
        # Create Instagram square canvas (1080x1080)
        canvas_width = 1080
        canvas_height = 1080
        canvas = Image.new('RGB', (canvas_width, canvas_height), (10, 15, 20))
        draw = ImageDraw.Draw(canvas)
        
        # Select 4 key features for the combined image
        featured_images = [
            'heatmap.png',
            'levelscan.png',
            'volume_profile.png',
            'price_action_cards.png'
        ]
        
        # Load and arrange 4 images in a 2x2 grid
        grid_size = 2
        cell_width = 480
        cell_height = 480
        padding = 20
        start_x = 60
        start_y = 120
        
        for idx, img_name in enumerate(featured_images):
            img_path = os.path.join(app.static_folder, 'images', img_name)
            if os.path.exists(img_path):
                screenshot = Image.open(img_path)
                screenshot.thumbnail((cell_width, cell_height), Image.Resampling.LANCZOS)
                
                row = idx // grid_size
                col = idx % grid_size
                x = start_x + col * (cell_width + padding)
                y = start_y + row * (cell_height + padding)
                
                # Add white border around each image
                border_size = 3
                draw.rectangle(
                    [(x - border_size, y - border_size), 
                     (x + screenshot.width + border_size, y + screenshot.height + border_size)],
                    outline=(77, 166, 255),
                    width=border_size
                )
                canvas.paste(screenshot, (x, y))
        
        # Draw "3 DAYS FREE TRIAL" badge at top
        badge_height = 60
        badge_y = 30
        badge_width = 600
        badge_x = (canvas_width - badge_width) // 2
        
        badge_color = (255, 215, 0)
        draw.rounded_rectangle(
            [(badge_x, badge_y), (badge_x + badge_width, badge_y + badge_height)],
            radius=15,
            fill=badge_color
        )
        
        try:
            title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
            subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
        except:
            title_font = ImageFont.load_default()
            subtitle_font = ImageFont.load_default()
        
        # Badge text
        badge_text = "🎁 3 DAYS FREE TRIAL"
        bbox = draw.textbbox((0, 0), badge_text, font=title_font)
        text_width = bbox[2] - bbox[0]
        text_x = (canvas_width - text_width) // 2
        draw.text((text_x, badge_y + 12), badge_text, fill=(0, 0, 0), font=title_font)
        
        # Draw platform name at bottom
        bottom_y = canvas_height - 60
        platform_text = "MG F&O Stocks Dashboard"
        platform_bbox = draw.textbbox((0, 0), platform_text, font=subtitle_font)
        platform_width = platform_bbox[2] - platform_bbox[0]
        platform_x = (canvas_width - platform_width) // 2
        draw.text((platform_x, bottom_y), platform_text, fill=(255, 255, 255), font=subtitle_font)
        
        # Convert to base64
        buffer = io.BytesIO()
        canvas.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'image_data': f"data:image/png;base64,{img_base64}",
            'filename': 'mg_dashboard_combined_instagram.png'
        })
        
    except Exception as e:
        logger.error(f"Error generating combined Instagram image: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/generate-instagram-images')
def generate_instagram_images():
    """Generate Instagram promotional images from platform screenshots with '3 Days Free Trial' badge"""
    from PIL import Image, ImageDraw, ImageFont
    import io
    import base64
    
    try:
        # Define platform cards with their images
        platform_cards = [
            {
                'name': 'Index Analysis Charts',
                'image': 'index_analysis.png',
                'description': 'Visual analysis of 20+ indices'
            },
            {
                'name': 'Price Action Cards',
                'image': 'price_action_cards.png',
                'description': '10 cards tracking market movements'
            },
            {
                'name': 'Volume Profile',
                'image': 'volume_profile.png',
                'description': '100-day charts with volume analysis'
            },
            {
                'name': 'Camarilla F&O Scan',
                'image': 'camarilla_scan.png',
                'description': 'Live pivot levels for 200+ F&O stocks'
            },
            {
                'name': 'MG Heatmap',
                'image': 'heatmap.png',
                'description': 'Real-time market sentiment visualization'
            },
            {
                'name': 'Pivot Level Stocks Scan',
                'image': 'levelscan.png',
                'description': 'CPR, Camarilla & Fibonacci scanner'
            },
            {
                'name': '5-Day Line Chart',
                'image': 'linechart.png',
                'description': '5-day trend visualization'
            },
            {
                'name': '5-Day Volume Profile',
                'image': 'volume_5day.png',
                'description': 'Volume profile with VPOC & VAH'
            }
        ]
        
        generated_images = []
        
        for card in platform_cards:
            # Create Instagram square canvas (1080x1080)
            canvas_width = 1080
            canvas_height = 1080
            canvas = Image.new('RGB', (canvas_width, canvas_height), (10, 15, 20))
            draw = ImageDraw.Draw(canvas)
            
            # Load screenshot
            img_path = os.path.join(app.static_folder, 'images', card['image'])
            if os.path.exists(img_path):
                screenshot = Image.open(img_path)
                
                # Resize screenshot to fit nicely
                max_width = 950
                max_height = 650
                screenshot.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                
                # Center the screenshot
                x = (canvas_width - screenshot.width) // 2
                y = 100
                canvas.paste(screenshot, (x, y))
                
                # Draw "3 DAYS FREE TRIAL" badge at top
                badge_height = 60
                badge_y = 30
                badge_width = 600
                badge_x = (canvas_width - badge_width) // 2
                
                # Create gradient effect for badge (using solid color as PIL doesn't support gradients easily)
                badge_color = (255, 215, 0)  # Gold color
                draw.rounded_rectangle(
                    [(badge_x, badge_y), (badge_x + badge_width, badge_y + badge_height)],
                    radius=15,
                    fill=badge_color
                )
                
                # Try to use a nice font, fallback to default
                try:
                    title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
                    subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 24)
                    platform_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
                except:
                    title_font = ImageFont.load_default()
                    subtitle_font = ImageFont.load_default()
                    platform_font = ImageFont.load_default()
                
                # Badge text
                badge_text = "🎁 3 DAYS FREE TRIAL"
                bbox = draw.textbbox((0, 0), badge_text, font=title_font)
                text_width = bbox[2] - bbox[0]
                text_x = (canvas_width - text_width) // 2
                draw.text((text_x, badge_y + 12), badge_text, fill=(0, 0, 0), font=title_font)
                
                # Draw feature name below screenshot
                bottom_y = y + screenshot.height + 40
                name_bbox = draw.textbbox((0, 0), card['name'], font=platform_font)
                name_width = name_bbox[2] - name_bbox[0]
                name_x = (canvas_width - name_width) // 2
                draw.text((name_x, bottom_y), card['name'], fill=(77, 166, 255), font=platform_font)
                
                # Draw platform name
                platform_text = "MG F&O Stocks Dashboard"
                platform_bbox = draw.textbbox((0, 0), platform_text, font=subtitle_font)
                platform_width = platform_bbox[2] - platform_bbox[0]
                platform_x = (canvas_width - platform_width) // 2
                draw.text((platform_x, bottom_y + 50), platform_text, fill=(255, 255, 255), font=subtitle_font)
                
                # Convert to base64 for display
                buffer = io.BytesIO()
                canvas.save(buffer, format='PNG')
                buffer.seek(0)
                img_base64 = base64.b64encode(buffer.getvalue()).decode()
                
                generated_images.append({
                    'name': card['name'],
                    'image_data': f"data:image/png;base64,{img_base64}",
                    'filename': f"{card['image'].replace('.png', '')}_instagram.png"
                })
        
        return jsonify({
            'success': True,
            'images': generated_images
        })
        
    except Exception as e:
        logger.error(f"Error generating Instagram images: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def run_scheduler():
    """Background scheduler thread with enhanced logging"""
    global scheduler_initialized
    logger.info("🚀 EOD Scheduler: Background thread started successfully")
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
        except Exception as e:
            logger.error(f"❌ Scheduler thread error: {str(e)}")
            time.sleep(60)

def start_eod_scheduler(flask_app):
    """Initialize and start the EOD scheduler - works with gunicorn"""
    global scheduler_thread, scheduler_initialized, ohlc_storage
    
    # Prevent duplicate initialization
    if scheduler_initialized:
        logger.warning("⚠️ EOD Scheduler: Already initialized, skipping duplicate initialization")
        return
    
    try:
        # Initialize OHLC storage system
        with flask_app.app_context():
            ohlc_storage = OHLCStorage(db.session)
            logger.info("📊 OHLC storage system initialized")
        
        # Calculate UTC time for 15:45 IST (10:15 UTC)
        # IST is UTC+5:30, so 15:45 IST = 10:15 UTC
        utc_time = "10:15"
        
        # Schedule automatic EOD save at 10:15 UTC (15:45 IST)
        schedule.every().day.at(utc_time).do(perform_eod_save)
        
        # Log in both UTC and IST for clarity
        ist_tz = pytz.timezone('Asia/Kolkata')
        now_utc = datetime.now(pytz.UTC)
        now_ist = now_utc.astimezone(ist_tz)
        
        logger.info(f"⏰ EOD Scheduler: Set to save OHLC data automatically at {utc_time} UTC (15:45 IST) daily")
        logger.info(f"🕒 Current time: {now_utc.strftime('%H:%M:%S UTC')} ({now_ist.strftime('%H:%M:%S IST')})")
        
        # Start scheduler in background thread
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        scheduler_initialized = True
        
        logger.info("🚀 EOD Scheduler: Initialization completed successfully")
        
    except Exception as e:
        logger.error(f"❌ EOD Scheduler initialization failed: {str(e)}")
        scheduler_initialized = False

if __name__ == '__main__':
    # Initialize scheduler when running directly
    start_eod_scheduler(app)
    app.run(host='0.0.0.0', port=5000, debug=True)
