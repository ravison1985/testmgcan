from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Database instance will be initialized in app.py
db = SQLAlchemy()

class StockData(db.Model):
    """Model for real-time stock data"""
    __tablename__ = 'stock_data'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    ltp = db.Column(db.Float, nullable=False)
    change = db.Column(db.Float, default=0.0)
    change_percent = db.Column(db.Float, default=0.0)
    volume = db.Column(db.BigInteger, default=0)
    
    # Historical levels for break analysis
    pdh = db.Column(db.Float, nullable=True)  # Previous Day High
    pdl = db.Column(db.Float, nullable=True)  # Previous Day Low
    wkh = db.Column(db.Float, nullable=True)  # Weekly High
    wkl = db.Column(db.Float, nullable=True)  # Weekly Low
    levels_updated_at = db.Column(db.DateTime, nullable=True)  # When levels were last calculated
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<StockData {self.symbol}:{self.ltp}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'ltp': self.ltp,
            'change': self.change,
            'change_percent': self.change_percent,
            'volume': self.volume,
            'pdh': self.pdh,
            'pdl': self.pdl,
            'wkh': self.wkh,
            'wkl': self.wkl,
            'levels_updated_at': self.levels_updated_at.isoformat() if self.levels_updated_at else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class HistoricalData(db.Model):
    """Model for historical candle data"""
    __tablename__ = 'historical_data'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    resolution = db.Column(db.String(10), nullable=False)  # 1, 5, 15, 30, 60, 240, 1D etc
    
    # OHLCV data
    open_price = db.Column(db.Float, nullable=False)
    high_price = db.Column(db.Float, nullable=False)
    low_price = db.Column(db.Float, nullable=False)
    close_price = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, default=0)
    
    # Timestamp for the candle
    candle_time = db.Column(db.DateTime, nullable=False, index=True)
    day_of_week = db.Column(db.String(10), nullable=True)  # Monday, Tuesday, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Composite unique constraint to prevent duplicate candles (automatically creates index)
    __table_args__ = (
        db.UniqueConstraint('symbol', 'resolution', 'candle_time', name='unique_candle'),
    )
    
    def __repr__(self):
        return f'<HistoricalData {self.symbol}:{self.resolution}:{self.candle_time}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'resolution': self.resolution,
            'open': self.open_price,
            'high': self.high_price,
            'low': self.low_price,
            'close': self.close_price,
            'volume': self.volume,
            'candle_time': self.candle_time.isoformat() if self.candle_time else None,
            'day_of_week': self.day_of_week,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class DataFetchLog(db.Model):
    """Model to track historical data fetch operations"""
    __tablename__ = 'data_fetch_log'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False)
    resolution = db.Column(db.String(10), nullable=False)
    range_from = db.Column(db.DateTime, nullable=False)
    range_to = db.Column(db.DateTime, nullable=False)
    records_fetched = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')  # pending, success, error
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<DataFetchLog {self.symbol}:{self.resolution}:{self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'resolution': self.resolution,
            'range_from': self.range_from.isoformat() if self.range_from else None,
            'range_to': self.range_to.isoformat() if self.range_to else None,
            'records_fetched': self.records_fetched,
            'status': self.status,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class DailyOHLCData(db.Model):
    """Model for daily OHLC data storage"""
    __tablename__ = 'daily_ohlc_data'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    trading_date = db.Column(db.Date, nullable=False, index=True)
    day_of_week = db.Column(db.String(10), nullable=True)  # Monday, Tuesday, etc.
    open_price = db.Column(db.Numeric(12, 4), nullable=False)
    high_price = db.Column(db.Numeric(12, 4), nullable=False)
    low_price = db.Column(db.Numeric(12, 4), nullable=False)
    close_price = db.Column(db.Numeric(12, 4), nullable=False)
    volume = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint to prevent duplicate entries
    __table_args__ = (
        db.UniqueConstraint('symbol', 'trading_date', name='unique_daily_ohlc'),
    )
    
    def __repr__(self):
        return f'<DailyOHLCData {self.symbol}:{self.trading_date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'trading_date': self.trading_date.isoformat() if self.trading_date else None,
            'day_of_week': self.day_of_week,
            'open_price': float(self.open_price),
            'high_price': float(self.high_price),
            'low_price': float(self.low_price),
            'close_price': float(self.close_price),
            'volume': self.volume,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class WeeklyOHLCData(db.Model):
    """Model for weekly OHLC data storage aggregated from daily data"""
    __tablename__ = 'weekly_ohlc_data'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    week_start_date = db.Column(db.Date, nullable=False, index=True)
    week_end_date = db.Column(db.Date, nullable=False, index=True)
    year = db.Column(db.Integer, nullable=False)
    week_number = db.Column(db.Integer, nullable=False)  # Week 1-53 of the year
    open_price = db.Column(db.Numeric(12, 4), nullable=False)  # First day's open
    high_price = db.Column(db.Numeric(12, 4), nullable=False)  # Highest during week
    low_price = db.Column(db.Numeric(12, 4), nullable=False)   # Lowest during week
    close_price = db.Column(db.Numeric(12, 4), nullable=False) # Last day's close
    volume = db.Column(db.BigInteger, default=0)               # Sum of week's volume
    trading_days_count = db.Column(db.Integer, default=0)      # Number of trading days
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint to prevent duplicate entries
    __table_args__ = (
        db.UniqueConstraint('symbol', 'week_start_date', name='unique_weekly_ohlc'),
    )
    
    def __repr__(self):
        return f'<WeeklyOHLCData {self.symbol}:{self.week_start_date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'week_start_date': self.week_start_date.isoformat() if self.week_start_date else None,
            'week_end_date': self.week_end_date.isoformat() if self.week_end_date else None,
            'year': self.year,
            'week_number': self.week_number,
            'open_price': float(self.open_price),
            'high_price': float(self.high_price),
            'low_price': float(self.low_price),
            'close_price': float(self.close_price),
            'volume': self.volume,
            'trading_days_count': self.trading_days_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AccessToken(db.Model):
    """Model for storing Fyers access tokens with expiry tracking"""
    __tablename__ = 'access_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text, nullable=False)
    client_id = db.Column(db.String(100), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<AccessToken {self.client_id}:{self.expires_at}>'
    
    def is_valid(self):
        """Check if token is still valid"""
        return self.is_active and datetime.utcnow() < self.expires_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'client_id': self.client_id,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'is_valid': self.is_valid()
        }

class CamarillaLevels(db.Model):
    """Model for storing Camarilla pivot levels for stocks"""
    __tablename__ = 'camarilla_levels'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, index=True)
    
    # Previous day's OHLC
    prev_high = db.Column(db.Float, nullable=False)
    prev_low = db.Column(db.Float, nullable=False)
    prev_close = db.Column(db.Float, nullable=False)
    
    # Pivot Point
    pivot = db.Column(db.Float, nullable=False)  # (H + L + C) / 3
    
    # Camarilla levels - Resistance and Support
    r5 = db.Column(db.Float, nullable=False)  # Highest resistance
    r4 = db.Column(db.Float, nullable=False)
    r3 = db.Column(db.Float, nullable=False)
    r2 = db.Column(db.Float, nullable=False)
    r1 = db.Column(db.Float, nullable=False)
    s1 = db.Column(db.Float, nullable=False)
    s2 = db.Column(db.Float, nullable=False)
    s3 = db.Column(db.Float, nullable=False)
    s4 = db.Column(db.Float, nullable=False)
    s5 = db.Column(db.Float, nullable=False)  # Lowest support
    
    # Current status
    current_ltp = db.Column(db.Float)
    break_level = db.Column(db.String(10))  # R1, R2, R3, R4, R5, S1, S2, S3, S4, S5, or None
    trend_direction = db.Column(db.String(10))  # 'bullish', 'bearish', 'sideways'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint for symbol and date (automatically creates index)
    __table_args__ = (
        db.UniqueConstraint('symbol', 'date', name='unique_camarilla_symbol_date'),
    )
    
    def __repr__(self):
        return f'<CamarillaLevels {self.symbol}:{self.date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'date': self.date.isoformat() if self.date else None,
            'prev_high': self.prev_high,
            'prev_low': self.prev_low,
            'prev_close': self.prev_close,
            'pivot': self.pivot,
            'r5': self.r5,
            'r4': self.r4,
            'r3': self.r3,
            'r2': self.r2,
            'r1': self.r1,
            's1': self.s1,
            's2': self.s2,
            's3': self.s3,
            's4': self.s4,
            's5': self.s5,
            'current_ltp': self.current_ltp,
            'break_level': self.break_level,
            'trend_direction': self.trend_direction,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class CprLevel(db.Model):
    """Model for storing CPR (Central Pivot Range) levels for stocks"""
    __tablename__ = 'cpr_levels'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, index=True)
    
    # Previous day's close for pivot calculation
    prev_close = db.Column(db.Float, nullable=False)
    
    # CPR levels
    pp = db.Column(db.Float, nullable=False)   # Pivot Point
    tc = db.Column(db.Float, nullable=False)   # Top Central
    bc = db.Column(db.Float, nullable=False)   # Bottom Central
    r1 = db.Column(db.Float, nullable=False)   # Resistance 1
    r2 = db.Column(db.Float, nullable=False)   # Resistance 2
    r3 = db.Column(db.Float, nullable=False)   # Resistance 3
    s1 = db.Column(db.Float, nullable=False)   # Support 1
    s2 = db.Column(db.Float, nullable=False)   # Support 2
    s3 = db.Column(db.Float, nullable=False)   # Support 3
    
    # Current status
    current_ltp = db.Column(db.Float)
    break_level = db.Column(db.String(10))     # TC, BC, R1, R2, R3, S1, S2, S3, CPR, or None
    trend_direction = db.Column(db.String(10)) # 'bullish', 'bearish', 'sideways'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint for symbol and date (automatically creates index)
    __table_args__ = (
        db.UniqueConstraint('symbol', 'date', name='unique_cpr_symbol_date'),
    )
    
    def __repr__(self):
        return f'<CprLevel {self.symbol}:{self.date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'date': self.date.isoformat() if self.date else None,
            'prev_close': self.prev_close,
            'pp': self.pp,
            'tc': self.tc,
            'bc': self.bc,
            'r1': self.r1,
            'r2': self.r2,
            'r3': self.r3,
            's1': self.s1,
            's2': self.s2,
            's3': self.s3,
            'current_ltp': self.current_ltp,
            'break_level': self.break_level,
            'trend_direction': self.trend_direction,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class FibonacciLevel(db.Model):
    """Model for storing Fibonacci pivot levels for stocks"""
    __tablename__ = 'fibonacci_levels'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, index=True)
    
    # Previous day's close for pivot calculation
    prev_close = db.Column(db.Float, nullable=False)
    
    # Fibonacci levels
    pp = db.Column(db.Float, nullable=False)        # Pivot Point
    r1_61 = db.Column(db.Float, nullable=False)     # Resistance 61.8%
    r2_123 = db.Column(db.Float, nullable=False)    # Resistance 123.6%
    r3_161 = db.Column(db.Float, nullable=False)    # Resistance 161.8%
    s1_61 = db.Column(db.Float, nullable=False)     # Support 61.8%
    s2_123 = db.Column(db.Float, nullable=False)    # Support 123.6%
    s3_161 = db.Column(db.Float, nullable=False)    # Support 161.8%
    level_38 = db.Column(db.Float, nullable=False)  # 38.2% level
    level_50 = db.Column(db.Float, nullable=False)  # 50% level
    
    # Current status
    current_ltp = db.Column(db.Float)
    break_level = db.Column(db.String(10))         # R1, R2, R3, S1, S2, S3, 38.2%, 50%, PP, or None
    trend_direction = db.Column(db.String(10))     # 'bullish', 'bearish', 'sideways'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint for symbol and date (automatically creates index)
    __table_args__ = (
        db.UniqueConstraint('symbol', 'date', name='unique_fibonacci_symbol_date'),
    )
    
    def __repr__(self):
        return f'<FibonacciLevel {self.symbol}:{self.date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'date': self.date.isoformat() if self.date else None,
            'prev_close': self.prev_close,
            'pp': self.pp,
            'r1_61': self.r1_61,
            'r2_123': self.r2_123,
            'r3_161': self.r3_161,
            's1_61': self.s1_61,
            's2_123': self.s2_123,
            's3_161': self.s3_161,
            'level_38': self.level_38,
            'level_50': self.level_50,
            'current_ltp': self.current_ltp,
            'break_level': self.break_level,
            'trend_direction': self.trend_direction,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class User(UserMixin, db.Model):
    """User model for authentication system"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)  # Made nullable for Google OAuth users
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'
    
    # Google OAuth support
    google_id = db.Column(db.String(255), unique=True, nullable=True, index=True)  # Google user ID
    profile_image_url = db.Column(db.String(512), nullable=True)  # Google profile picture URL
    
    # New fields for user management
    email = db.Column(db.String(100), unique=True, nullable=True)
    mobile = db.Column(db.String(15), nullable=True)  # Not compulsory
    subscription_period = db.Column(db.String(20), default='monthly')  # monthly, yearly, lifetime
    subscription_start = db.Column(db.Date, nullable=True)
    subscription_end = db.Column(db.Date, nullable=True)
    has_used_trial = db.Column(db.Boolean, default=False)  # Track if user has used free trial
    
    account_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    
    def __repr__(self):
        return f'<User {self.username}:{self.role}>'
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if password matches"""
        return check_password_hash(self.password_hash, password)
    
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    def is_subscription_active(self):
        """Check if user's subscription is currently active"""
        if not self.account_active:
            return False
        
        # Admin users always have access
        if self.is_admin():
            return True
            
        # Check subscription dates
        if not self.subscription_start or not self.subscription_end:
            return False
            
        from datetime import date
        today = date.today()
        return self.subscription_start <= today <= self.subscription_end
    
    def get_subscription_status(self):
        """Get detailed subscription status"""
        if self.is_admin():
            return {'status': 'active', 'type': 'admin', 'message': 'Admin Access'}
        
        if not self.account_active:
            return {'status': 'inactive', 'type': 'disabled', 'message': 'Account Disabled'}
        
        if not self.subscription_start or not self.subscription_end:
            return {'status': 'inactive', 'type': 'no_subscription', 'message': 'No Subscription'}
        
        from datetime import date
        today = date.today()
        
        if today < self.subscription_start:
            return {'status': 'inactive', 'type': 'not_started', 'message': f'Starts on {self.subscription_start.strftime("%d-%m-%Y")}'}
        elif today > self.subscription_end:
            return {'status': 'inactive', 'type': 'expired', 'message': f'Expired on {self.subscription_end.strftime("%d-%m-%Y")}'}
        else:
            days_left = (self.subscription_end - today).days
            return {'status': 'active', 'type': 'active', 'message': f'{days_left} days remaining'}
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'email': self.email,
            'mobile': self.mobile,
            'subscription_period': self.subscription_period,
            'subscription_start': self.subscription_start.isoformat() if self.subscription_start else None,
            'subscription_end': self.subscription_end.isoformat() if self.subscription_end else None,
            'account_active': self.account_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class UserSession(db.Model):
    """Model for tracking user sessions with IP address"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=False, unique=True, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)
    login_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationship to User
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))
    
    def __repr__(self):
        return f'<UserSession {self.user_id}:{self.ip_address}:{self.is_active}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'login_time': self.login_time.isoformat() if self.login_time else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'is_active': self.is_active
        }

class HistData365(db.Model):
    """Model for storing 365-day historical data for all symbols"""
    __tablename__ = 'hist_data_365'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    date = db.Column(db.Date, nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    
    # OHLCV data
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    
    # Additional fields
    timeframe = db.Column(db.String(10), nullable=False, default='1D')  # 1D for daily
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    day_of_week = db.Column(db.String(10), nullable=True)  # Monday, Tuesday, etc.
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Create unique constraint on symbol, date, and timeframe
    __table_args__ = (db.UniqueConstraint('symbol', 'date', 'timeframe', name='_symbol_date_timeframe_365_uc'),)
    
    def __repr__(self):
        return f'<HistData365 {self.symbol}:{self.date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'date': self.date.isoformat() if self.date else None,
            'datetime': self.datetime_stamp.isoformat() if self.datetime_stamp else None,
            'open': self.open,
            'high': self.high,
            'low': self.low,
            'close': self.close,
            'volume': self.volume,
            'timeframe': self.timeframe,
            'source': self.source,
            'day_of_week': self.day_of_week,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class HistData1Min(db.Model):
    """Model for storing 1-minute historical data"""
    __tablename__ = 'hist_data_1min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_1min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData2Min(db.Model):
    """Model for storing 2-minute historical data"""
    __tablename__ = 'hist_data_2min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_2min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData3Min(db.Model):
    """Model for storing 3-minute historical data"""
    __tablename__ = 'hist_data_3min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_3min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData5Min(db.Model):
    """Model for storing 5-minute historical data"""
    __tablename__ = 'hist_data_5min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_5min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData10Min(db.Model):
    """Model for storing 10-minute historical data"""
    __tablename__ = 'hist_data_10min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_10min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData15Min(db.Model):
    """Model for storing 15-minute historical data"""
    __tablename__ = 'hist_data_15min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_15min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData20Min(db.Model):
    """Model for storing 20-minute historical data"""
    __tablename__ = 'hist_data_20min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_20min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData30Min(db.Model):
    """Model for storing 30-minute historical data"""
    __tablename__ = 'hist_data_30min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_30min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData45Min(db.Model):
    """Model for storing 45-minute historical data"""
    __tablename__ = 'hist_data_45min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_45min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData60Min(db.Model):
    """Model for storing 60-minute historical data"""
    __tablename__ = 'hist_data_60min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_60min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData120Min(db.Model):
    """Model for storing 120-minute historical data"""
    __tablename__ = 'hist_data_120min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_120min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData180Min(db.Model):
    """Model for storing 180-minute historical data"""
    __tablename__ = 'hist_data_180min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_180min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class HistData240Min(db.Model):
    """Model for storing 240-minute historical data"""
    __tablename__ = 'hist_data_240min'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    datetime_stamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float, nullable=False)
    high = db.Column(db.Float, nullable=False)
    low = db.Column(db.Float, nullable=False)
    close = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, nullable=False)
    source = db.Column(db.String(50), nullable=False, default='fyers_hist_auth')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('symbol', 'datetime_stamp', name='_symbol_datetime_240min_uc'),)
    
    def to_dict(self):
        return {'symbol': self.symbol, 'datetime': self.datetime_stamp.isoformat(), 'open': self.open, 'high': self.high, 'low': self.low, 'close': self.close, 'volume': self.volume}

class FiveMinCandleData(db.Model):
    """Model specifically for storing 5-minute candle data for fast chart rendering"""
    __tablename__ = 'five_min_candle_data'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)  # NSE:SYMBOL-EQ format
    
    # OHLCV data for 5-minute candles
    open_price = db.Column(db.Float, nullable=False)
    high_price = db.Column(db.Float, nullable=False)
    low_price = db.Column(db.Float, nullable=False)
    close_price = db.Column(db.Float, nullable=False)
    volume = db.Column(db.BigInteger, default=0)
    
    # Timestamp for the 5-minute candle
    candle_time = db.Column(db.DateTime, nullable=False, index=True)
    day_of_week = db.Column(db.String(10), nullable=True)
    
    # Data source and tracking
    source = db.Column(db.String(50), nullable=False, default='fyers_1min_aggregated')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Composite unique constraint to prevent duplicate candles
    __table_args__ = (
        db.UniqueConstraint('symbol', 'candle_time', name='unique_5min_candle'),
    )
    
    def __repr__(self):
        return f'<FiveMinCandleData {self.symbol}:{self.candle_time}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'open': self.open_price,
            'high': self.high_price,
            'low': self.low_price,
            'close': self.close_price,
            'volume': self.volume,
            'candle_time': self.candle_time.isoformat() if self.candle_time else None,
            'day_of_week': self.day_of_week,
            'source': self.source,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Alert(db.Model):
    """Model for storing price action and index analysis alerts"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Alert configuration
    alert_type = db.Column(db.String(30), nullable=False, index=True)  # 'price_action', 'index_analysis'
    alert_category = db.Column(db.String(50), nullable=False)  # 'gainers', 'losers', 'recoveries', 'gap_up', 'gap_down', 'volatile', 'turn_positive', 'turn_negative', 'index_change', 'index_from_open', 'index_from_high', 'index_from_low'
    
    # Target specification
    symbol = db.Column(db.String(50), nullable=True, index=True)  # For individual stock alerts (NULL for general alerts)
    threshold_value = db.Column(db.Float, nullable=True)  # Threshold percentage for index alerts
    condition = db.Column(db.String(20), nullable=True)  # 'above', 'below', 'equals', 'in_top_5'
    
    # Alert settings
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Tracking
    last_triggered = db.Column(db.DateTime, nullable=True)
    trigger_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('alerts', lazy=True))
    
    def __repr__(self):
        return f'<Alert {self.alert_type}:{self.alert_category}:{self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'alert_type': self.alert_type,
            'alert_category': self.alert_category,
            'symbol': self.symbol,
            'threshold_value': self.threshold_value,
            'condition': self.condition,
            'title': self.title,
            'message': self.message,
            'is_active': self.is_active,
            'last_triggered': self.last_triggered.isoformat() if self.last_triggered else None,
            'trigger_count': self.trigger_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AlertTrigger(db.Model):
    """Model for storing alert trigger history"""
    __tablename__ = 'alert_triggers'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=False, index=True)
    
    # Trigger details
    triggered_value = db.Column(db.Float, nullable=True)  # The value that triggered the alert
    triggered_symbol = db.Column(db.String(50), nullable=True)  # Symbol that triggered if general alert
    message = db.Column(db.Text, nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    alert = db.relationship('Alert', backref=db.backref('triggers', lazy=True))
    
    def __repr__(self):
        return f'<AlertTrigger {self.alert_id}:{self.triggered_symbol}:{self.created_at}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'triggered_value': self.triggered_value,
            'triggered_symbol': self.triggered_symbol,
            'message': self.message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Watchlist(db.Model):
    """Model for user stock watchlists"""
    __tablename__ = 'watchlist'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100), nullable=True)  # Custom name for the stock
    notes = db.Column(db.Text, nullable=True)  # Optional user notes
    added_ltp = db.Column(db.Numeric(12, 4), nullable=True)  # LTP when added to watchlist
    investment_amount = db.Column(db.Integer, nullable=True)  # Investment amount in rupees - user must set manually
    position_type = db.Column(db.String(5), nullable=True)  # Long or Short position - user must set manually
    selection_method = db.Column(db.String(50), nullable=True)  # Selection method: Price action, Camarilla, CPR, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate entries per user
    __table_args__ = (
        db.UniqueConstraint('user_id', 'symbol', name='unique_user_watchlist'),
    )
    
    # Relationship
    user = db.relationship('User', backref=db.backref('watchlist_items', lazy=True))
    
    def __repr__(self):
        return f'<Watchlist {self.user_id}:{self.symbol}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'display_name': self.display_name,
            'notes': self.notes,
            'added_ltp': float(self.added_ltp) if self.added_ltp else None,
            'investment_amount': self.investment_amount,
            'position_type': self.position_type,
            'selection_method': self.selection_method,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class WeeklyCprLevel(db.Model):
    """Model for storing weekly CPR (Central Pivot Range) levels for stocks"""
    __tablename__ = 'weekly_cpr_levels'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    week_start_date = db.Column(db.Date, nullable=False, index=True)
    week_end_date = db.Column(db.Date, nullable=False, index=True)
    year = db.Column(db.Integer, nullable=False)
    week_number = db.Column(db.Integer, nullable=False)
    
    # Previous week's close for pivot calculation
    prev_week_close = db.Column(db.Float, nullable=False)
    
    # Weekly OHLC for calculations
    week_high = db.Column(db.Float, nullable=False)
    week_low = db.Column(db.Float, nullable=False)
    week_close = db.Column(db.Float, nullable=False)
    
    # CPR levels based on weekly data
    pp = db.Column(db.Float, nullable=False)   # Pivot Point
    tc = db.Column(db.Float, nullable=False)   # Top Central
    bc = db.Column(db.Float, nullable=False)   # Bottom Central
    r1 = db.Column(db.Float, nullable=False)   # Resistance 1
    r2 = db.Column(db.Float, nullable=False)   # Resistance 2
    r3 = db.Column(db.Float, nullable=False)   # Resistance 3
    s1 = db.Column(db.Float, nullable=False)   # Support 1
    s2 = db.Column(db.Float, nullable=False)   # Support 2
    s3 = db.Column(db.Float, nullable=False)   # Support 3
    
    # Current status
    current_ltp = db.Column(db.Float)
    break_level = db.Column(db.String(10))     # TC, BC, R1, R2, R3, S1, S2, S3, CPR, or None
    trend_direction = db.Column(db.String(10)) # 'bullish', 'bearish', 'sideways'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint for symbol and week
    __table_args__ = (
        db.UniqueConstraint('symbol', 'year', 'week_number', name='unique_weekly_cpr_symbol_week'),
    )
    
    def __repr__(self):
        return f'<WeeklyCprLevel {self.symbol}:{self.year}-W{self.week_number}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'week_start_date': self.week_start_date.isoformat() if self.week_start_date else None,
            'week_end_date': self.week_end_date.isoformat() if self.week_end_date else None,
            'year': self.year,
            'week_number': self.week_number,
            'prev_week_close': self.prev_week_close,
            'week_high': self.week_high,
            'week_low': self.week_low,
            'week_close': self.week_close,
            'pp': self.pp,
            'tc': self.tc,
            'bc': self.bc,
            'r1': self.r1,
            'r2': self.r2,
            'r3': self.r3,
            's1': self.s1,
            's2': self.s2,
            's3': self.s3,
            'current_ltp': self.current_ltp,
            'break_level': self.break_level,
            'trend_direction': self.trend_direction,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class WeeklyFibonacciLevel(db.Model):
    """Model for storing weekly Fibonacci pivot levels for stocks"""
    __tablename__ = 'weekly_fibonacci_levels'
    
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(50), nullable=False, index=True)
    full_symbol = db.Column(db.String(100), nullable=False)
    week_start_date = db.Column(db.Date, nullable=False, index=True)
    week_end_date = db.Column(db.Date, nullable=False, index=True)
    year = db.Column(db.Integer, nullable=False)
    week_number = db.Column(db.Integer, nullable=False)
    
    # Previous week's close for pivot calculation
    prev_week_close = db.Column(db.Float, nullable=False)
    
    # Weekly OHLC for calculations
    week_high = db.Column(db.Float, nullable=False)
    week_low = db.Column(db.Float, nullable=False)
    week_close = db.Column(db.Float, nullable=False)
    
    # Fibonacci levels based on weekly data
    pp = db.Column(db.Float, nullable=False)        # Pivot Point
    r1_61 = db.Column(db.Float, nullable=False)     # Resistance 61.8%
    r2_123 = db.Column(db.Float, nullable=False)    # Resistance 123.6%
    r3_161 = db.Column(db.Float, nullable=False)    # Resistance 161.8%
    s1_61 = db.Column(db.Float, nullable=False)     # Support 61.8%
    s2_123 = db.Column(db.Float, nullable=False)    # Support 123.6%
    s3_161 = db.Column(db.Float, nullable=False)    # Support 161.8%
    level_38 = db.Column(db.Float, nullable=False)  # 38.2% level
    level_50 = db.Column(db.Float, nullable=False)  # 50% level
    
    # Current status
    current_ltp = db.Column(db.Float)
    break_level = db.Column(db.String(10))         # R1, R2, R3, S1, S2, S3, 38.2%, 50%, PP, or None
    trend_direction = db.Column(db.String(10))     # 'bullish', 'bearish', 'sideways'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint for symbol and week
    __table_args__ = (
        db.UniqueConstraint('symbol', 'year', 'week_number', name='unique_weekly_fibonacci_symbol_week'),
    )
    
    def __repr__(self):
        return f'<WeeklyFibonacciLevel {self.symbol}:{self.year}-W{self.week_number}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'full_symbol': self.full_symbol,
            'week_start_date': self.week_start_date.isoformat() if self.week_start_date else None,
            'week_end_date': self.week_end_date.isoformat() if self.week_end_date else None,
            'year': self.year,
            'week_number': self.week_number,
            'prev_week_close': self.prev_week_close,
            'week_high': self.week_high,
            'week_low': self.week_low,
            'week_close': self.week_close,
            'pp': self.pp,
            'r1_61': self.r1_61,
            'r2_123': self.r2_123,
            'r3_161': self.r3_161,
            's1_61': self.s1_61,
            's2_123': self.s2_123,
            's3_161': self.s3_161,
            'level_38': self.level_38,
            'level_50': self.level_50,
            'current_ltp': self.current_ltp,
            'break_level': self.break_level,
            'trend_direction': self.trend_direction,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class SubscriptionPlan(db.Model):
    """Model for subscription plans with dynamic pricing"""
    __tablename__ = 'subscription_plans'
    
    id = db.Column(db.Integer, primary_key=True)
    plan_name = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    original_price = db.Column(db.Integer)
    strike_price = db.Column(db.Integer, nullable=True)  # Permanent strike price for discount calculation
    validity_days = db.Column(db.Integer, nullable=False)
    validity_display = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    features = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SubscriptionPlan {self.plan_name}:{self.price}>'
    
    def get_discount_percent(self):
        """Calculate discount percentage based on strike price"""
        if self.strike_price and self.strike_price > 0 and self.price < self.strike_price:
            discount = ((self.strike_price - self.price) / self.strike_price) * 100
            return max(0, round(discount))
        return 0
    
    def to_dict(self):
        return {
            'id': self.id,
            'plan_name': self.plan_name,
            'display_name': self.display_name,
            'price': self.price,
            'original_price': self.original_price,
            'strike_price': self.strike_price,
            'discount_percent': self.get_discount_percent(),
            'validity_days': self.validity_days,
            'validity_display': self.validity_display,
            'description': self.description,
            'features': self.features,
            'is_active': self.is_active,
            'sort_order': self.sort_order,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class CouponCode(db.Model):
    """Model for discount coupon codes"""
    __tablename__ = 'coupon_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), nullable=False, unique=True, index=True)
    discount_percent = db.Column(db.Float)
    discount_amount = db.Column(db.Integer)
    discount_type = db.Column(db.String(20), default='percentage')
    max_uses = db.Column(db.Integer, nullable=True)
    uses_count = db.Column(db.Integer, default=0)
    valid_from = db.Column(db.DateTime, nullable=True)
    valid_until = db.Column(db.DateTime, nullable=True)
    applicable_plans = db.Column(db.Text)
    min_purchase_amount = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=True)
    created_by_user_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<CouponCode {self.code}>'
    
    def is_valid(self):
        """Check if coupon is currently valid"""
        if not self.is_active:
            return False, "Coupon is inactive"
        
        now = datetime.utcnow()
        if self.valid_until and now > self.valid_until:
            return False, "Coupon has expired"
        
        if self.valid_from and now < self.valid_from:
            return False, "Coupon not yet valid"
        
        if self.max_uses and self.uses_count >= self.max_uses:
            return False, "Coupon usage limit reached"
        
        return True, "Valid"
    
    def calculate_discount(self, amount):
        """Calculate discount amount for given price"""
        if self.discount_type == 'fixed' and self.discount_amount:
            return min(self.discount_amount, amount)
        elif self.discount_type == 'percentage' and self.discount_percent:
            return (amount * self.discount_percent) / 100
        return 0
    
    def to_dict(self):
        is_valid, message = self.is_valid()
        return {
            'id': self.id,
            'code': self.code,
            'discount_type': self.discount_type,
            'discount_percent': self.discount_percent,
            'discount_amount': self.discount_amount,
            'max_uses': self.max_uses,
            'uses_count': self.uses_count,
            'remaining_uses': self.max_uses - self.uses_count if self.max_uses else None,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'applicable_plans': self.applicable_plans,
            'min_purchase_amount': self.min_purchase_amount,
            'is_active': self.is_active,
            'is_valid': is_valid,
            'validation_message': message,
            'created_by_user_id': self.created_by_user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
