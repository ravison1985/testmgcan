import threading
import queue
import time
import json
import logging
from datetime import datetime
import pytz
from fyers_apiv3.FyersWebsocket import data_ws
from config import Config

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self, access_token, app=None):
        self.access_token = access_token
        self.app = app  # Store Flask app instance for database context
        self.data_queue = queue.Queue(maxsize=1000)  # Limit queue size to prevent memory leaks
        self.websocket = None
        self.is_connected = False
        self.connection_status = "disconnected"
        self.last_update = None
        self.stock_data = {}
        self.stock_data_lock = threading.Lock()  # Thread-safe access to stock_data
        self.thread = None
        self.message_counter = 0  # Counter to reduce logging frequency
        self._last_log_ts = 0  # Time-based throttling for batch logs
        self._subscribed = False  # Guard against multiple subscriptions
        
        # Disconnection Tracking System
        self.disconnect_history = []  # Track all disconnection events
        self.disconnect_start_time = None  # When current disconnection started
        self.last_connected_time = None  # When last connected
        self.total_disconnection_time = 0  # Total seconds disconnected
        self.disconnection_count = 0  # Total number of disconnections
        self.reconnection_attempts = 0  # Track reconnection attempts
        self.last_stats_log_time = time.time()  # Track when we last logged stats
        
        # High/Low Alert System
        self.previous_highs = {}  # Track previous highs for each symbol
        self.previous_lows = {}   # Track previous lows for each symbol
        self.alerts_queue = queue.Queue(maxsize=500)  # Queue for high/low alerts
        self.recent_alerts_cache = []  # Cache recent alerts for broadcast to all users
        self.alerts_cache_lock = threading.Lock()  # Thread-safe access to alerts cache
        self.alerts_cache_max_age = 2  # Keep alerts for 2 seconds only - all users poll at 500ms so everyone sees it
        self.break_levels_cache = {}  # Cache historical levels (PDH, PDL, WKH, WKL)
        self.break_alerts_sent = {}  # Track which break alerts have been sent
        
        # RVOL Alert System
        self.avg_volume_cache = {}  # Cache average volume for RVOL calculation
        self.rvol_alerts_sent = {}  # Track which RVOL threshold alerts have been sent (1x, 2x, 3x)
        self.last_rvol_avg_refresh = 0  # Track when we last refreshed average volume data
        
        # 5-Minute Candle Storage System
        self.current_candles = {}  # Track current 5-min candle for each symbol
        self.candle_storage_lock = threading.Lock()  # Thread-safe access to candle storage
        self.last_candle_save_time = None  # Track when we last saved candles
    
    def is_market_open(self):
        """Check if the market is currently open in IST"""
        try:
            # Get current time in IST
            ist = pytz.timezone('Asia/Kolkata')
            now = datetime.now(ist)
            current_time = now.time()
            current_weekday = now.weekday()  # Monday=0, Sunday=6
            
            # Market is closed on weekends (Saturday=5, Sunday=6)
            if current_weekday >= 5:
                return False
            
            # Market trading hours in IST:
            # Pre-market: 09:00 - 09:15
            # Regular market: 09:15 - 15:30 
            # Post-market: 15:40 - 16:00
            
            from datetime import time
            pre_market_start = time(9, 0)   # 9:00 AM
            market_start = time(9, 15)      # 9:15 AM  
            market_end = time(15, 30)       # 3:30 PM
            post_market_start = time(15, 40) # 3:40 PM
            post_market_end = time(16, 0)   # 4:00 PM
            
            # Check if in trading hours
            is_pre_market = pre_market_start <= current_time < market_start
            is_regular_market = market_start <= current_time <= market_end
            is_post_market = post_market_start <= current_time <= post_market_end
            
            return is_pre_market or is_regular_market or is_post_market
            
        except Exception as e:
            logger.error(f"Error checking market hours: {str(e)}")
            # Default to market open if we can't determine (safer for alerts)
            return True
        
    def onmessage(self, message):
        """Handle incoming WebSocket messages"""
        try:
            # Performance: Increment counter but reduce logging for speed
            self.message_counter += 1
            
            # Handle different message formats from Fyers API
            if isinstance(message, dict):
                # Single message format
                messages = [message]
            elif isinstance(message, list):
                # List of messages format
                messages = message
            else:
                logger.warning(f"Unknown message format: {type(message)}")
                return
            
            processed_count = 0
            for data in messages:
                if isinstance(data, dict):
                    # Extract symbol data based on Fyers API format
                    # The symbol might be in the data directly or we need to map it
                    symbol = data.get('symbol', data.get('s', ''))
                    ltp = data.get('ltp', data.get('lp', data.get('last_price', 0)))
                    change = data.get('ch', data.get('change', 0))
                    chp = data.get('chp', data.get('change_percent', 0))
                    volume = data.get('vol_traded_today', data.get('v', data.get('volume', 0)))
                    high = data.get('high_price', data.get('high', data.get('h', data.get('day_high', 0))))
                    low = data.get('low_price', data.get('low', data.get('l', data.get('day_low', 0))))
                    open_price = data.get('open_price', data.get('open', data.get('o', data.get('day_open', 0))))
                    prev_close = data.get('prev_close_price', data.get('prev_close', data.get('pc', 0)))
                    
                    # Skip WebSocket status/control messages (like authentication responses)
                    if not symbol or symbol.lower() == 'ok' or data.get('type') in ['cn', 'ful']:
                        continue
                    
                    if symbol:  # Only process if we have a symbol
                        # Clean symbol name for display
                        display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                        
                        current_high = float(high) if high else 0.0
                        current_low = float(low) if low else 0.0
                        
                        stock_info = {
                            'symbol': display_symbol,
                            'full_symbol': symbol,
                            'ltp': float(ltp) if ltp else 0.0,
                            'change': float(change) if change else 0.0,
                            'change_percent': float(chp) if chp else 0.0,
                            'volume': int(volume) if volume else 0,
                            'high_price': current_high,
                            'low_price': current_low,
                            'open_price': float(open_price) if open_price else 0.0,
                            'prev_close_price': float(prev_close) if prev_close else 0.0,
                            'timestamp': int(time.time())
                        }
                        
                        # Check for new highs and lows
                        self._check_for_new_highs_lows(symbol, display_symbol, current_high, current_low, float(ltp) if ltp else 0.0)
                        
                        # Check for RVOL threshold alerts (1x, 2x, 3x)
                        self._check_for_rvol_alerts(symbol, display_symbol, int(volume) if volume else 0)
                        
                        # Check for break level alerts (PDH, PDL, WKH, WKL) - Temporarily disabled for performance
                        # self._check_for_break_levels(symbol, display_symbol, float(ltp) if ltp else 0.0)
                        
                        # 5-minute candle data storage - DISABLED per user request
                        # self.update_5min_candle(
                        #     display_symbol,
                        #     float(ltp) if ltp else 0.0,
                        #     float(open_price) if open_price else 0.0,
                        #     current_high,
                        #     current_low,
                        #     int(volume) if volume else 0
                        # )
                        
                        # Thread-safe update to stock_data with lock
                        with self.stock_data_lock:
                            self.stock_data[symbol] = stock_info
                        
                        # Skip queue operations for performance - we use cached stock_data dict
                        # Queue was causing slowdowns with multiple users and high message rate
                        
                        self.last_update = time.time()
                        processed_count += 1
                        
            # Performance: Time-based DEBUG logging (every 60s) to prevent log flooding
            current_time = time.time()
            if current_time - self._last_log_ts >= 60:
                logger.debug(f"WebSocket batch update: {len(self.stock_data)} symbols active")
                self._last_log_ts = current_time
            
            # Hourly disconnection stats logging (every 3600s = 1 hour)
            if current_time - self.last_stats_log_time >= 3600:
                if self.disconnection_count > 0:
                    avg_downtime = self.total_disconnection_time / self.disconnection_count
                    logger.info(f"⏰ HOURLY WEBSOCKET STATS - Total Disconnections: {self.disconnection_count} | Total Downtime: {self.total_disconnection_time:.2f}s | Avg Downtime: {avg_downtime:.2f}s")
                else:
                    logger.info(f"⏰ HOURLY WEBSOCKET STATS - No disconnections in the past hour ✅")
                self.last_stats_log_time = current_time
            
            # 5-minute candle saving - DISABLED per user request
            # candle_time = self.get_current_5min_candle_time()
            # if candle_time and (self.last_candle_save_time is None or candle_time > self.last_candle_save_time):
            #     self.save_completed_candles()
            #     self.last_candle_save_time = candle_time
            
            
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {str(e)}")
    
    def onerror(self, message):
        """Handle WebSocket errors"""
        ist = pytz.timezone('Asia/Kolkata')
        error_time = datetime.now(ist)
        
        logger.error(f"🔴 WebSocket ERROR at {error_time.strftime('%H:%M:%S IST')}: {message}")
        
        # Track disconnection start if not already tracking
        if self.is_connected and self.disconnect_start_time is None:
            self.disconnect_start_time = time.time()
            self.disconnection_count += 1
            logger.warning(f"📊 DISCONNECTION #{self.disconnection_count} - Started at {error_time.strftime('%H:%M:%S IST')}")
        
        self.connection_status = "error"
        self._subscribed = False  # Reset subscription state to force re-subscribe on reconnect
    
    def onclose(self, message):
        """Handle WebSocket connection close"""
        ist = pytz.timezone('Asia/Kolkata')
        close_time = datetime.now(ist)
        
        logger.info(f"🔴 WebSocket CLOSED at {close_time.strftime('%H:%M:%S IST')}: {message}")
        
        # Track disconnection start if not already tracking
        if self.is_connected and self.disconnect_start_time is None:
            self.disconnect_start_time = time.time()
            self.disconnection_count += 1
            logger.warning(f"📊 DISCONNECTION #{self.disconnection_count} - Started at {close_time.strftime('%H:%M:%S IST')}")
        
        self.is_connected = False
        self.connection_status = "disconnected"
        self._subscribed = False  # Reset subscription state to force re-subscribe on reconnect
    
    
    
    def onopen(self):
        """Handle WebSocket connection open"""
        try:
            ist = pytz.timezone('Asia/Kolkata')
            connect_time = datetime.now(ist)
            
            # Calculate downtime if there was a disconnection
            if self.disconnect_start_time is not None:
                downtime = time.time() - self.disconnect_start_time
                self.total_disconnection_time += downtime
                
                # Log reconnection with downtime stats
                logger.info(f"✅ WebSocket RECONNECTED at {connect_time.strftime('%H:%M:%S IST')}")
                logger.info(f"📊 RECONNECTION STATS - Downtime: {downtime:.2f}s | Total disconnections: {self.disconnection_count} | Total downtime: {self.total_disconnection_time:.2f}s")
                
                # Store disconnect event in history
                self.disconnect_history.append({
                    'start_time': datetime.fromtimestamp(self.disconnect_start_time, ist).strftime('%H:%M:%S IST'),
                    'end_time': connect_time.strftime('%H:%M:%S IST'),
                    'duration_seconds': downtime,
                    'reconnection_attempts': self.reconnection_attempts
                })
                
                # Reset tracking
                self.disconnect_start_time = None
                self.reconnection_attempts = 0
            else:
                logger.info(f"✅ WebSocket CONNECTED at {connect_time.strftime('%H:%M:%S IST')}")
            
            self.is_connected = True
            self.connection_status = "connected"
            self.last_connected_time = time.time()
            
            # Subscribe only once to prevent duplicate subscriptions
            if not self._subscribed:
                data_type = "SymbolUpdate"
                try:
                    self.websocket.subscribe(symbols=Config.NIFTY50_SYMBOLS, data_type=data_type)
                    self._subscribed = True
                    logger.info(f"📡 Subscribed to {len(Config.NIFTY50_SYMBOLS)} F&O stocks and INDEX symbols")
                    
                    # Initialize average volume cache for RVOL alerts on first connection
                    if not self.avg_volume_cache:
                        threading.Thread(target=self.refresh_avg_volume_cache, daemon=True).start()
                        logger.info("🔄 Initializing average volume cache for RVOL alerts...")
                        
                except Exception as sub_error:
                    logger.error(f"Error subscribing to symbols: {str(sub_error)}")
            
        except Exception as e:
            logger.error(f"Error in WebSocket onopen: {str(e)}")
            self.connection_status = "error"
    
    def connect(self):
        """Establish WebSocket connection"""
        try:
            logger.info("Initializing WebSocket connection...")
            
            self.websocket = data_ws.FyersDataSocket(
                access_token=self.access_token,
                log_path="",
                litemode=False,
                write_to_file=False,
                reconnect=True,
                on_connect=self.onopen,
                on_close=self.onclose,
                on_error=self.onerror,
                on_message=self.onmessage,
                reconnect_retry=50
            )
            
            self.connection_status = "connecting"
            
            # Start WebSocket in a separate thread
            self.thread = threading.Thread(target=self._connect_websocket, daemon=True)
            self.thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to WebSocket: {str(e)}")
            self.connection_status = "error"
            return False
    
    def _connect_websocket(self):
        """Internal method to connect WebSocket"""
        try:
            # Try different connection methods based on Fyers API
            if hasattr(self.websocket, 'connect'):
                self.websocket.connect()
            elif hasattr(self.websocket, 'start'):
                self.websocket.start()
            elif hasattr(self.websocket, 'run'):
                self.websocket.run()
            else:
                logger.error("WebSocket object does not have a known connection method")
                # Try to call it directly if it's callable
                if callable(self.websocket):
                    self.websocket()
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            self.connection_status = "error"
    
    def disconnect(self):
        """Disconnect WebSocket"""
        try:
            if self.websocket:
                # Try different disconnection methods
                if hasattr(self.websocket, 'close'):
                    self.websocket.close()
                elif hasattr(self.websocket, 'disconnect'):
                    self.websocket.disconnect()
                elif hasattr(self.websocket, 'stop'):
                    self.websocket.stop()
            self.is_connected = False
            self.connection_status = "disconnected"
            logger.info("WebSocket disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket: {str(e)}")
    
    def get_latest_data(self):
        """Get all latest stock data - thread-safe snapshot"""
        with self.stock_data_lock:
            return dict(self.stock_data)
    
    def get_connection_status(self):
        """Get current connection status with disconnection tracking"""
        return {
            'status': self.connection_status,
            'is_connected': self.is_connected,
            'last_update': self.last_update,
            'symbol_count': len(self.stock_data),
            'disconnection_stats': {
                'total_disconnections': self.disconnection_count,
                'total_downtime_seconds': round(self.total_disconnection_time, 2),
                'currently_disconnected': self.disconnect_start_time is not None,
                'disconnect_history': self.disconnect_history[-10:]  # Last 10 disconnections
            }
        }
    
    def get_disconnection_stats(self):
        """Get detailed disconnection statistics"""
        ist = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        
        stats = {
            'total_disconnections': self.disconnection_count,
            'total_downtime_seconds': round(self.total_disconnection_time, 2),
            'average_downtime_seconds': round(self.total_disconnection_time / self.disconnection_count, 2) if self.disconnection_count > 0 else 0,
            'currently_connected': self.is_connected,
            'current_time_ist': current_time.strftime('%H:%M:%S IST'),
            'disconnect_history': self.disconnect_history
        }
        
        # Log stats every hour (if requested)
        logger.info(f"📊 WEBSOCKET STATS - Disconnections: {stats['total_disconnections']} | Total Downtime: {stats['total_downtime_seconds']}s | Avg Downtime: {stats['average_downtime_seconds']}s")
        
        return stats
    
    def get_new_messages(self):
        """Get latest stock data - optimized for multi-user performance
        
        Returns the cached stock_data dict instead of consuming queue.
        This prevents queue depletion issues with multiple concurrent users.
        Thread-safe snapshot using lock.
        """
        # Return thread-safe snapshot of cached data
        # This ensures all users get the same complete data set without race conditions
        with self.stock_data_lock:
            return list(self.stock_data.values())
    
    def _check_for_new_highs_lows(self, symbol, display_symbol, current_high, current_low, current_ltp):
        """Check if current high/low are new records and generate alerts"""
        try:
            # Only process if we have valid price data
            if current_high <= 0 or current_low <= 0:
                return
                
            # Only send alerts during market hours
            if not self.is_market_open():
                return
                
            # Check for new high
            if symbol in self.previous_highs:
                if current_high > self.previous_highs[symbol]:
                    alert = {
                        'type': 'high',
                        'symbol': display_symbol,
                        'price': current_ltp,
                        'new_high': current_high,
                        'previous_high': self.previous_highs[symbol],
                        'timestamp': int(time.time())
                    }
                    self._add_alert(alert)
            
            # Check for new low  
            if symbol in self.previous_lows:
                if current_low < self.previous_lows[symbol]:
                    alert = {
                        'type': 'low',
                        'symbol': display_symbol,
                        'price': current_ltp,
                        'new_low': current_low,
                        'previous_low': self.previous_lows[symbol],
                        'timestamp': int(time.time())
                    }
                    self._add_alert(alert)
            
            # Update previous values
            self.previous_highs[symbol] = current_high
            self.previous_lows[symbol] = current_low
            
        except Exception as e:
            logger.error(f"Error checking high/low for {symbol}: {str(e)}")
    
    def _check_for_break_levels(self, symbol, display_symbol, current_ltp):
        """Check if current LTP breaks historical levels and generate alerts"""
        try:
            if current_ltp <= 0:
                return
                
            # Get historical levels from cache or database
            levels = self._get_break_levels(symbol)
            if not levels:
                return
                
            pdh, pdl, wkh, wkl = levels
            
            # Create unique alert key for this symbol
            alert_key = f"{symbol}_{int(time.time() // 3600)}"  # Hourly unique key
            
            # Check for break level alerts
            breaks = []
            
            # PDH Break (breakout above previous day high)
            if pdh and current_ltp > pdh:
                if f"{alert_key}_PDH" not in self.break_alerts_sent:
                    breaks.append("PDH")
                    self.break_alerts_sent[f"{alert_key}_PDH"] = True
                    
            # PDL Break (breakdown below previous day low) 
            if pdl and current_ltp < pdl:
                if f"{alert_key}_PDL" not in self.break_alerts_sent:
                    breaks.append("PDL")
                    self.break_alerts_sent[f"{alert_key}_PDL"] = True
                    
            # WKH Break (breakout above weekly high)
            if wkh and current_ltp > wkh:
                if f"{alert_key}_WKH" not in self.break_alerts_sent:
                    breaks.append("WKH")
                    self.break_alerts_sent[f"{alert_key}_WKH"] = True
                    
            # WKL Break (breakdown below weekly low)
            if wkl and current_ltp < wkl:
                if f"{alert_key}_WKL" not in self.break_alerts_sent:
                    breaks.append("WKL")
                    self.break_alerts_sent[f"{alert_key}_WKL"] = True
            
            # Generate alerts for each break
            for break_type in breaks:
                alert_type = 'high' if break_type in ['PDH', 'WKH'] else 'low'
                level_value = pdh if break_type == 'PDH' else (wkh if break_type == 'WKH' else (pdl if break_type == 'PDL' else wkl))
                
                alert = {
                    'type': alert_type,
                    'symbol': display_symbol,
                    'price': current_ltp,
                    'break_type': break_type,
                    'break_level': level_value,
                    'timestamp': int(time.time())
                }
                self._add_alert(alert)
                
        except Exception as e:
            logger.error(f"Error checking break levels for {symbol}: {str(e)}")
    
    def _get_break_levels(self, symbol):
        """Get historical levels (PDH, PDL, WKH, WKL) from cache or database"""
        try:
            # Check cache first
            if symbol in self.break_levels_cache:
                return self.break_levels_cache[symbol]
            
            # Skip database query if no app instance
            if not self.app:
                return None
                
            # Import here to avoid circular imports
            from models import StockData
            
            # Query database for historical levels using app context
            with self.app.app_context():
                stock = StockData.query.filter_by(symbol=symbol).first()
                if stock and (stock.pdh or stock.pdl or stock.wkh or stock.wkl):
                    levels = (stock.pdh, stock.pdl, stock.wkh, stock.wkl)
                    self.break_levels_cache[symbol] = levels
                    return levels
                
            return None
            
        except Exception as e:
            logger.error(f"Error getting break levels for {symbol}: {str(e)}")
            return None
    
    def _add_alert(self, alert):
        """Add alert to cache for broadcast to all users - thread-safe"""
        current_time = time.time()
        alert['cache_timestamp'] = current_time
        
        # Add to queue for legacy support
        try:
            self.alerts_queue.put_nowait(alert)
        except queue.Full:
            # Remove old alerts if queue is full
            try:
                for _ in range(50):  # Remove 50 old alerts
                    self.alerts_queue.get_nowait()
                self.alerts_queue.put_nowait(alert)  # Add the new one
            except queue.Empty:
                pass
        
        # Thread-safe update to alerts cache
        with self.alerts_cache_lock:
            # Add to broadcast cache (all users will see this)
            self.recent_alerts_cache.append(alert)
            
            # Clean old alerts from cache (older than max_age seconds)
            self.recent_alerts_cache = [
                a for a in self.recent_alerts_cache 
                if current_time - a.get('cache_timestamp', 0) < self.alerts_cache_max_age
            ]
    
    def get_new_alerts(self):
        """Get recent alerts for broadcast to all users
        
        Returns alerts from recent cache instead of consuming queue.
        This ensures all users see the same alerts (broadcast pattern).
        Thread-safe snapshot using lock.
        """
        # Return thread-safe snapshot of recent cached alerts (broadcast to all users)
        # Frontend will deduplicate based on alert ID
        with self.alerts_cache_lock:
            return list(self.recent_alerts_cache)
    
    def refresh_break_levels_cache(self):
        """Refresh the break levels cache from database"""
        # Skip if no app instance (cannot access database)
        if not self.app:
            return
            
        try:
            from models import StockData
            
            # Clear existing cache
            self.break_levels_cache.clear()
            
            # Load fresh data from database using Flask app context
            with self.app.app_context():
                stocks = StockData.query.filter(
                    (StockData.pdh.isnot(None)) |
                    (StockData.pdl.isnot(None)) | 
                    (StockData.wkh.isnot(None)) |
                    (StockData.wkl.isnot(None))
                ).all()
                
                for stock in stocks:
                    levels = (stock.pdh, stock.pdl, stock.wkh, stock.wkl)
                    self.break_levels_cache[stock.symbol] = levels
                    
                logger.info(f"Refreshed break levels cache for {len(self.break_levels_cache)} symbols")
            
        except Exception as e:
            logger.error(f"Error refreshing break levels cache: {str(e)}")
    
    def refresh_avg_volume_cache(self):
        """Refresh the average volume cache from database for RVOL calculation"""
        if not self.app:
            return
            
        try:
            from datetime import date, timedelta
            from sqlalchemy import text, func
            
            # Get last 5 trading days
            end_date = date.today()
            start_date = end_date - timedelta(days=10)  # Look back 10 days to ensure 5 trading days
            
            with self.app.app_context():
                from models import db
                
                # Query to get 5-day average volume for all symbols
                query = text("""
                    SELECT 
                        symbol,
                        AVG(volume) as avg_5day_volume,
                        COUNT(*) as days_count
                    FROM hist_data_365
                    WHERE date >= :start_date 
                    AND date < :end_date
                    AND volume > 0
                    GROUP BY symbol
                    HAVING COUNT(*) >= 3
                """)
                
                result = db.session.execute(query, {
                    'start_date': start_date,
                    'end_date': end_date
                }).fetchall()
                
                # Clear and rebuild cache
                self.avg_volume_cache.clear()
                
                for record in result:
                    symbol = record.symbol
                    avg_volume = float(record.avg_5day_volume)
                    self.avg_volume_cache[symbol] = avg_volume
                
                self.last_rvol_avg_refresh = time.time()
                logger.info(f"Refreshed average volume cache for {len(self.avg_volume_cache)} symbols")
                
        except Exception as e:
            logger.error(f"Error refreshing average volume cache: {str(e)}")
    
    def _check_for_rvol_alerts(self, symbol, display_symbol, current_volume):
        """Check if RVOL crosses threshold levels (1x, 2x, 3x) and generate alerts"""
        try:
            # Refresh average volume cache periodically (every hour)
            if time.time() - self.last_rvol_avg_refresh > 3600:
                self.refresh_avg_volume_cache()
            
            # Only send alerts during market hours
            if not self.is_market_open():
                return
            
            # Skip if no valid volume data
            if current_volume <= 0:
                return
            
            # Get average volume from cache
            avg_volume = self.avg_volume_cache.get(display_symbol, 0)
            if avg_volume <= 0:
                return
            
            # Calculate RVOL
            rvol = current_volume / avg_volume
            
            # Create unique alert key for today
            alert_key = f"{symbol}_{int(time.time() // 86400)}"  # Daily unique key
            
            # Check threshold crossings: 1x, 2x, 3x
            thresholds = [
                (1.0, '1x'),
                (2.0, '2x'),
                (3.0, '3x')
            ]
            
            for threshold_value, threshold_label in thresholds:
                threshold_key = f"{alert_key}_RVOL_{threshold_label}"
                
                # Alert when RVOL crosses above threshold
                if rvol >= threshold_value and threshold_key not in self.rvol_alerts_sent:
                    alert = {
                        'type': 'rvol',
                        'symbol': display_symbol,
                        'rvol': round(rvol, 2),
                        'threshold': threshold_label,
                        'volume': current_volume,
                        'avg_volume': int(avg_volume),
                        'timestamp': int(time.time())
                    }
                    self._add_alert(alert)
                    self.rvol_alerts_sent[threshold_key] = True
                    logger.info(f"RVOL Alert: {display_symbol} crossed {threshold_label} (RVOL: {rvol:.2f})")
            
        except Exception as e:
            logger.error(f"Error checking RVOL alerts for {symbol}: {str(e)}")
    
    def get_current_5min_candle_time(self):
        """Get the current 5-minute candle start time in IST"""
        try:
            ist = pytz.timezone('Asia/Kolkata')
            now = datetime.now(ist)
            
            # Round down to nearest 5 minutes
            minutes = (now.minute // 5) * 5
            candle_time = now.replace(minute=minutes, second=0, microsecond=0)
            
            return candle_time
        except Exception as e:
            logger.error(f"Error getting 5-min candle time: {str(e)}")
            return None
    
    def update_5min_candle(self, symbol, ltp, open_price, high_price, low_price, volume):
        """Update the current 5-minute candle for a symbol"""
        try:
            candle_time = self.get_current_5min_candle_time()
            if not candle_time:
                return
            
            with self.candle_storage_lock:
                candle_key = f"{symbol}_{candle_time.strftime('%Y%m%d%H%M')}"
                
                if candle_key not in self.current_candles:
                    # New candle - initialize with first tick data
                    self.current_candles[candle_key] = {
                        'symbol': symbol,
                        'datetime': candle_time,
                        'open': ltp if ltp else open_price,
                        'high': ltp if ltp else high_price,
                        'low': ltp if ltp else low_price,
                        'close': ltp,
                        'volume': volume if volume else 0,
                        'tick_count': 1
                    }
                else:
                    # Update existing candle
                    candle = self.current_candles[candle_key]
                    
                    # Update high if current price is higher
                    if ltp and ltp > candle['high']:
                        candle['high'] = ltp
                    if high_price and high_price > candle['high']:
                        candle['high'] = high_price
                    
                    # Update low if current price is lower
                    if ltp and ltp < candle['low']:
                        candle['low'] = ltp
                    if low_price and low_price > 0 and low_price < candle['low']:
                        candle['low'] = low_price
                    
                    # Update close with latest price
                    if ltp:
                        candle['close'] = ltp
                    
                    # Update volume (use max to avoid decrements)
                    if volume and volume > candle['volume']:
                        candle['volume'] = volume
                    
                    candle['tick_count'] += 1
                
        except Exception as e:
            logger.error(f"Error updating 5-min candle for {symbol}: {str(e)}")
    
    def save_completed_candles(self):
        """Save completed 5-minute candles to database"""
        # Skip if no app instance (cannot access database)
        if not self.app:
            return
            
        try:
            from models import db
            from sqlalchemy import text
            
            candle_time = self.get_current_5min_candle_time()
            if not candle_time:
                return
            
            # Get candles that are from previous time periods (completed)
            completed_candles = []
            current_time_key = candle_time.strftime('%Y%m%d%H%M')
            
            with self.candle_storage_lock:
                keys_to_remove = []
                for candle_key, candle_data in self.current_candles.items():
                    candle_time_key = candle_key.split('_', 1)[1]
                    
                    # If this candle is from a previous time period, it's completed
                    if candle_time_key < current_time_key:
                        completed_candles.append(candle_data)
                        keys_to_remove.append(candle_key)
                
                # Remove completed candles from tracking
                for key in keys_to_remove:
                    del self.current_candles[key]
            
            # Save completed candles to database using Flask app context
            if completed_candles:
                with self.app.app_context():
                    saved_count = 0
                    for candle in completed_candles:
                        try:
                            # Check if record already exists
                            existing = db.session.execute(
                                text("SELECT id FROM hist_data_5min WHERE symbol = :symbol AND datetime_stamp = :datetime"),
                                {'symbol': candle['symbol'], 'datetime': candle['datetime']}
                            ).fetchone()
                            
                            if existing:
                                # Update existing record
                                db.session.execute(
                                    text("""
                                        UPDATE hist_data_5min 
                                        SET open = :open, high = :high, low = :low, close = :close, volume = :volume, source = :source
                                        WHERE symbol = :symbol AND datetime_stamp = :datetime
                                    """),
                                    {
                                        'symbol': candle['symbol'],
                                        'datetime': candle['datetime'],
                                        'open': candle['open'],
                                        'high': candle['high'],
                                        'low': candle['low'],
                                        'close': candle['close'],
                                        'volume': candle['volume'],
                                        'source': 'websocket_live'
                                    }
                                )
                            else:
                                # Insert new record
                                db.session.execute(
                                    text("""
                                        INSERT INTO hist_data_5min 
                                        (symbol, datetime_stamp, open, high, low, close, volume, source, created_at)
                                        VALUES (:symbol, :datetime, :open, :high, :low, :close, :volume, :source, CURRENT_TIMESTAMP)
                                    """),
                                    {
                                        'symbol': candle['symbol'],
                                        'datetime': candle['datetime'],
                                        'open': candle['open'],
                                        'high': candle['high'],
                                        'low': candle['low'],
                                        'close': candle['close'],
                                        'volume': candle['volume'],
                                        'source': 'websocket_live'
                                    }
                                )
                            saved_count += 1
                        except Exception as save_error:
                            logger.error(f"Error saving candle for {candle['symbol']}: {str(save_error)}")
                            continue
                    
                    # Commit all changes
                    db.session.commit()
                    logger.info(f"📊 Saved {saved_count} completed 5-minute candles to database")
                
        except Exception as e:
            logger.error(f"Error saving completed candles: {str(e)}")
            try:
                with self.app.app_context():
                    db.session.rollback()
            except:
                pass
