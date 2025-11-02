import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from fyers_apiv3 import fyersModel
from models import db, HistoricalData, DataFetchLog
from config import Config

logger = logging.getLogger(__name__)

class HistoricalDataManager:
    """Manages fetching and storing historical stock data from Fyers API"""
    
    def __init__(self, access_token: Optional[str] = None, use_hist_auth: bool = False):
        self.access_token = access_token
        self.use_hist_auth = use_hist_auth
        self.client_id = Config.HIST_CLIENT_ID if use_hist_auth else Config.CLIENT_ID
        self.fyers = None
        if access_token:
            self._initialize_fyers_client()
        
    def get_fresh_token(self):
        """Get a fresh token specifically for historical data from database"""
        try:
            from models import AccessToken
            # Use the appropriate client_id based on authentication type
            target_client_id = self.client_id
            
            # Get the most recent valid token from database
            stored_token = AccessToken.query.filter_by(
                client_id=target_client_id,
                is_active=True
            ).order_by(AccessToken.created_at.desc()).first()
            
            if stored_token and stored_token.is_valid():
                auth_type = "historical data" if self.use_hist_auth else "regular"
                logger.info(f"Using stored valid {auth_type} token for historical data")
                return stored_token.token
            else:
                auth_type = "historical data" if self.use_hist_auth else "regular"
                logger.warning(f"No valid stored {auth_type} token found for historical data")
                return None
        except Exception as e:
            logger.error(f"Error getting fresh token for historical data: {str(e)}")
            return None
    
    def _initialize_fyers_client(self):
        """Initialize Fyers API client"""
        try:
            if not self.access_token:
                raise ValueError("Access token is required to initialize Fyers client")
                
            self.fyers = fyersModel.FyersModel(
                client_id=self.client_id,
                token=self.access_token,
                log_path=""
            )
            logger.info("Fyers client initialized for historical data")
        except Exception as e:
            logger.error(f"Error initializing Fyers client: {str(e)}")
            raise
    
    def fetch_historical_data(self, symbol: str, resolution: str, 
                            range_from: datetime, range_to: datetime) -> Optional[List[Dict]]:
        """
        Fetch historical data from Fyers API
        
        Args:
            symbol: Stock symbol (can be cleaned like 'RELIANCE' or full like 'NSE:RELIANCE-EQ')
            resolution: Time resolution ('1', '5', '15', '30', '60', '240', '1D')
            range_from: Start datetime
            range_to: End datetime
        
        Returns:
            List of candle data dictionaries or None if error
        """
        try:
            # Ensure proper time range - avoid current day for complete candles
            if range_to.date() >= datetime.now().date():
                range_to = datetime.now().replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(minutes=1)
            
            # Convert datetime to date string format (YYYY-MM-DD)
            from_date = range_from.strftime('%Y-%m-%d')
            to_date = range_to.strftime('%Y-%m-%d')
            
            # Validate time range
            if range_from >= range_to:
                logger.error(f"Invalid time range for {symbol}: from {range_from} to {range_to}")
                return None
            
            # Convert symbol to proper Fyers API format if it's a cleaned symbol
            api_symbol = symbol
            if not symbol.startswith(('NSE:', 'BSE:')):
                # This is a cleaned symbol, convert to proper format
                if 'NIFTY' in symbol.upper() or 'VIX' in symbol.upper():
                    api_symbol = f"NSE:{symbol}-INDEX"
                elif 'SENSEX' in symbol.upper():
                    api_symbol = f"BSE:{symbol}-INDEX"
                else:
                    api_symbol = f"NSE:{symbol}-EQ"
            
            # Prepare request data - use date string format
            data = {
                "symbol": api_symbol,
                "resolution": resolution,
                "date_format": "1",  # Date string format (YYYY-MM-DD)
                "range_from": from_date,
                "range_to": to_date,
                "cont_flag": "1"
            }
            
            logger.info(f"🔍 API Request for {symbol}: from {from_date} to {to_date}, resolution: {resolution}")
            logger.info(f"🔍 Full request data: {data}")
            
            # Fetch data from Fyers API
            if self.fyers is None:
                logger.error("Fyers client not initialized")
                return None
                
            response = self.fyers.history(data)
            
            if isinstance(response, dict) and response.get('s') == 'ok':
                candles = response.get('candles', [])
                logger.info(f"✅ Successfully fetched {len(candles)} candles for {symbol}")
                return candles
            else:
                error_msg = response.get('message', 'Unknown error') if isinstance(response, dict) else 'Invalid response'
                logger.error(f"Fyers API error for symbol {symbol}: {error_msg}")
                logger.error(f"Full API response: {response}")
                return None
                
        except Exception as e:
            logger.error(f"Exception fetching historical data for {symbol}: {str(e)}")
            return None
    
    def store_historical_data(self, symbol: str, resolution: str, candles: List) -> int:
        """
        Store historical candle data in database
        
        Args:
            symbol: Stock symbol
            resolution: Time resolution
            candles: List of candle data [timestamp, open, high, low, close, volume]
        
        Returns:
            Number of records stored
        """
        try:
            if not candles:
                return 0
                
            stored_count = 0
            full_symbol = symbol
            display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            # OPTIMIZATION: Pre-fetch all existing records for this symbol and resolution
            # to avoid individual database queries for each candle
            existing_records = {}
            try:
                existing_data = HistoricalData.query.filter_by(
                    symbol=display_symbol,
                    resolution=resolution
                ).all()
                
                # Create a lookup dictionary by candle_time
                for record in existing_data:
                    existing_records[record.candle_time] = record
                    
            except Exception as e:
                logger.warning(f"Could not pre-fetch existing records for {symbol}: {str(e)}")
            
            # Process candles using pre-fetched data for fast lookups
            records_to_add = []
            records_to_update = []
            
            for candle in candles:
                try:
                    # Parse candle data: [timestamp, open, high, low, close, volume]
                    if len(candle) < 5:
                        logger.warning(f"Invalid candle data: {candle}")
                        continue
                    
                    timestamp = candle[0]
                    open_price = float(candle[1])
                    high_price = float(candle[2])
                    low_price = float(candle[3])
                    close_price = float(candle[4])
                    volume = int(candle[5]) if len(candle) > 5 else 0
                    
                    # Convert timestamp to datetime
                    candle_time = datetime.fromtimestamp(timestamp)
                    
                    # Calculate day of week
                    day_of_week = candle_time.strftime('%A')  # Monday, Tuesday, etc.
                    
                    # Fast lookup in pre-fetched data (no database query!)
                    existing = existing_records.get(candle_time)
                    
                    if existing:
                        # Update existing record
                        existing.open_price = open_price
                        existing.high_price = high_price
                        existing.low_price = low_price
                        existing.close_price = close_price
                        existing.volume = volume
                        existing.day_of_week = day_of_week
                        records_to_update.append(existing)
                    else:
                        # Create new record for batch insert
                        historical_data = HistoricalData()
                        historical_data.symbol = display_symbol
                        historical_data.full_symbol = full_symbol
                        historical_data.resolution = resolution
                        historical_data.open_price = open_price
                        historical_data.high_price = high_price
                        historical_data.low_price = low_price
                        historical_data.close_price = close_price
                        historical_data.volume = volume
                        historical_data.candle_time = candle_time
                        historical_data.day_of_week = day_of_week
                        records_to_add.append(historical_data)
                    
                    stored_count += 1
                    
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error processing candle {candle}: {str(e)}")
                    continue
            
            # Batch operations: add all new records at once
            if records_to_add:
                db.session.add_all(records_to_add)
            
            # Single commit for all operations
            db.session.commit()
            logger.debug(f"Stored {stored_count} historical records for {symbol} ({len(records_to_add)} new, {len(records_to_update)} updated)")
            return stored_count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error storing historical data for {symbol}: {str(e)}")
            return 0
    
    def fetch_and_store_historical_data(self, symbol: str, resolution: str,
                                      range_from: datetime, range_to: datetime) -> bool:
        """
        Fetch historical data from API and store in database
        
        Args:
            symbol: Stock symbol
            resolution: Time resolution
            range_from: Start datetime
            range_to: End datetime
        
        Returns:
            True if successful, False otherwise
        """
        # Check if symbol is in excluded list
        from config import Config
        if symbol in Config.EXCLUDED_SYMBOLS:
            logger.warning(f"⚠️ Skipping excluded symbol {symbol} (known API issues)")
            return False
        
        display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
        
        # Create fetch log entry
        fetch_log = DataFetchLog()
        fetch_log.symbol = display_symbol
        fetch_log.resolution = resolution
        fetch_log.range_from = range_from
        fetch_log.range_to = range_to
        fetch_log.status = 'pending'
        db.session.add(fetch_log)
        db.session.commit()
        
        try:
            # Ensure we have a valid token for historical data
            if not self.access_token:
                self.access_token = self.get_fresh_token()
                if self.access_token:
                    self._initialize_fyers_client()
                else:
                    fetch_log.status = 'error'
                    fetch_log.error_message = 'No valid token available for historical data'
                    fetch_log.records_fetched = 0
                    db.session.commit()
                    logger.error(f"No valid token for historical data fetch of {symbol}")
                    return False
            
            # Fetch data from API
            candles = self.fetch_historical_data(symbol, resolution, range_from, range_to)
            
            if candles is None:
                # Update log with error
                fetch_log.status = 'error'
                fetch_log.error_message = 'Failed to fetch data from API'
                fetch_log.records_fetched = 0
                db.session.commit()
                logger.warning(f"Skipping {symbol} due to API fetch failure, continuing with next symbol")
                return False
            
            # Store data in database
            stored_count = self.store_historical_data(symbol, resolution, candles)
            
            # Update log with success
            fetch_log.status = 'success'
            fetch_log.records_fetched = stored_count
            db.session.commit()
            
            logger.info(f"✅ {symbol}: {stored_count} candles stored | Range: {range_from.strftime('%Y-%m-%d')} to {range_to.strftime('%Y-%m-%d')} | Resolution: {resolution}")
            return True
            
        except Exception as e:
            # Update log with error
            fetch_log.status = 'error'
            fetch_log.error_message = str(e)
            fetch_log.records_fetched = 0
            db.session.commit()
            logger.error(f"Error in fetch_and_store_historical_data for {symbol}: {str(e)}")
            logger.warning(f"Skipping {symbol} due to error, continuing with next symbol")
            return False
    
    def fetch_bulk_historical_data(self, symbols: List[str], resolution: str,
                                 days_back: int = 30) -> Dict[str, bool]:
        """
        Fetch historical data for multiple symbols
        
        Args:
            symbols: List of stock symbols
            resolution: Time resolution
            days_back: Number of days to fetch data for
        
        Returns:
            Dictionary with symbol as key and success status as value
        """
        results = {}
        
        # Import Config to check excluded symbols
        from config import Config
        
        # Filter out excluded symbols that are known to cause API errors
        filtered_symbols = []
        for symbol in symbols:
            if symbol in Config.EXCLUDED_SYMBOLS:
                logger.warning(f"⚠️ Skipping excluded symbol {symbol} (known API issues)")
                results[symbol] = False  # Mark as failed but continue
            else:
                filtered_symbols.append(symbol)
        
        logger.info(f"📊 Filtered {len(symbols) - len(filtered_symbols)} excluded symbols, processing {len(filtered_symbols)} symbols")
        
        # Filter out symbols that already have data to focus on missing ones
        symbols_to_process = []
        for symbol in filtered_symbols:
            display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            existing_count = HistoricalData.query.filter_by(
                symbol=display_symbol,
                resolution=resolution
            ).count()
            
            # Check if symbol has enough data for the requested days_back period
            # Add some buffer (e.g., 5 extra days) to account for weekends/holidays
            required_records = days_back + 5
            if existing_count < required_records:  # Need to fetch data for this symbol
                symbols_to_process.append(symbol)
        
        logger.info(f"Found {len(symbols_to_process)} symbols needing historical data out of {len(symbols)} total")
        
        # Process all symbols that need data (no batch limit for parallel processing)
        if len(symbols_to_process) > 25:
            logger.info(f"Processing {len(symbols_to_process)} symbols needing historical data")
        # Remove batch limiting - process all symbols that need data
        
        if not symbols_to_process:
            logger.info("All symbols already have sufficient historical data")
            return {}
        
        symbols = symbols_to_process
        
        # Calculate time range based on resolution
        now = datetime.now()
        
        # For daily data, go back to previous market close
        if resolution == '1D':
            range_to = now.replace(hour=15, minute=30, second=0, microsecond=0) - timedelta(days=1)
            range_from = range_to - timedelta(days=days_back)
        else:
            # For intraday data, ensure we don't fetch current incomplete candle
            range_to = now - timedelta(minutes=int(resolution) if resolution.isdigit() else 1)
            range_from = range_to - timedelta(days=days_back)
        
        logger.info(f"📊 Fetching bulk historical data for {len(symbols)} symbols")
        logger.info(f"📅 Resolution: {resolution} | Date range: {range_from.strftime('%Y-%m-%d %H:%M')} to {range_to.strftime('%Y-%m-%d %H:%M')} | Duration: {days_back} days")
        
        # Process all symbols in parallel batches for better performance  
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        import gc
        
        def fetch_single_symbol(symbol):
            """Fetch historical data for a single symbol with Flask app context"""
            try:
                # Import Flask app for application context
                from app import app
                
                # Run within Flask application context for database access
                with app.app_context():
                    success = self.fetch_and_store_historical_data(
                        symbol, resolution, range_from, range_to
                    )
                    return symbol, success
            except Exception as e:
                logger.error(f"Error processing {symbol}: {str(e)}")
                return symbol, False
        
        logger.info(f"Starting parallel processing of {len(symbols)} symbols with max 10 threads")
        processed_count = 0
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all symbols for processing
            future_to_symbol = {executor.submit(fetch_single_symbol, symbol): symbol for symbol in symbols}
            
            # Collect results as they complete
            for future in as_completed(future_to_symbol):
                symbol, success = future.result()
                results[symbol] = success
                processed_count += 1
                
                # Update progress every 10 symbols instead of every symbol
                if processed_count % 10 == 0 or processed_count == len(symbols):
                    successful_count = len([v for v in results.values() if v])
                    progress_pct = round((processed_count / len(symbols)) * 100, 1)
                    logger.info(f"📈 Progress: {processed_count}/{len(symbols)} symbols processed ({successful_count} successful, {processed_count-successful_count} failed) | {progress_pct}% complete | Date range: {range_from.strftime('%Y-%m-%d')} to {range_to.strftime('%Y-%m-%d')}")
                
                logger.debug(f"Completed {processed_count}/{len(symbols)}: {symbol} - {'Success' if success else 'Failed'}")
                
                # Memory cleanup every 5 symbols
                if processed_count % 5 == 0:
                    gc.collect()
                    # Commit is handled within each worker thread's app context
                    logger.info(f"Processed {processed_count}/{len(symbols)} symbols")
        
        # Final cleanup - commits are handled within each worker thread's app context
        gc.collect()
        logger.info(f"Parallel processing completed: {len([v for v in results.values() if v])}/{len(results)} successful")
        
        return results
    
    def get_historical_data(self, symbol: str, resolution: str,
                          limit: int = 100) -> List[Dict]:
        """
        Get historical data from database
        
        Args:
            symbol: Stock symbol (display name)
            resolution: Time resolution
            limit: Maximum number of records to return
        
        Returns:
            List of historical data dictionaries
        """
        try:
            records = HistoricalData.query.filter_by(
                symbol=symbol,
                resolution=resolution
            ).order_by(HistoricalData.candle_time.desc()).limit(limit).all()
            
            return [record.to_dict() for record in records]
            
        except Exception as e:
            logger.error(f"Error getting historical data for {symbol}: {str(e)}")
            return []
    
    def get_fetch_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent fetch log entries"""
        try:
            logs = DataFetchLog.query.order_by(
                DataFetchLog.created_at.desc()
            ).limit(limit).all()
            
            return [log.to_dict() for log in logs]
            
        except Exception as e:
            logger.error(f"Error getting fetch logs: {str(e)}")
            return []