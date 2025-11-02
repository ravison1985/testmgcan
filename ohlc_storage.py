"""
OHLC Data Storage Manager
Handles storing and retrieving daily OHLC data to avoid Fyers API rate limits
"""

import logging
from datetime import datetime, date, time, timedelta
from typing import Dict, List, Optional, Tuple, Set
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import os

logger = logging.getLogger(__name__)

# Indian stock market holidays for 2025 (you can expand this list)
INDIAN_MARKET_HOLIDAYS_2025: Set[date] = {
    date(2025, 1, 26),   # Republic Day
    date(2025, 3, 14),   # Holi
    date(2025, 3, 29),   # Holi (Second Day)
    date(2025, 4, 10),   # Ram Navami
    date(2025, 4, 14),   # Dr. Babasaheb Ambedkar Jayanti / Mahavir Jayanti
    date(2025, 4, 18),   # Good Friday
    date(2025, 5, 1),    # Maharashtra Day / Labour Day
    date(2025, 8, 15),   # Independence Day
    date(2025, 9, 20),   # Ganesh Chaturthi (as mentioned by user)
    date(2025, 10, 2),   # Gandhi Jayanti
    date(2025, 11, 1),   # Diwali Balipratipada
    date(2025, 11, 7),   # Diwali
    date(2025, 11, 15),  # Guru Nanak Jayanti
    date(2025, 12, 25),  # Christmas Day
}

class OHLCStorage:
    """Manage daily OHLC data storage and retrieval"""
    
    def __init__(self, db_session):
        self.db = db_session
        
    def is_trading_day(self, check_date: date) -> bool:
        """
        Check if the given date is a trading day (not weekend or holiday)
        
        Args:
            check_date: Date to check
            
        Returns:
            bool: True if it's a trading day, False otherwise
        """
        # Check if it's a weekend (Saturday = 5, Sunday = 6)
        if check_date.weekday() >= 5:
            logger.info(f"📅 {check_date} is a weekend - Market closed")
            return False
            
        # Check if it's a holiday
        if check_date in INDIAN_MARKET_HOLIDAYS_2025:
            logger.info(f"📅 {check_date} is a market holiday - Market closed")
            return False
            
        return True
        
    def get_day_name(self, check_date: date) -> str:
        """
        Get the day name for a given date
        
        Args:
            check_date: Date to get day name for
            
        Returns:
            str: Day name (Monday, Tuesday, etc.)
        """
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        return day_names[check_date.weekday()]
        
    def store_daily_ohlc(self, symbol_data: Dict) -> bool:
        """
        Store daily OHLC data for a symbol (only on trading days)
        
        Args:
            symbol_data: Dict containing symbol, ohlc data, and date
            Format: {
                'symbol': 'RELIANCE',
                'full_symbol': 'NSE:RELIANCE-EQ',
                'open_price': 2500.0,
                'high_price': 2550.0,
                'low_price': 2490.0,
                'close_price': 2540.0,
                'volume': 1000000,
                'trading_date': '2025-09-16'
            }
        
        Returns:
            bool: True if stored successfully, False otherwise (including holidays)
        """
        try:
            # Convert string date to date object if needed
            trading_date = symbol_data['trading_date']
            if isinstance(trading_date, str):
                trading_date = datetime.strptime(trading_date, '%Y-%m-%d').date()
            
            # Check if it's a trading day
            if not self.is_trading_day(trading_date):
                logger.info(f"❌ Skipped storing OHLC data for {symbol_data['symbol']} on {trading_date} - Not a trading day")
                return False
            
            # Get day of week
            day_of_week = self.get_day_name(trading_date)
            
            # Use PostgreSQL UPSERT to avoid conflicts
            query = text("""
                INSERT INTO daily_ohlc_data 
                (symbol, full_symbol, trading_date, day_of_week, open_price, high_price, low_price, close_price, volume)
                VALUES (:symbol, :full_symbol, :trading_date, :day_of_week, :open_price, :high_price, :low_price, :close_price, :volume)
                ON CONFLICT (symbol, trading_date) 
                DO UPDATE SET 
                    full_symbol = EXCLUDED.full_symbol,
                    day_of_week = EXCLUDED.day_of_week,
                    open_price = EXCLUDED.open_price,
                    high_price = EXCLUDED.high_price,
                    low_price = EXCLUDED.low_price,
                    close_price = EXCLUDED.close_price,
                    volume = EXCLUDED.volume,
                    updated_at = NOW()
            """)
            
            self.db.execute(query, {
                'symbol': symbol_data['symbol'],
                'full_symbol': symbol_data['full_symbol'],
                'trading_date': trading_date,
                'day_of_week': day_of_week,
                'open_price': float(symbol_data['open_price']),
                'high_price': float(symbol_data['high_price']),
                'low_price': float(symbol_data['low_price']),
                'close_price': float(symbol_data['close_price']),
                'volume': int(symbol_data.get('volume', 0))
            })
            self.db.commit()
            
            logger.info(f"✅ Stored OHLC data for {symbol_data['symbol']} on {trading_date} ({day_of_week})")
            return True
            
        except Exception as e:
            logger.error(f"Error storing OHLC data for {symbol_data.get('symbol', 'unknown')}: {str(e)}")
            self.db.rollback()
            return False
    
    def store_bulk_ohlc_data(self, symbols_data: List[Dict]) -> int:
        """
        Store multiple symbols OHLC data in bulk
        
        Args:
            symbols_data: List of symbol data dictionaries
        
        Returns:
            int: Number of records successfully stored
        """
        stored_count = 0
        for symbol_data in symbols_data:
            if self.store_daily_ohlc(symbol_data):
                stored_count += 1
        
        logger.info(f"Bulk stored OHLC data for {stored_count}/{len(symbols_data)} symbols")
        return stored_count
    
    def get_ohlc_data(self, symbol: str, trading_date: Optional[date] = None) -> Optional[Dict]:
        """
        Retrieve OHLC data for a symbol on a specific date
        
        Args:
            symbol: Symbol name (e.g., 'RELIANCE')
            trading_date: Trading date (defaults to current date)
        
        Returns:
            Dict with OHLC data or None if not found
        """
        try:
            if trading_date is None:
                trading_date = date.today()
            
            query = text("""
                SELECT symbol, full_symbol, trading_date, 
                       open_price, high_price, low_price, close_price, volume,
                       created_at, updated_at
                FROM daily_ohlc_data 
                WHERE symbol = :symbol AND trading_date = :trading_date
            """)
            
            result = self.db.execute(query, {
                'symbol': symbol,
                'trading_date': trading_date
            }).fetchone()
            
            if result:
                return {
                    'symbol': result.symbol,
                    'full_symbol': result.full_symbol,
                    'trading_date': result.trading_date,
                    'open_price': float(result.open_price),
                    'high_price': float(result.high_price),
                    'low_price': float(result.low_price),
                    'close_price': float(result.close_price),
                    'volume': int(result.volume),
                    'created_at': result.created_at,
                    'updated_at': result.updated_at
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving OHLC data for {symbol}: {str(e)}")
            return None
    
    def get_bulk_ohlc_data(self, symbols: List[str], trading_date: Optional[date] = None) -> Dict[str, Dict]:
        """
        Retrieve OHLC data for multiple symbols
        
        Args:
            symbols: List of symbol names
            trading_date: Trading date (defaults to current date)
        
        Returns:
            Dict mapping symbol -> OHLC data
        """
        try:
            if trading_date is None:
                trading_date = date.today()
            
            # Create placeholders for IN clause
            placeholders = ', '.join([f':symbol_{i}' for i in range(len(symbols))])
            
            query = text(f"""
                SELECT symbol, full_symbol, trading_date,
                       open_price, high_price, low_price, close_price, volume
                FROM daily_ohlc_data 
                WHERE symbol IN ({placeholders}) AND trading_date = :trading_date
            """)
            
            # Create parameters dict
            params = {'trading_date': str(trading_date)}
            for i, symbol in enumerate(symbols):
                params[f'symbol_{i}'] = symbol
            
            results = self.db.execute(query, params).fetchall()
            
            ohlc_data = {}
            for result in results:
                ohlc_data[result.symbol] = {
                    'symbol': result.symbol,
                    'full_symbol': result.full_symbol,
                    'trading_date': result.trading_date,
                    'open_price': float(result.open_price),
                    'high_price': float(result.high_price),
                    'low_price': float(result.low_price),
                    'close_price': float(result.close_price),
                    'volume': int(result.volume)
                }
            
            logger.info(f"Retrieved OHLC data for {len(ohlc_data)}/{len(symbols)} symbols on {trading_date}")
            return ohlc_data
            
        except Exception as e:
            logger.error(f"Error retrieving bulk OHLC data: {str(e)}")
            return {}
    
    def save_current_live_data_as_ohlc(self, websocket_data: Dict, trading_date: Optional[date] = None) -> int:
        """
        Convert current WebSocket live data to OHLC format and store in BOTH daily_ohlc_data and hist_data_365 (only on trading days)
        
        Args:
            websocket_data: Current live data from WebSocket
            trading_date: Trading date (defaults to current date)
        
        Returns:
            int: Number of symbols stored (0 if not a trading day)
        """
        if trading_date is None:
            trading_date = date.today()
        
        # Check if today is a trading day before processing any data
        if not self.is_trading_day(trading_date):
            day_name = self.get_day_name(trading_date)
            logger.info(f"🚫 EOD Save skipped on {trading_date} ({day_name}) - Market is closed (holiday/weekend)")
            return 0
        
        stored_count = 0
        day_name = self.get_day_name(trading_date)
        
        for symbol, data in websocket_data.items():
            try:
                # Clean symbol name
                clean_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                
                ohlc_data = {
                    'symbol': clean_symbol,
                    'full_symbol': data.get('full_symbol', symbol),
                    'trading_date': trading_date,
                    'open_price': data.get('open_price', data.get('ltp', 0)),
                    'high_price': data.get('high_price', data.get('ltp', 0)),
                    'low_price': data.get('low_price', data.get('ltp', 0)),
                    'close_price': data.get('ltp', 0),  # Use LTP as close price
                    'volume': data.get('volume', 0)
                }
                
                # Only store if we have valid price data
                if ohlc_data['close_price'] > 0:
                    # Save to daily_ohlc_data table
                    if self.store_daily_ohlc(ohlc_data):
                        stored_count += 1
                    
                    # ALSO save to hist_data_365 table
                    self.store_to_hist_data_365(ohlc_data, day_name)
                        
            except Exception as e:
                logger.error(f"Error converting live data for {symbol}: {str(e)}")
        
        logger.info(f"📊 Stored current live data as OHLC for {stored_count} symbols on {trading_date} ({day_name}) in BOTH tables")
        return stored_count
    
    def store_to_hist_data_365(self, ohlc_data: Dict, day_name: str) -> bool:
        """
        Store OHLC data to hist_data_365 table
        
        Args:
            ohlc_data: Dict containing symbol, ohlc data, and date
            day_name: Day of week name
        
        Returns:
            bool: True if stored successfully, False otherwise
        """
        try:
            # Create datetime from trading_date
            trading_date = ohlc_data['trading_date']
            datetime_stamp = datetime.combine(trading_date, datetime.min.time())
            
            # Use PostgreSQL UPSERT to avoid conflicts
            query = text("""
                INSERT INTO hist_data_365 
                (symbol, date, datetime_stamp, open, high, low, close, volume, timeframe, source, day_of_week)
                VALUES (:symbol, :date, :datetime_stamp, :open, :high, :low, :close, :volume, :timeframe, :source, :day_of_week)
                ON CONFLICT (symbol, date, timeframe) 
                DO UPDATE SET 
                    datetime_stamp = EXCLUDED.datetime_stamp,
                    open = EXCLUDED.open,
                    high = EXCLUDED.high,
                    low = EXCLUDED.low,
                    close = EXCLUDED.close,
                    volume = EXCLUDED.volume,
                    source = EXCLUDED.source,
                    day_of_week = EXCLUDED.day_of_week
            """)
            
            self.db.execute(query, {
                'symbol': ohlc_data['symbol'],
                'date': trading_date,
                'datetime_stamp': datetime_stamp,
                'open': float(ohlc_data['open_price']),
                'high': float(ohlc_data['high_price']),
                'low': float(ohlc_data['low_price']),
                'close': float(ohlc_data['close_price']),
                'volume': int(ohlc_data.get('volume', 0)),
                'timeframe': '1D',
                'source': 'live_websocket_eod',
                'day_of_week': day_name
            })
            self.db.commit()
            
            logger.debug(f"✅ Stored hist_data_365 for {ohlc_data['symbol']} on {trading_date}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing hist_data_365 for {ohlc_data.get('symbol', 'unknown')}: {str(e)}")
            self.db.rollback()
            return False
    
    def is_market_eod_time(self) -> bool:
        """
        Check if current time is End of Day (after 3:45 PM IST)
        
        Returns:
            bool: True if it's EOD time
        """
        now = datetime.now()
        eod_time = time(15, 45)  # 3:45 PM
        return now.time() >= eod_time
    
    def get_available_dates(self, symbol: str) -> List[date]:
        """
        Get all available trading dates for a symbol
        
        Args:
            symbol: Symbol name
        
        Returns:
            List of dates with OHLC data
        """
        try:
            query = text("""
                SELECT DISTINCT trading_date 
                FROM daily_ohlc_data 
                WHERE symbol = :symbol 
                ORDER BY trading_date DESC
            """)
            
            results = self.db.execute(query, {'symbol': symbol}).fetchall()
            return [result.trading_date for result in results]
            
        except Exception as e:
            logger.error(f"Error getting available dates for {symbol}: {str(e)}")
            return []
    
    def cleanup_old_data(self, days_to_keep: int = 365) -> int:
        """
        Clean up OHLC data older than specified days
        
        Args:
            days_to_keep: Number of days to keep (default 365)
        
        Returns:
            int: Number of records deleted
        """
        try:
            query = text("""
                DELETE FROM daily_ohlc_data 
                WHERE trading_date < CURRENT_DATE - INTERVAL '%s days'
            """ % days_to_keep)
            
            result = self.db.execute(query)
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old OHLC records")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old OHLC data: {str(e)}")
            self.db.rollback()
            return 0
    
    def get_week_boundaries(self, check_date: date) -> Tuple[date, date]:
        """
        Get the Monday (start) and Friday (end) of the week for a given date
        
        Args:
            check_date: Date to find the week for
            
        Returns:
            Tuple of (week_start_date, week_end_date)
        """
        # Get Monday of the week (weekday 0)
        monday = check_date - timedelta(days=check_date.weekday())
        # Get Friday of the week  
        friday = monday + timedelta(days=4)
        return monday, friday
    
    def create_weekly_data_from_daily(self, symbol: Optional[str] = None, start_date: Optional[date] = None, end_date: Optional[date] = None) -> int:
        """
        Create weekly OHLC data by aggregating daily data from hist_data_365 table
        
        Args:
            symbol: Specific symbol to process (None for all symbols)
            start_date: Start date for processing (None for all available data)
            end_date: End date for processing (None for all available data)
            
        Returns:
            int: Number of weekly records created
        """
        try:
            # Build the base query
            where_conditions = []
            params = {}
            
            if symbol:
                where_conditions.append("symbol = :symbol")
                params['symbol'] = symbol
                
            if start_date:
                where_conditions.append("date >= :start_date")
                params['start_date'] = start_date
                
            if end_date:
                where_conditions.append("date <= :end_date")
                params['end_date'] = end_date
            
            # Always filter for daily timeframe data (hist_data_365 uses 'timeframe' instead of 'resolution')
            where_conditions.append("timeframe = :timeframe")
            params['timeframe'] = '1D'
            
            where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
            
            # Get all daily data from hist_data_365 table grouped by symbol and ordered by date
            query = text(f"""
                SELECT symbol, symbol as full_symbol, date as trading_date,
                       open as open_price, high as high_price, low as low_price, 
                       close as close_price, COALESCE(volume, 0) as volume
                FROM hist_data_365 
                {where_clause}
                ORDER BY symbol, date
            """)
            
            results = self.db.execute(query, params).fetchall()
            
            if not results:
                logger.info("No daily historical data (1D timeframe) found in hist_data_365 for weekly aggregation")
                return 0
            
            # Group data by symbol and week
            weekly_data = {}
            
            for row in results:
                symbol_name = row.symbol
                trading_date = row.trading_date
                
                # Get week boundaries
                week_start, week_end = self.get_week_boundaries(trading_date)
                
                # Create week key
                week_key = (symbol_name, week_start, week_end)
                
                if week_key not in weekly_data:
                    # Initialize week data
                    weekly_data[week_key] = {
                        'symbol': symbol_name,
                        'full_symbol': row.full_symbol,
                        'week_start_date': week_start,
                        'week_end_date': week_end,
                        'year': trading_date.year,
                        'week_number': trading_date.isocalendar()[1],  # ISO week number
                        'daily_records': [],
                        'total_volume': 0,
                        'trading_days_count': 0
                    }
                
                # Add daily record to the week
                weekly_data[week_key]['daily_records'].append({
                    'date': trading_date,
                    'open': float(row.open_price),
                    'high': float(row.high_price),
                    'low': float(row.low_price),
                    'close': float(row.close_price),
                    'volume': int(row.volume)
                })
                
                weekly_data[week_key]['total_volume'] += int(row.volume)
                weekly_data[week_key]['trading_days_count'] += 1
            
            # Create weekly records
            created_count = 0
            
            for week_key, week_info in weekly_data.items():
                daily_records = week_info['daily_records']
                
                # Sort by date to ensure correct order
                daily_records.sort(key=lambda x: x['date'])
                
                # Calculate weekly OHLC
                weekly_open = daily_records[0]['open']  # First day's open
                weekly_high = max(record['high'] for record in daily_records)  # Highest high
                weekly_low = min(record['low'] for record in daily_records)    # Lowest low
                weekly_close = daily_records[-1]['close']  # Last day's close
                
                # Insert or update weekly record
                upsert_query = text("""
                    INSERT INTO weekly_ohlc_data 
                    (symbol, full_symbol, week_start_date, week_end_date, year, week_number,
                     open_price, high_price, low_price, close_price, volume, trading_days_count)
                    VALUES (:symbol, :full_symbol, :week_start_date, :week_end_date, :year, :week_number,
                            :open_price, :high_price, :low_price, :close_price, :volume, :trading_days_count)
                    ON CONFLICT (symbol, week_start_date) 
                    DO UPDATE SET 
                        full_symbol = EXCLUDED.full_symbol,
                        week_end_date = EXCLUDED.week_end_date,
                        year = EXCLUDED.year,
                        week_number = EXCLUDED.week_number,
                        open_price = EXCLUDED.open_price,
                        high_price = EXCLUDED.high_price,
                        low_price = EXCLUDED.low_price,
                        close_price = EXCLUDED.close_price,
                        volume = EXCLUDED.volume,
                        trading_days_count = EXCLUDED.trading_days_count,
                        updated_at = NOW()
                """)
                
                self.db.execute(upsert_query, {
                    'symbol': week_info['symbol'],
                    'full_symbol': week_info['full_symbol'],
                    'week_start_date': week_info['week_start_date'],
                    'week_end_date': week_info['week_end_date'],
                    'year': week_info['year'],
                    'week_number': week_info['week_number'],
                    'open_price': weekly_open,
                    'high_price': weekly_high,
                    'low_price': weekly_low,
                    'close_price': weekly_close,
                    'volume': week_info['total_volume'],
                    'trading_days_count': week_info['trading_days_count']
                })
                
                created_count += 1
                
                logger.debug(f"Created weekly data for {week_info['symbol']} week {week_info['week_start_date']} to {week_info['week_end_date']}")
            
            self.db.commit()
            logger.info(f"📊 Created {created_count} weekly OHLC records from daily data")
            return created_count
            
        except Exception as e:
            logger.error(f"Error creating weekly data from daily: {str(e)}")
            self.db.rollback()
            return 0
    
    def get_weekly_data_summary(self) -> Dict:
        """
        Get summary statistics of weekly OHLC data
        
        Returns:
            Dict with summary statistics
        """
        try:
            query = text("""
                SELECT 
                    COUNT(*) as total_records,
                    COUNT(DISTINCT symbol) as unique_symbols,
                    MIN(week_start_date) as earliest_week,
                    MAX(week_end_date) as latest_week,
                    AVG(trading_days_count) as avg_trading_days_per_week
                FROM weekly_ohlc_data
            """)
            
            result = self.db.execute(query).fetchone()
            
            if result:
                return {
                    'total_records': result.total_records or 0,
                    'unique_symbols': result.unique_symbols or 0,
                    'earliest_week': result.earliest_week.isoformat() if result.earliest_week else None,
                    'latest_week': result.latest_week.isoformat() if result.latest_week else None,
                    'avg_trading_days_per_week': round(float(result.avg_trading_days_per_week), 2) if result.avg_trading_days_per_week else 0
                }
            
            return {
                'total_records': 0,
                'unique_symbols': 0,
                'earliest_week': None,
                'latest_week': None,
                'avg_trading_days_per_week': 0
            }
            
        except Exception as e:
            logger.error(f"Error getting weekly data summary: {str(e)}")
            return {
                'total_records': 0,
                'unique_symbols': 0,
                'earliest_week': None,
                'latest_week': None,
                'avg_trading_days_per_week': 0
            }