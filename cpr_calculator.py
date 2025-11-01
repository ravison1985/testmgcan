import logging
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timezone, date

logger = logging.getLogger(__name__)


class CprCalculator:
    """
    Central Pivot Range (CPR) Calculator
    
    CPR formulas:
    - Pivot Point (PP) = (High + Low + Close) / 3
    - Top Central (TC) = (PP - BC) + PP = 2*PP - BC
    - Bottom Central (BC) = (High + Low) / 2
    - R1 = 2*PP - Low
    - R2 = PP + (High - Low)
    - R3 = High + 2*(PP - Low)
    - S1 = 2*PP - High
    - S2 = PP - (High - Low)
    - S3 = Low - 2*(High - PP)
    """

    def __init__(self):
        self.levels = {}

    def calculate_cpr_levels(self, symbol: str, high: float, low: float,
                             close: float) -> Optional[Dict]:
        """Calculate CPR levels for a symbol using H, L, C data"""
        try:
            # Basic CPR calculations
            pp = (high + low + close) / 3  # Pivot Point
            bc = (high + low) / 2  # Bottom Central
            tc = (2 * pp) - bc  # Top Central

            # Support and Resistance levels
            r1 = (2 * pp) - low
            r2 = pp + (high - low)
            r3 = high + (2 * (pp - low))

            s1 = (2 * pp) - high
            s2 = pp - (high - low)
            s3 = low - (2 * (high - pp))

            levels = {
                'symbol': symbol,
                'pp': pp,
                'tc': tc,
                'bc': bc,
                'r1': r1,
                'r2': r2,
                'r3': r3,
                's1': s1,
                's2': s2,
                's3': s3,
                'high': high,
                'low': low,
                'prev_close': close,
                'calculated_at': datetime.now(timezone.utc)
            }

            self.levels[symbol] = levels
            logger.info(f"CPR levels calculated for {symbol}")
            return levels

        except Exception as e:
            logger.error(f"Error calculating CPR levels for {symbol}: {e}")
            return {}

    def determine_break_level(self, symbol: str, current_ltp: float) -> Optional[str]:
        """Determine which CPR level is broken"""
        if symbol not in self.levels:
            return None

        levels = self.levels[symbol]

        # Check which level is broken
        # Check resistance breaks
        if current_ltp > levels['r3']:
            return 'R3'
        elif current_ltp > levels['r2']:
            return 'R2'
        elif current_ltp > levels['r1']:
            return 'R1'
        elif current_ltp > levels['tc']:
            return 'TC'
        # Check support breaks
        elif current_ltp < levels['s3']:
            return 'S3'
        elif current_ltp < levels['s2']:
            return 'S2'
        elif current_ltp < levels['s1']:
            return 'S1'
        elif current_ltp < levels['bc']:
            return 'BC'
        # Inside CPR range
        elif levels['bc'] <= current_ltp <= levels['tc']:
            return 'CPR'

        return None

    def save_to_database(self,
                         symbol: str,
                         current_ltp: Optional[float] = None):
        """Save CPR levels to database"""
        if symbol not in self.levels:
            logger.warning(f"No CPR levels calculated for {symbol}")
            return False

        from models import CprLevel
        from app import db

        try:
            levels = self.levels[symbol]
            break_level = self.determine_break_level(symbol, current_ltp) if current_ltp else None

            # Check if record exists
            existing = CprLevel.query.filter_by(symbol=symbol,
                                                date=date.today()).first()

            if existing:
                # Update existing record
                existing.pp = levels['pp']
                existing.tc = levels['tc']
                existing.bc = levels['bc']
                existing.r1 = levels['r1']
                existing.r2 = levels['r2']
                existing.r3 = levels['r3']
                existing.s1 = levels['s1']
                existing.s2 = levels['s2']
                existing.s3 = levels['s3']
                existing.prev_close = levels['prev_close']
                existing.current_ltp = current_ltp
                existing.break_level = break_level
                # Trend direction removed as not displayed in table
                existing.updated_at = datetime.now(timezone.utc)
            else:
                # Create new record
                new_level = CprLevel()
                new_level.symbol = symbol
                new_level.full_symbol = f"NSE:{symbol}-EQ"
                new_level.date = date.today()
                new_level.pp = levels['pp']
                new_level.tc = levels['tc']
                new_level.bc = levels['bc']
                new_level.r1 = levels['r1']
                new_level.r2 = levels['r2']
                new_level.r3 = levels['r3']
                new_level.s1 = levels['s1']
                new_level.s2 = levels['s2']
                new_level.s3 = levels['s3']
                new_level.prev_close = levels['prev_close']
                new_level.current_ltp = current_ltp
                new_level.break_level = break_level
                # Trend direction removed as not displayed in table
                db.session.add(new_level)

            db.session.commit()
            logger.info(f"CPR levels saved to database for {symbol}")
            return True

        except Exception as e:
            logger.error(f"Error saving CPR levels for {symbol}: {e}")
            db.session.rollback()
            return False

    def get_previous_day_ohlc(self, symbol: str) -> Optional[Dict[str, float]]:
        """Get previous trading day's OHLC data from database - prioritizes hist_data_365 over other sources"""
        try:
            from models import HistoricalData
            from app import db
            from sqlalchemy import text
            from datetime import date
            
            # Get today's date
            today = date.today()
            
            # Get the most recent data (previous day) - prioritize emergency data
            display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            # PRIORITY 1: Check hist_data_365 first (primary data source)
            hist_data_query = db.session.execute(
                text("""
                    SELECT open, high, low, close, date
                    FROM hist_data_365 
                    WHERE symbol = :symbol
                    AND timeframe = '1D'
                    AND date < :today
                    ORDER BY date DESC
                    LIMIT 1
                """),
                {'symbol': display_symbol, 'today': today}
            )
            
            hist_row = hist_data_query.fetchone()
            if hist_row:
                logger.info(f"CPR: Using hist_data_365 for {symbol} from {hist_row.date} (H:{hist_row.high}, L:{hist_row.low}, C:{hist_row.close})")
                return {
                    'high': float(hist_row.high),
                    'low': float(hist_row.low),
                    'close': float(hist_row.close),
                    'open': float(hist_row.open),
                    'date': hist_row.date
                }
            
            # PRIORITY 2: Fallback to daily_ohlc_data (emergency/manual saves)
            daily_ohlc_query = db.session.execute(
                text("""
                    SELECT open_price, high_price, low_price, close_price, trading_date
                    FROM daily_ohlc_data 
                    WHERE REPLACE(REPLACE(symbol, 'NSE:', ''), '-EQ', '') = :symbol
                    AND trading_date < :today
                    ORDER BY trading_date DESC
                    LIMIT 1
                """),
                {'symbol': display_symbol, 'today': today}
            )
            
            daily_row = daily_ohlc_query.fetchone()
            if daily_row:
                logger.info(f"CPR: Using daily_ohlc_data fallback for {symbol} from {daily_row.trading_date} (H:{daily_row.high_price}, L:{daily_row.low_price}, C:{daily_row.close_price})")
                return {
                    'high': float(daily_row.high_price),
                    'low': float(daily_row.low_price),
                    'close': float(daily_row.close_price),
                    'open': float(daily_row.open_price),
                    'date': daily_row.trading_date
                }
            
            # PRIORITY 3: Final fallback to historical_data (legacy)
            today = date.today()
            latest_data = HistoricalData.query.filter(
                HistoricalData.symbol == display_symbol,
                HistoricalData.resolution == '1D',
                db.func.date(HistoricalData.candle_time) < today
            ).order_by(HistoricalData.candle_time.desc()).first()
            
            if latest_data:
                logger.info(f"CPR: Using historical_data fallback for {symbol} from {latest_data.candle_time.date()} (H:{latest_data.high_price}, L:{latest_data.low_price}, C:{latest_data.close_price})")
                return {
                    'high': latest_data.high_price,
                    'low': latest_data.low_price,
                    'close': latest_data.close_price,
                    'open': latest_data.open_price,
                    'date': latest_data.candle_time.date()
                }
            
            logger.warning(f"No OHLC data found for {symbol} in hist_data_365, daily_ohlc_data, or historical_data")
            return None
            
        except Exception as e:
            logger.error(f"Error getting previous day OHLC for {symbol}: {str(e)}")
            return None

    def get_previous_day_ohlc_batch(self, symbols: List[str]) -> Dict[str, Dict[str, float]]:
        """Get previous trading day's OHLC data for multiple symbols - prioritizes hist_data_365 as primary source
        
        Prioritizes data sources:
        1. hist_data_365 (primary data source) - most accurate historical data
        2. daily_ohlc_data (emergency manual saves) - fallback for manual entries
        3. historical_data (API data) - legacy fallback for older dates
        """
        try:
            from models import HistoricalData
            from app import db
            from sqlalchemy import text, bindparam
            from datetime import date
            
            # Clean symbol names
            display_symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in symbols]
            today = date.today()
            
            symbol_data = {}
            
            # PRIORITY 1: Check hist_data_365 first (primary data source) - EXCLUDE TODAY'S DATA
            hist_data_query = db.session.execute(
                text("""
                    SELECT symbol, open, high, low, close, date
                    FROM hist_data_365 
                    WHERE symbol IN :symbols
                    AND timeframe = '1D'
                    AND date < :today
                    ORDER BY symbol, date DESC
                """).bindparams(bindparam('symbols', expanding=True)),
                {'symbols': display_symbols, 'today': today}
            )
            
            # Group hist_data_365 by symbol (get most recent for each)
            hist_data_map = {}
            for row in hist_data_query:
                if row.symbol not in hist_data_map:
                    hist_data_map[row.symbol] = {
                        'high': float(row.high),
                        'low': float(row.low),
                        'close': float(row.close),
                        'open': float(row.open),
                        'date': row.date
                    }
            
            # Add data from hist_data_365 (priority source)
            symbol_data.update(hist_data_map)
            
            # PRIORITY 2: Fallback to daily_ohlc_data for symbols not in hist_data_365
            symbols_still_needed = [sym for sym in display_symbols if sym not in hist_data_map]
            
            daily_data_map = {}
            if symbols_still_needed:
                daily_ohlc_query = text("""
                    SELECT symbol, open_price, high_price, low_price, close_price, trading_date
                    FROM daily_ohlc_data 
                    WHERE REPLACE(REPLACE(symbol, 'NSE:', ''), '-EQ', '') IN :symbols
                    AND trading_date < :today
                    ORDER BY trading_date DESC
                """).bindparams(bindparam('symbols', expanding=True))
                
                daily_results = db.session.execute(daily_ohlc_query, {'symbols': symbols_still_needed, 'today': today}).fetchall()
                
                # Group daily_ohlc_data by symbol (get most recent for each)
                for record in daily_results:
                    # Normalize key to display symbol format
                    normalized_key = record.symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                    if normalized_key not in daily_data_map:
                        daily_data_map[normalized_key] = {
                            'high': float(record.high_price),
                            'low': float(record.low_price),
                            'close': float(record.close_price),
                            'open': float(record.open_price),
                            'date': record.trading_date
                        }
                
                # Add data from daily_ohlc_data as fallback
                symbol_data.update(daily_data_map)
            
            # PRIORITY 3: Final fallback to historical_data for symbols not found anywhere
            symbols_still_needed = [s for s in display_symbols if s not in symbol_data]
            
            if symbols_still_needed:
                # Batch query to get PREVIOUS DAY's OHLC data for remaining symbols
                latest_data_query = db.session.query(HistoricalData).filter(
                    HistoricalData.symbol.in_(symbols_still_needed),
                    HistoricalData.resolution == '1D',
                    db.func.date(HistoricalData.candle_time) < today
                ).order_by(HistoricalData.symbol, HistoricalData.candle_time.desc()).all()
                
                # Group by symbol and get the most recent record for each
                for record in latest_data_query:
                    if record.symbol not in symbol_data:
                        symbol_data[record.symbol] = {
                            'high': record.high_price,
                            'low': record.low_price,
                            'close': record.close_price,
                            'open': record.open_price,
                            'date': record.candle_time.date()
                        }
            
            logger.info(f"CPR OHLC data source priority: {len(hist_data_map)} hist_data_365 + {len(daily_data_map)} daily_ohlc_data + {len([s for s in symbols_still_needed if s in symbol_data]) - len(daily_data_map)} historical_data = {len(symbol_data)}/{len(display_symbols)} symbols")
            
            return symbol_data
            
        except Exception as e:
            logger.error(f"Error getting batch previous day OHLC: {str(e)}")
            return {}

    def get_existing_cpr_records_batch(self, symbols: List[str], target_date):
        """Get existing CPR records for multiple symbols in one query"""
        try:
            from models import CprLevel
            from app import db
            
            display_symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in symbols]
            
            existing_records = CprLevel.query.filter(
                CprLevel.symbol.in_(display_symbols),
                CprLevel.date == target_date
            ).all()
            
            return {record.symbol: record for record in existing_records}
            
        except Exception as e:
            logger.error(f"Error getting existing CPR records: {str(e)}")
            return {}

    def calculate_and_store_levels_batch(self, symbols: Optional[List[str]] = None, websocket_manager=None) -> Dict[str, bool]:
        """Calculate and store CPR levels for all or specified symbols using batch processing"""
        from models import CprLevel
        from app import db
        from datetime import date
        
        if symbols is None:
            # Get ALL symbols from WebSocket manager (all 228 symbols), not just HistoricalData (75 symbols)
            if websocket_manager:
                # Use all symbols that WebSocket is tracking (228 symbols)
                symbols_from_websocket = list(websocket_manager.get_latest_data().keys())
                if symbols_from_websocket:
                    # Clean symbols to display format for calculations
                    symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in symbols_from_websocket]
                    logger.info(f"CPR: Processing {len(symbols)} symbols from WebSocket manager")
                else:
                    # Fallback to Config symbols if WebSocket not populated yet
                    from config import Config
                    symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                    logger.info(f"CPR: WebSocket empty, using Config symbols: {len(symbols)}")
            else:
                # Final fallback to Config if no WebSocket, then HistoricalData as last resort
                try:
                    from config import Config  
                    symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                    logger.info(f"CPR: No WebSocket, using Config symbols: {len(symbols)}")
                except Exception:
                    # Last resort: use HistoricalData symbols
                    from models import HistoricalData
                    symbols_with_data = db.session.query(HistoricalData.symbol).distinct().all()
                    symbols = [symbol[0] for symbol in symbols_with_data]
                    logger.info(f"CPR: Using HistoricalData fallback: {len(symbols)} symbols")
        
        results = {}
        today = date.today()
        
        # Process symbols in batches of 20
        batch_size = 20
        for i in range(0, len(symbols), batch_size):
            batch_symbols = symbols[i:i + batch_size]
            logger.info(f"Processing CPR batch {i//batch_size + 1}: symbols {i+1}-{min(i+batch_size, len(symbols))}")
            
            try:
                # Batch fetch previous day OHLC data
                prev_data_map = self.get_previous_day_ohlc_batch(batch_symbols)
                
                # Batch fetch existing records
                existing_records_map = self.get_existing_cpr_records_batch(batch_symbols, today)
                
                # Process each symbol in the batch
                records_to_add = []
                for symbol in batch_symbols:
                    try:
                        display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
                        
                        # Check if we have previous day data
                        if display_symbol not in prev_data_map:
                            logger.warning(f"No previous day data for {symbol}")
                            results[symbol] = False
                            continue
                        
                        prev_data = prev_data_map[display_symbol]
                        
                        # Calculate CPR levels
                        levels = self.calculate_cpr_levels(
                            symbol,
                            prev_data['high'],
                            prev_data['low'], 
                            prev_data['close']
                        )
                        
                        if not levels:
                            results[symbol] = False
                            continue
                        
                        # Get current LTP from websocket if available
                        current_ltp = None
                        if websocket_manager and hasattr(websocket_manager, 'stock_data') and websocket_manager.stock_data:
                            full_symbol = f"NSE:{display_symbol}-EQ"
                            if full_symbol in websocket_manager.stock_data:
                                current_ltp = websocket_manager.stock_data[full_symbol].get('ltp')
                        
                        break_level = self.determine_break_level(symbol, current_ltp) if current_ltp else None
                        
                        # Check if record already exists
                        if display_symbol in existing_records_map:
                            # Update existing record
                            existing = existing_records_map[display_symbol]
                            existing.pp = levels['pp']
                            existing.tc = levels['tc']
                            existing.bc = levels['bc']
                            existing.r1 = levels['r1']
                            existing.r2 = levels['r2']
                            existing.r3 = levels['r3']
                            existing.s1 = levels['s1']
                            existing.s2 = levels['s2']
                            existing.s3 = levels['s3']
                            existing.prev_close = levels['prev_close']
                            existing.current_ltp = current_ltp
                            existing.break_level = break_level
                            existing.updated_at = datetime.now(timezone.utc)
                        else:
                            # Create new record
                            cpr_record = CprLevel()
                            cpr_record.symbol = display_symbol
                            cpr_record.full_symbol = f"NSE:{display_symbol}-EQ"
                            cpr_record.date = today
                            cpr_record.pp = levels['pp']
                            cpr_record.tc = levels['tc']
                            cpr_record.bc = levels['bc']
                            cpr_record.r1 = levels['r1']
                            cpr_record.r2 = levels['r2']
                            cpr_record.r3 = levels['r3']
                            cpr_record.s1 = levels['s1']
                            cpr_record.s2 = levels['s2']
                            cpr_record.s3 = levels['s3']
                            cpr_record.prev_close = levels['prev_close']
                            cpr_record.current_ltp = current_ltp
                            cpr_record.break_level = break_level
                            records_to_add.append(cpr_record)
                        
                        results[symbol] = True
                        logger.info(f"Calculated CPR levels for {symbol}")
                        
                    except Exception as e:
                        logger.error(f"Error calculating CPR levels for {symbol}: {str(e)}")
                        results[symbol] = False
                
                # Bulk add new records for this batch
                if records_to_add:
                    db.session.add_all(records_to_add)
                
                # Commit this batch
                db.session.commit()
                logger.info(f"Stored CPR levels for batch {i//batch_size + 1} ({len([s for s in batch_symbols if results.get(s, False)])} symbols)")
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error processing CPR batch {i//batch_size + 1}: {str(e)}")
                # Mark all symbols in this batch as failed
                for symbol in batch_symbols:
                    results[symbol] = False
        
        total_success = len([k for k, v in results.items() if v])
        logger.info(f"Completed CPR level calculation: {total_success}/{len(symbols)} symbols successful")
        
        return results

    def get_all_levels(self) -> Dict:
        """Get all calculated CPR levels"""
        return self.levels

    def clear_levels(self):
        """Clear all calculated levels"""
        self.levels = {}
        logger.info("All CPR levels cleared")


# Global calculator instance
cpr_calculator = CprCalculator()
