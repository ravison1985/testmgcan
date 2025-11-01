import logging
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timezone, date

logger = logging.getLogger(__name__)


class FibonacciCalculator:
    """
    Fibonacci Pivot Calculator (TradingView style)

    TradingView Fibonacci pivot formulas (based on previous day OHLC):
    - Pivot Point (PP) = (High + Low + Close) / 3
    - R1 = PP + 0.382 * (High - Low)
    - R2 = PP + 0.618 * (High - Low)
    - R3 = PP + 1.000 * (High - Low)
    - S1 = PP - 0.382 * (High - Low)
    - S2 = PP - 0.618 * (High - Low)
    - S3 = PP - 1.000 * (High - Low)
    - Extra levels:
        - 38.2% level = PP + 0.382 * (High - Low)   (same as R1, kept for compatibility)
        - 50% level   = (High + Low) / 2
    """

    def __init__(self):
        self.levels = {}

    def calculate_fibonacci_levels(self, symbol: str, high: float, low: float,
                                   close: float) -> Optional[Dict]:
        """Calculate Fibonacci pivot levels for a symbol using previous day's H, L, C"""
        try:
            pp = (high + low + close) / 3
            range_hl = high - low

            # TradingView style Fibonacci Pivots
            r1 = pp + (0.382 * range_hl)
            r2 = pp + (0.618 * range_hl)
            r3 = pp + (1.000 * range_hl)

            s1 = pp - (0.382 * range_hl)
            s2 = pp - (0.618 * range_hl)
            s3 = pp - (1.000 * range_hl)

            # Extra levels (kept for table compatibility)
            level_38 = pp + (0.382 * range_hl)  # same as R1
            level_50 = (high + low) / 2  # 50% retracement

            levels = {
                'symbol': symbol,
                'pp': pp,
                'r1_61': r1,  # renamed but kept key name for DB compatibility
                'r2_123': r2,
                'r3_161': r3,
                's1_61': s1,
                's2_123': s2,
                's3_161': s3,
                'level_38': level_38,
                'level_50': level_50,
                'high': high,
                'low': low,
                'prev_close': close,
                'calculated_at': datetime.now(timezone.utc)
            }

            self.levels[symbol] = levels
            logger.info(
                f"Fibonacci (TradingView) levels calculated for {symbol}")
            return levels

        except Exception as e:
            logger.error(
                f"Error calculating Fibonacci levels for {symbol}: {e}")
            return {}

    def determine_break_level(self, symbol: str,
                              current_ltp: float) -> Optional[str]:
        """Determine which Fibonacci level is broken"""
        if symbol not in self.levels:
            return None

        levels = self.levels[symbol]

        # Check which level is broken
        # Check resistance breaks
        if current_ltp > levels['r3_161']:
            return 'R3'
        elif current_ltp > levels['r2_123']:
            return 'R2'
        elif current_ltp > levels['r1_61']:
            return 'R1'
        elif current_ltp > levels['level_38']:
            return '38.2%'
        # Check support breaks
        elif current_ltp < levels['s3_161']:
            return 'S3'
        elif current_ltp < levels['s2_123']:
            return 'S2'
        elif current_ltp < levels['s1_61']:
            return 'S1'
        elif current_ltp < levels['level_50']:
            return '50%'
        # Between key levels
        else:
            return 'PP'

    def save_to_database(self,
                         symbol: str,
                         current_ltp: Optional[float] = None):
        """Save Fibonacci levels to database"""
        if symbol not in self.levels:
            logger.warning(f"No Fibonacci levels calculated for {symbol}")
            return False

        from models import FibonacciLevel
        from app import db

        try:

            levels = self.levels[symbol]
            break_level = self.determine_break_level(
                symbol, current_ltp) if current_ltp else None

            # Check if record exists for today's date
            existing = FibonacciLevel.query.filter_by(
                symbol=symbol, date=date.today()).first()

            if existing:
                # Update existing record
                existing.pp = levels['pp']
                existing.r1_61 = levels['r1_61']
                existing.r2_123 = levels['r2_123']
                existing.r3_161 = levels['r3_161']
                existing.s1_61 = levels['s1_61']
                existing.s2_123 = levels['s2_123']
                existing.s3_161 = levels['s3_161']
                existing.level_38 = levels['level_38']
                existing.level_50 = levels['level_50']
                existing.prev_close = levels['prev_close']
                existing.current_ltp = current_ltp
                existing.break_level = break_level
                existing.updated_at = datetime.now(timezone.utc)
            else:
                # Create new record
                new_level = FibonacciLevel()
                new_level.symbol = symbol
                new_level.full_symbol = f"NSE:{symbol}-EQ"
                new_level.date = date.today()
                new_level.pp = levels['pp']
                new_level.r1_61 = levels['r1_61']
                new_level.r2_123 = levels['r2_123']
                new_level.r3_161 = levels['r3_161']
                new_level.s1_61 = levels['s1_61']
                new_level.s2_123 = levels['s2_123']
                new_level.s3_161 = levels['s3_161']
                new_level.level_38 = levels['level_38']
                new_level.level_50 = levels['level_50']
                new_level.prev_close = levels['prev_close']
                new_level.current_ltp = current_ltp
                new_level.break_level = break_level
                # Trend direction removed as not displayed in table
                db.session.add(new_level)

            db.session.commit()
            logger.info(f"Fibonacci levels saved to database for {symbol}")
            return True

        except Exception as e:
            logger.error(f"Error saving Fibonacci levels for {symbol}: {e}")
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
            
            # Get the most recent historical data (previous closed day)
            display_symbol = symbol.replace('NSE:',
                                            '').replace('-EQ', '').replace(
                                                '-INDEX', '')

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
                logger.info(f"Fibonacci: Using hist_data_365 for {symbol} from {hist_row.date} (H:{hist_row.high}, L:{hist_row.low}, C:{hist_row.close})")
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
                    AND trading_date < CURRENT_DATE
                    ORDER BY trading_date DESC
                    LIMIT 1
                """),
                {'symbol': display_symbol}
            )
            
            daily_row = daily_ohlc_query.fetchone()
            if daily_row:
                logger.info(f"Fibonacci: Using daily_ohlc_data fallback for {symbol} from {daily_row.trading_date} (H:{daily_row.high_price}, L:{daily_row.low_price}, C:{daily_row.close_price})")
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
                logger.info(f"Fibonacci: Using historical_data fallback for {symbol} from {latest_data.candle_time.date()} (H:{latest_data.high_price}, L:{latest_data.low_price}, C:{latest_data.close_price})")
                return {
                    'high': float(latest_data.high_price),
                    'low': float(latest_data.low_price),
                    'close': float(latest_data.close_price),
                    'open': float(latest_data.open_price),
                    'date': latest_data.candle_time.date()
                }

            logger.warning(f"No OHLC data found for {symbol} in hist_data_365, daily_ohlc_data, or historical_data")
            return None

        except Exception as e:
            logger.error(
                f"Error getting previous day OHLC for {symbol}: {str(e)}")
            return None

    def get_previous_day_ohlc_batch(
            self, symbols: List[str]) -> Dict[str, Dict[str, float]]:
        """Get previous trading day's OHLC data for multiple symbols - prioritizes hist_data_365 as primary source"""
        try:
            from models import HistoricalData
            from app import db
            from sqlalchemy import text, bindparam
            from datetime import date

            # Clean symbol names
            display_symbols = [
                symbol.replace('NSE:', '').replace('-EQ',
                                                   '').replace('-INDEX', '')
                for symbol in symbols
            ]
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
                daily_ohlc_query = db.session.execute(
                    text("""
                        SELECT REPLACE(REPLACE(symbol, 'NSE:', ''), '-EQ', '') as display_symbol,
                               symbol, open_price, high_price, low_price, close_price, trading_date
                        FROM daily_ohlc_data 
                        WHERE REPLACE(REPLACE(symbol, 'NSE:', ''), '-EQ', '') IN :symbols
                        AND trading_date < :today
                        ORDER BY trading_date DESC
                    """).bindparams(bindparam('symbols', expanding=True)),
                    {'symbols': symbols_still_needed, 'today': today}
                )
                
                for row in daily_ohlc_query:
                    if row.display_symbol not in daily_data_map:
                        daily_data_map[row.display_symbol] = {
                            'high': float(row.high_price),
                            'low': float(row.low_price),
                            'close': float(row.close_price),
                            'open': float(row.open_price),
                            'date': row.trading_date
                        }
                
                # Add data from daily_ohlc_data as fallback
                symbol_data.update(daily_data_map)

            # PRIORITY 3: Final fallback to historical_data for symbols not found anywhere
            symbols_still_needed = [sym for sym in display_symbols if sym not in symbol_data]
            
            if symbols_still_needed:
                # Batch query to get latest OHLC data for remaining symbols
                latest_data_query = db.session.query(HistoricalData).filter(
                    HistoricalData.symbol.in_(symbols_still_needed),
                    HistoricalData.resolution == '1D',
                    db.func.date(HistoricalData.candle_time) < today
                ).order_by(
                        HistoricalData.symbol,
                        HistoricalData.candle_time.desc()).all()

                # Group by symbol and get the most recent record for each
                for record in latest_data_query:
                    if record.symbol not in symbol_data:
                        symbol_data[record.symbol] = {
                            'high': float(record.high_price),
                            'low': float(record.low_price),
                            'close': float(record.close_price),
                            'open': float(record.open_price),
                            'date': record.candle_time.date()
                        }

            logger.info(f"Fibonacci OHLC data source priority: {len(hist_data_map)} hist_data_365 + {len(daily_data_map)} daily_ohlc_data + {len([s for s in symbols_still_needed if s in symbol_data]) - len(daily_data_map)} historical_data = {len(symbol_data)}/{len(display_symbols)} symbols")
            return symbol_data

        except Exception as e:
            logger.error(f"Error getting batch previous day OHLC: {str(e)}")
            return {}

    def get_existing_fibonacci_records_batch(self, symbols: List[str],
                                             target_date):
        """Get existing Fibonacci records for multiple symbols in one query"""
        try:
            from models import FibonacciLevel
            from app import db

            display_symbols = [
                symbol.replace('NSE:', '').replace('-EQ',
                                                   '').replace('-INDEX', '')
                for symbol in symbols
            ]

            existing_records = FibonacciLevel.query.filter(
                FibonacciLevel.symbol.in_(display_symbols),
                FibonacciLevel.date == target_date).all()

            return {record.symbol: record for record in existing_records}

        except Exception as e:
            logger.error(f"Error getting existing Fibonacci records: {str(e)}")
            return {}

    def calculate_and_store_levels_batch(
            self,
            symbols: Optional[List[str]] = None,
            websocket_manager=None) -> Dict[str, bool]:
        """Calculate and store Fibonacci levels for all or specified symbols using batch processing"""
        from models import FibonacciLevel
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
                    logger.info(f"Fibonacci: Processing {len(symbols)} symbols from WebSocket manager")
                else:
                    # Fallback to Config symbols if WebSocket not populated yet
                    from config import Config
                    symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                    logger.info(f"Fibonacci: WebSocket empty, using Config symbols: {len(symbols)}")
            else:
                # Final fallback to Config if no WebSocket, then HistoricalData as last resort
                try:
                    from config import Config  
                    symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in Config.NIFTY50_SYMBOLS]
                    logger.info(f"Fibonacci: No WebSocket, using Config symbols: {len(symbols)}")
                except Exception:
                    # Last resort: use HistoricalData symbols
                    from models import HistoricalData
                    symbols_with_data = db.session.query(HistoricalData.symbol).distinct().all()
                    symbols = [symbol[0] for symbol in symbols_with_data]
                    logger.info(f"Fibonacci: Using HistoricalData fallback: {len(symbols)} symbols")

        results = {}
        today = date.today()

        # Process symbols in batches of 20
        batch_size = 20
        for i in range(0, len(symbols), batch_size):
            batch_symbols = symbols[i:i + batch_size]
            logger.info(
                f"Processing Fibonacci batch {i//batch_size + 1}: symbols {i+1}-{min(i+batch_size, len(symbols))}"
            )

            try:
                # Batch fetch previous day OHLC data
                prev_data_map = self.get_previous_day_ohlc_batch(batch_symbols)

                # Batch fetch existing records
                existing_records_map = self.get_existing_fibonacci_records_batch(
                    batch_symbols, today)

                # Process each symbol in the batch
                records_to_add = []
                for symbol in batch_symbols:
                    try:
                        display_symbol = symbol.replace('NSE:', '').replace(
                            '-EQ', '').replace('-INDEX', '')

                        # Check if we have previous day data
                        if display_symbol not in prev_data_map:
                            logger.warning(
                                f"No previous day data for {symbol}")
                            results[symbol] = False
                            continue

                        prev_data = prev_data_map[display_symbol]

                        # Calculate Fibonacci levels
                        levels = self.calculate_fibonacci_levels(
                            symbol, prev_data['high'], prev_data['low'],
                            prev_data['close'])

                        if not levels:
                            results[symbol] = False
                            continue

                        # Get current LTP from websocket if available
                        current_ltp = None
                        if websocket_manager and hasattr(
                                websocket_manager,
                                'stock_data') and websocket_manager.stock_data:
                            full_symbol = f"NSE:{display_symbol}-EQ"
                            if full_symbol in websocket_manager.stock_data:
                                current_ltp = websocket_manager.stock_data[
                                    full_symbol].get('ltp')

                        break_level = self.determine_break_level(
                            symbol, current_ltp) if current_ltp else None

                        # Check if record already exists
                        if display_symbol in existing_records_map:
                            # Update existing record
                            existing = existing_records_map[display_symbol]
                            existing.pp = levels['pp']
                            existing.r1_61 = levels['r1_61']
                            existing.r2_123 = levels['r2_123']
                            existing.r3_161 = levels['r3_161']
                            existing.s1_61 = levels['s1_61']
                            existing.s2_123 = levels['s2_123']
                            existing.s3_161 = levels['s3_161']
                            existing.level_38 = levels['level_38']
                            existing.level_50 = levels['level_50']
                            existing.prev_close = levels['prev_close']
                            existing.current_ltp = current_ltp
                            existing.break_level = break_level
                            existing.updated_at = datetime.now(timezone.utc)
                        else:
                            # Create new record
                            fib_record = FibonacciLevel()
                            fib_record.symbol = display_symbol
                            fib_record.full_symbol = f"NSE:{display_symbol}-EQ"
                            fib_record.date = today
                            fib_record.pp = levels['pp']
                            fib_record.r1_61 = levels['r1_61']
                            fib_record.r2_123 = levels['r2_123']
                            fib_record.r3_161 = levels['r3_161']
                            fib_record.s1_61 = levels['s1_61']
                            fib_record.s2_123 = levels['s2_123']
                            fib_record.s3_161 = levels['s3_161']
                            fib_record.level_38 = levels['level_38']
                            fib_record.level_50 = levels['level_50']
                            fib_record.prev_close = levels['prev_close']
                            fib_record.current_ltp = current_ltp
                            fib_record.break_level = break_level
                            records_to_add.append(fib_record)

                        results[symbol] = True
                        logger.info(
                            f"Calculated Fibonacci levels for {symbol}")

                    except Exception as e:
                        logger.error(
                            f"Error calculating Fibonacci levels for {symbol}: {str(e)}"
                        )
                        results[symbol] = False

                # Bulk add new records for this batch
                if records_to_add:
                    db.session.add_all(records_to_add)

                # Commit this batch
                db.session.commit()
                logger.info(
                    f"Stored Fibonacci levels for batch {i//batch_size + 1} ({len([s for s in batch_symbols if results.get(s, False)])} symbols)"
                )

            except Exception as e:
                db.session.rollback()
                logger.error(
                    f"Error processing Fibonacci batch {i//batch_size + 1}: {str(e)}"
                )
                # Mark all symbols in this batch as failed
                for symbol in batch_symbols:
                    results[symbol] = False

        total_success = len([k for k, v in results.items() if v])
        logger.info(
            f"Completed Fibonacci level calculation: {total_success}/{len(symbols)} symbols successful"
        )

        return results

    def get_all_levels(self) -> Dict:
        """Get all calculated Fibonacci levels"""
        return self.levels

    def clear_levels(self):
        """Clear all calculated levels"""
        self.levels = {}
        logger.info("All Fibonacci levels cleared")


# Global calculator instance
fibonacci_calculator = FibonacciCalculator()
