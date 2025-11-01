import logging
from datetime import datetime, timedelta, date
from typing import Dict, List, Optional
from models import db, CamarillaLevels, HistoricalData
from config import Config

logger = logging.getLogger(__name__)

class CamarillaCalculator:
    """Calculate and manage Camarilla pivot levels for stocks"""
    
    def __init__(self):
        pass
    
    def calculate_camarilla_levels(self, high: float, low: float, close: float) -> Dict[str, float]:
        """
        Calculate Camarilla pivot levels based on previous day's H, L, C
        
        Updated Camarilla formula:
        P = (H + L + C) / 3
        Range = H - L
        
        R1 = C + (Range × 1.1) / 12
        R2 = C + (Range × 1.1) / 6
        R3 = C + (Range × 1.1) / 4
        R4 = C + (Range × 1.1) / 2
        R5 = H/L * C
        
        S1 = C - (Range × 1.1) / 12
        S2 = C - (Range × 1.1) / 6
        S3 = C - (Range × 1.1) / 4
        S4 = C - (Range × 1.1) / 2
        S5 = C - (R5 - C)
        """
        try:
            # Calculate Pivot Point
            pivot = (high + low + close) / 3
            
            # Calculate Range
            range_hl = high - low
            
            # Calculate resistance levels (R1 to R5)
            r1 = close + (range_hl * 1.1) / 12
            r2 = close + (range_hl * 1.1) / 6
            r3 = close + (range_hl * 1.1) / 4
            r4 = close + (range_hl * 1.1) / 2
            # Add protection against divide-by-zero for R5 calculation
            r5 = (high / low) * close if low > 0 else high * 2
            
            # Calculate support levels (S1 to S5)
            s1 = close - (range_hl * 1.1) / 12
            s2 = close - (range_hl * 1.1) / 6
            s3 = close - (range_hl * 1.1) / 4
            s4 = close - (range_hl * 1.1) / 2
            s5 = close - (r5 - close)
            
            return {
                'pivot': round(pivot, 2),
                'r5': round(r5, 2),
                'r4': round(r4, 2),
                'r3': round(r3, 2),
                'r2': round(r2, 2),
                'r1': round(r1, 2),
                's1': round(s1, 2),
                's2': round(s2, 2),
                's3': round(s3, 2),
                's4': round(s4, 2),
                's5': round(s5, 2)
            }
        except Exception as e:
            logger.error(f"Error calculating Camarilla levels: {str(e)}")
            return {}
    
    def get_previous_day_ohlc(self, symbol: str) -> Optional[Dict[str, float]]:
        """Get previous trading day's OHLC data from database - prioritizes hist_data_365 over other sources"""
        try:
            from sqlalchemy import text
            
            # Get the most recent data (previous day) - prioritize emergency data
            display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            
            # PRIORITY 1: Check hist_data_365 first (primary data source) - EXCLUDE TODAY'S DATA
            today = date.today()
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
                logger.info(f"Camarilla: Using hist_data_365 for {symbol} from {hist_row.date} (H:{hist_row.high}, L:{hist_row.low}, C:{hist_row.close})")
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
                logger.info(f"Camarilla: Using daily_ohlc_data fallback for {symbol} from {daily_row.trading_date} (H:{daily_row.high_price}, L:{daily_row.low_price}, C:{daily_row.close_price})")
                return {
                    'high': float(daily_row.high_price),
                    'low': float(daily_row.low_price),
                    'close': float(daily_row.close_price),
                    'open': float(daily_row.open_price),
                    'date': daily_row.trading_date
                }
            
            # PRIORITY 3: Final fallback to historical_data (legacy)
            latest_data = HistoricalData.query.filter(
                HistoricalData.symbol == display_symbol,
                HistoricalData.resolution == '1D',
                db.func.date(HistoricalData.candle_time) < today
            ).order_by(HistoricalData.candle_time.desc()).first()
            
            if latest_data:
                logger.info(f"Camarilla: Using historical_data fallback for {symbol} from {latest_data.candle_time.date()} (H:{latest_data.high_price}, L:{latest_data.low_price}, C:{latest_data.close_price})")
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
            logger.error(f"Error getting previous day OHLC for {symbol}: {str(e)}")
            return None
    
    def determine_break_level(self, current_price: float, levels: Dict[str, float]) -> str:
        """Determine which Camarilla level has been broken"""
        try:
            # Check resistance breaks (from highest to lowest)
            if current_price > levels['r5']:
                return 'R5'
            elif current_price > levels['r4']:
                return 'R4'
            elif current_price > levels['r3']:
                return 'R3'
            elif current_price > levels['r2']:
                return 'R2'
            elif current_price > levels['r1']:
                return 'R1'
            # Check support breaks (from lowest to highest)
            elif current_price < levels['s5']:
                return 'S5'
            elif current_price < levels['s4']:
                return 'S4'
            elif current_price < levels['s3']:
                return 'S3'
            elif current_price < levels['s2']:
                return 'S2'
            elif current_price < levels['s1']:
                return 'S1'
            else:
                return 'None'  # Price within normal range
                
        except Exception as e:
            logger.error(f"Error determining break level: {str(e)}")
            return 'None'
    
    
    def get_previous_day_ohlc_batch(self, symbols: List[str]) -> Dict[str, Dict[str, float]]:
        """Get previous trading day's OHLC data for multiple symbols - prioritizes hist_data_365 as primary source"""
        try:
            from sqlalchemy import text, bindparam
            
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
                
                # Add daily_ohlc_data as fallback
                symbol_data.update(daily_data_map)

            # PRIORITY 3: Final fallback to historical_data for symbols not found anywhere
            symbols_still_needed = [sym for sym in display_symbols if sym not in symbol_data]
            
            if symbols_still_needed:
                # Batch query to get latest OHLC data for remaining symbols
                latest_data_query = db.session.query(HistoricalData).filter(
                    HistoricalData.symbol.in_(symbols_still_needed),
                    HistoricalData.resolution == '1D',
                    db.func.date(HistoricalData.candle_time) < today
                ).order_by(HistoricalData.symbol, HistoricalData.candle_time.desc()).all()
                
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

            logger.info(f"Camarilla OHLC data source priority: {len(hist_data_map)} hist_data_365 + {len(daily_data_map)} daily_ohlc_data + {len([s for s in symbols_still_needed if s in symbol_data]) - len(daily_data_map)} historical_data = {len(symbol_data)}/{len(display_symbols)} symbols")
            return symbol_data
            
        except Exception as e:
            logger.error(f"Error getting batch previous day OHLC: {str(e)}")
            return {}

    def get_existing_camarilla_records_batch(self, symbols: List[str], target_date: date) -> Dict[str, CamarillaLevels]:
        """Get existing Camarilla records for multiple symbols in one query"""
        try:
            display_symbols = [symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '') for symbol in symbols]
            
            existing_records = CamarillaLevels.query.filter(
                CamarillaLevels.symbol.in_(display_symbols),
                CamarillaLevels.date == target_date
            ).all()
            
            return {record.symbol: record for record in existing_records}
            
        except Exception as e:
            logger.error(f"Error getting existing Camarilla records: {str(e)}")
            return {}

    def calculate_and_store_levels(self, symbols: Optional[List[str]] = None) -> Dict[str, bool]:
        """Calculate and store Camarilla levels for all or specified symbols using batch processing"""
        if symbols is None:
            symbols = Config.NIFTY50_SYMBOLS
        
        results = {}
        today = date.today()
        
        # Process symbols in batches of 20
        batch_size = 20
        for i in range(0, len(symbols), batch_size):
            batch_symbols = symbols[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}: symbols {i+1}-{min(i+batch_size, len(symbols))}")
            
            try:
                # Batch fetch previous day OHLC data
                prev_data_map = self.get_previous_day_ohlc_batch(batch_symbols)
                
                # Batch fetch existing records
                existing_records_map = self.get_existing_camarilla_records_batch(batch_symbols, today)
                
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
                        
                        # Calculate Camarilla levels
                        levels = self.calculate_camarilla_levels(
                            prev_data['high'],
                            prev_data['low'], 
                            prev_data['close']
                        )
                        
                        if not levels:
                            results[symbol] = False
                            continue
                        
                        # Check if record already exists
                        if display_symbol in existing_records_map:
                            # Update existing record
                            existing = existing_records_map[display_symbol]
                            existing.prev_high = prev_data['high']
                            existing.prev_low = prev_data['low']
                            existing.prev_close = prev_data['close']
                            existing.pivot = levels['pivot']
                            existing.r5 = levels['r5']
                            existing.r4 = levels['r4']
                            existing.r3 = levels['r3']
                            existing.r2 = levels['r2']
                            existing.r1 = levels['r1']
                            existing.s1 = levels['s1']
                            existing.s2 = levels['s2']
                            existing.s3 = levels['s3']
                            existing.s4 = levels['s4']
                            existing.s5 = levels['s5']
                            existing.updated_at = datetime.utcnow()
                        else:
                            # Create new record
                            camarilla_record = CamarillaLevels()
                            camarilla_record.symbol = display_symbol
                            camarilla_record.full_symbol = symbol
                            camarilla_record.date = today
                            camarilla_record.prev_high = prev_data['high']
                            camarilla_record.prev_low = prev_data['low']
                            camarilla_record.prev_close = prev_data['close']
                            camarilla_record.pivot = levels['pivot']
                            camarilla_record.r5 = levels['r5']
                            camarilla_record.r4 = levels['r4']
                            camarilla_record.r3 = levels['r3']
                            camarilla_record.r2 = levels['r2']
                            camarilla_record.r1 = levels['r1']
                            camarilla_record.s1 = levels['s1']
                            camarilla_record.s2 = levels['s2']
                            camarilla_record.s3 = levels['s3']
                            camarilla_record.s4 = levels['s4']
                            camarilla_record.s5 = levels['s5']
                            records_to_add.append(camarilla_record)
                        
                        results[symbol] = True
                        logger.info(f"Calculated Camarilla levels for {symbol}")
                        
                    except Exception as e:
                        logger.error(f"Error calculating levels for {symbol}: {str(e)}")
                        results[symbol] = False
                
                # Bulk add new records for this batch
                if records_to_add:
                    db.session.add_all(records_to_add)
                
                # Commit this batch
                db.session.commit()
                logger.info(f"Stored Camarilla levels for batch {i//batch_size + 1} ({len([s for s in batch_symbols if results.get(s, False)])} symbols)")
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error processing batch {i//batch_size + 1}: {str(e)}")
                # Mark all symbols in this batch as failed
                for symbol in batch_symbols:
                    results[symbol] = False
        
        total_success = len([k for k, v in results.items() if v])
        logger.info(f"Completed Camarilla level calculation: {total_success}/{len(symbols)} symbols successful")
        
        return results
    
    def update_current_status(self, symbol: str, current_ltp: float) -> bool:
        """Update current LTP and break status for a symbol"""
        try:
            display_symbol = symbol.replace('NSE:', '').replace('-EQ', '').replace('-INDEX', '')
            today = date.today()
            
            # Get today's Camarilla levels
            camarilla = CamarillaLevels.query.filter_by(
                symbol=display_symbol,
                date=today
            ).first()
            
            if not camarilla:
                logger.warning(f"No Camarilla levels found for {symbol} on {today}. Need to calculate levels first.")
                return False
            
            # Create levels dictionary for calculations
            levels = {
                'r5': camarilla.r5, 'r4': camarilla.r4, 'r3': camarilla.r3,
                'r2': camarilla.r2, 'r1': camarilla.r1, 's1': camarilla.s1,
                's2': camarilla.s2, 's3': camarilla.s3, 's4': camarilla.s4, 's5': camarilla.s5
            }
            
            # Update current status
            camarilla.current_ltp = current_ltp
            camarilla.break_level = self.determine_break_level(current_ltp, levels)
            # Trend direction removed as not displayed in table
            camarilla.updated_at = datetime.utcnow()
            
            # Commit the changes
            db.session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error updating current status for {symbol}: {str(e)}")
            db.session.rollback()
            return False
    
    def get_all_camarilla_data(self) -> List[Dict]:
        """Get all Camarilla data for today"""
        try:
            today = date.today()
            records = CamarillaLevels.query.filter_by(date=today).all()
            return [record.to_dict() for record in records]
        except Exception as e:
            logger.error(f"Error getting Camarilla data: {str(e)}")
            return []