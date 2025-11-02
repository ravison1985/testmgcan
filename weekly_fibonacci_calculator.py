#!/usr/bin/env python3
"""
Weekly Fibonacci Pivot Calculator

This module calculates Fibonacci pivot levels using weekly OHLC data instead of daily data.
Weekly Fibonacci calculations use the weekly High, Low, Close of the previous week
to calculate support and resistance levels for the current week.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from models import db, WeeklyFibonacciLevel, WeeklyOHLCData
from sqlalchemy import and_, func

logger = logging.getLogger(__name__)

class WeeklyFibonacciCalculator:
    """
    Weekly Fibonacci Pivot Calculator (TradingView style)

    TradingView Fibonacci pivot formulas (based on previous week OHLC):
    - Pivot Point (PP) = (Weekly_High + Weekly_Low + Weekly_Close) / 3
    - R1 = PP + 0.382 * (Weekly_High - Weekly_Low)
    - R2 = PP + 0.618 * (Weekly_High - Weekly_Low)
    - R3 = PP + 1.000 * (Weekly_High - Weekly_Low)
    - S1 = PP - 0.382 * (Weekly_High - Weekly_Low)
    - S2 = PP - 0.618 * (Weekly_High - Weekly_Low)
    - S3 = PP - 1.000 * (Weekly_High - Weekly_Low)
    - Extra levels:
        - 38.2% level = PP + 0.382 * (Weekly_High - Weekly_Low)   (same as R1, kept for compatibility)
        - 50% level   = (Weekly_High + Weekly_Low) / 2
    """

    def __init__(self):
        self.levels = {}

    def calculate_weekly_fibonacci_levels(self, symbol: str, week_high: float, week_low: float,
                                         week_close: float, prev_week_close: float,
                                         week_start_date, week_end_date, year: int,
                                         week_number: int) -> Optional[Dict]:
        """Calculate weekly Fibonacci pivot levels for a symbol using weekly H, L, C"""
        try:
            pp = (week_high + week_low + week_close) / 3
            range_hl = week_high - week_low

            # TradingView style Fibonacci Pivots
            r1 = pp + (0.382 * range_hl)
            r2 = pp + (0.618 * range_hl)
            r3 = pp + (1.000 * range_hl)

            s1 = pp - (0.382 * range_hl)
            s2 = pp - (0.618 * range_hl)
            s3 = pp - (1.000 * range_hl)

            # Extra levels (kept for table compatibility)
            level_38 = pp + (0.382 * range_hl)  # same as R1
            level_50 = (week_high + week_low) / 2  # 50% retracement

            levels = {
                'symbol': symbol,
                'full_symbol': symbol,  # Assume same for now
                'week_start_date': week_start_date,
                'week_end_date': week_end_date,
                'year': year,
                'week_number': week_number,
                'prev_week_close': prev_week_close,
                'week_high': week_high,
                'week_low': week_low,
                'week_close': week_close,
                'pp': pp,
                'r1_61': r1,  # renamed but kept key name for DB compatibility
                'r2_123': r2,
                'r3_161': r3,
                's1_61': s1,
                's2_123': s2,
                's3_161': s3,
                'level_38': level_38,
                'level_50': level_50,
                'calculated_at': datetime.now(timezone.utc)
            }

            self.levels[symbol] = levels
            logger.info(f"Weekly Fibonacci (TradingView) levels calculated for {symbol} (Week {year}-W{week_number})")
            return levels

        except Exception as e:
            logger.error(f"Error calculating weekly Fibonacci levels for {symbol}: {e}")
            return {}

    def determine_weekly_break_level(self, symbol: str, current_ltp: float) -> Optional[str]:
        """Determine which weekly Fibonacci level is broken"""
        if symbol not in self.levels:
            return None

        levels = self.levels[symbol]

        # Check which level is broken (from highest to lowest)
        if current_ltp > levels['r3_161']:
            return 'R3'
        elif current_ltp > levels['r2_123']:
            return 'R2'
        elif current_ltp > levels['r1_61']:
            return 'R1'
        elif current_ltp > levels['pp']:
            return 'PP'
        elif current_ltp > levels['level_50']:
            return '50%'
        elif current_ltp > levels['level_38']:
            return '38.2%'
        elif current_ltp > levels['s1_61']:
            return 'S1'
        elif current_ltp > levels['s2_123']:
            return 'S2'
        else:
            return 'S3'

    def determine_weekly_trend_direction(self, symbol: str, current_ltp: float) -> Optional[str]:
        """Determine weekly trend direction based on Fibonacci levels"""
        if symbol not in self.levels:
            return None

        levels = self.levels[symbol]

        if current_ltp > levels['pp']:
            return 'bullish'
        elif current_ltp < levels['level_50']:
            return 'bearish'
        else:
            return 'sideways'

    def save_weekly_fibonacci_to_database(self, symbol: str, current_ltp: Optional[float] = None) -> bool:
        """Save calculated weekly Fibonacci levels to database"""
        try:
            if symbol not in self.levels:
                logger.error(f"No weekly Fibonacci levels calculated for {symbol}")
                return False

            levels = self.levels[symbol]
            
            # Determine break level and trend if LTP provided
            break_level = None
            trend_direction = None
            if current_ltp is not None:
                break_level = self.determine_weekly_break_level(symbol, current_ltp)
                trend_direction = self.determine_weekly_trend_direction(symbol, current_ltp)

            # Check if record already exists for this symbol and week
            existing_record = WeeklyFibonacciLevel.query.filter_by(
                symbol=symbol,
                year=levels['year'],
                week_number=levels['week_number']
            ).first()

            if existing_record:
                # Update existing record
                existing_record.prev_week_close = levels['prev_week_close']
                existing_record.week_high = levels['week_high']
                existing_record.week_low = levels['week_low']
                existing_record.week_close = levels['week_close']
                existing_record.pp = levels['pp']
                existing_record.r1_61 = levels['r1_61']
                existing_record.r2_123 = levels['r2_123']
                existing_record.r3_161 = levels['r3_161']
                existing_record.s1_61 = levels['s1_61']
                existing_record.s2_123 = levels['s2_123']
                existing_record.s3_161 = levels['s3_161']
                existing_record.level_38 = levels['level_38']
                existing_record.level_50 = levels['level_50']
                existing_record.current_ltp = current_ltp
                existing_record.break_level = break_level
                existing_record.trend_direction = trend_direction
                existing_record.updated_at = datetime.now(timezone.utc)
                
                logger.info(f"Updated weekly Fibonacci record for {symbol} (Week {levels['year']}-W{levels['week_number']})")
            else:
                # Create new record
                fibonacci_record = WeeklyFibonacciLevel(
                    symbol=symbol,
                    full_symbol=levels['full_symbol'],
                    week_start_date=levels['week_start_date'],
                    week_end_date=levels['week_end_date'],
                    year=levels['year'],
                    week_number=levels['week_number'],
                    prev_week_close=levels['prev_week_close'],
                    week_high=levels['week_high'],
                    week_low=levels['week_low'],
                    week_close=levels['week_close'],
                    pp=levels['pp'],
                    r1_61=levels['r1_61'],
                    r2_123=levels['r2_123'],
                    r3_161=levels['r3_161'],
                    s1_61=levels['s1_61'],
                    s2_123=levels['s2_123'],
                    s3_161=levels['s3_161'],
                    level_38=levels['level_38'],
                    level_50=levels['level_50'],
                    current_ltp=current_ltp,
                    break_level=break_level,
                    trend_direction=trend_direction
                )
                
                db.session.add(fibonacci_record)
                logger.info(f"Created new weekly Fibonacci record for {symbol} (Week {levels['year']}-W{levels['week_number']})")

            db.session.commit()
            return True

        except Exception as e:
            logger.error(f"Error saving weekly Fibonacci levels for {symbol}: {e}")
            db.session.rollback()
            return False

    def calculate_and_save_all_weekly_fibonacci(self) -> Dict[str, int]:
        """Calculate and save weekly Fibonacci levels for all symbols with weekly data"""
        try:
            # Get the most recent weekly data for all symbols
            subquery = db.session.query(
                WeeklyOHLCData.symbol,
                func.max(WeeklyOHLCData.week_end_date).label('max_week')
            ).group_by(WeeklyOHLCData.symbol).subquery()
            
            current_weekly_data = db.session.query(WeeklyOHLCData).join(
                subquery,
                and_(
                    WeeklyOHLCData.symbol == subquery.c.symbol,
                    WeeklyOHLCData.week_end_date == subquery.c.max_week
                )
            ).all()

            results = {'calculated': 0, 'saved': 0, 'errors': 0}

            for current_week in current_weekly_data:
                try:
                    # Get previous week's data for this symbol
                    prev_week = db.session.query(WeeklyOHLCData).filter(
                        WeeklyOHLCData.symbol == current_week.symbol,
                        WeeklyOHLCData.week_end_date < current_week.week_end_date
                    ).order_by(WeeklyOHLCData.week_end_date.desc()).first()

                    if not prev_week:
                        logger.warning(f"No previous week data found for {current_week.symbol}")
                        continue

                    # Calculate weekly Fibonacci levels
                    levels = self.calculate_weekly_fibonacci_levels(
                        symbol=current_week.symbol,
                        week_high=float(current_week.high_price),
                        week_low=float(current_week.low_price),
                        week_close=float(current_week.close_price),
                        prev_week_close=float(prev_week.close_price),
                        week_start_date=current_week.week_start_date,
                        week_end_date=current_week.week_end_date,
                        year=current_week.year,
                        week_number=current_week.week_number
                    )

                    if levels:
                        results['calculated'] += 1
                        
                        # Save to database (using current week's close as LTP)
                        if self.save_weekly_fibonacci_to_database(current_week.symbol, float(current_week.close_price)):
                            results['saved'] += 1
                        else:
                            results['errors'] += 1
                    else:
                        results['errors'] += 1

                except Exception as e:
                    logger.error(f"Error processing weekly Fibonacci for {current_week.symbol}: {e}")
                    results['errors'] += 1

            logger.info(f"Weekly Fibonacci calculation completed: {results}")
            return results

        except Exception as e:
            logger.error(f"Error in calculate_and_save_all_weekly_fibonacci: {e}")
            return {'calculated': 0, 'saved': 0, 'errors': 1}

    def get_weekly_fibonacci_data(self) -> list:
        """Get all weekly Fibonacci data from database"""
        try:
            # Get the most recent weekly Fibonacci data for all symbols
            subquery = db.session.query(
                WeeklyFibonacciLevel.symbol,
                func.max(WeeklyFibonacciLevel.week_end_date).label('max_week')
            ).group_by(WeeklyFibonacciLevel.symbol).subquery()
            
            weekly_fibonacci_records = db.session.query(WeeklyFibonacciLevel).join(
                subquery,
                and_(
                    WeeklyFibonacciLevel.symbol == subquery.c.symbol,
                    WeeklyFibonacciLevel.week_end_date == subquery.c.max_week
                )
            ).order_by(WeeklyFibonacciLevel.symbol).all()

            return [record.to_dict() for record in weekly_fibonacci_records]

        except Exception as e:
            logger.error(f"Error getting weekly Fibonacci data: {e}")
            return []