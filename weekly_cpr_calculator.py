#!/usr/bin/env python3
"""
Weekly CPR (Central Pivot Range) Calculator

This module calculates CPR levels using weekly OHLC data instead of daily data.
Weekly CPR calculations use the weekly High, Low, Close of the previous week
to calculate support and resistance levels for the current week.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from models import db, WeeklyCprLevel, WeeklyOHLCData
from sqlalchemy import and_, func

logger = logging.getLogger(__name__)

class WeeklyCprCalculator:
    """
    Weekly Central Pivot Range (CPR) Calculator
    
    CPR formulas (using weekly OHLC data):
    - Pivot Point (PP) = (Weekly_High + Weekly_Low + Weekly_Close) / 3
    - Top Central (TC) = (PP - BC) + PP = 2*PP - BC
    - Bottom Central (BC) = (Weekly_High + Weekly_Low) / 2
    - R1 = 2*PP - Weekly_Low
    - R2 = PP + (Weekly_High - Weekly_Low)
    - R3 = Weekly_High + 2*(PP - Weekly_Low)
    - S1 = 2*PP - Weekly_High
    - S2 = PP - (Weekly_High - Weekly_Low)
    - S3 = Weekly_Low - 2*(Weekly_High - PP)
    """

    def __init__(self):
        self.levels = {}

    def calculate_weekly_cpr_levels(self, symbol: str, week_high: float, week_low: float,
                                   week_close: float, prev_week_close: float,
                                   week_start_date, week_end_date, year: int,
                                   week_number: int) -> Optional[Dict]:
        """Calculate weekly CPR levels for a symbol using weekly H, L, C data"""
        try:
            # Basic CPR calculations using weekly data
            pp = (week_high + week_low + week_close) / 3  # Pivot Point
            bc = (week_high + week_low) / 2  # Bottom Central
            tc = (2 * pp) - bc  # Top Central

            # Support and Resistance levels
            r1 = (2 * pp) - week_low
            r2 = pp + (week_high - week_low)
            r3 = week_high + (2 * (pp - week_low))

            s1 = (2 * pp) - week_high
            s2 = pp - (week_high - week_low)
            s3 = week_low - (2 * (week_high - pp))

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
                'tc': tc,
                'bc': bc,
                'r1': r1,
                'r2': r2,
                'r3': r3,
                's1': s1,
                's2': s2,
                's3': s3,
                'calculated_at': datetime.now(timezone.utc)
            }

            self.levels[symbol] = levels
            logger.info(f"Weekly CPR levels calculated for {symbol} (Week {year}-W{week_number})")
            return levels

        except Exception as e:
            logger.error(f"Error calculating weekly CPR levels for {symbol}: {e}")
            return {}

    def determine_weekly_break_level(self, symbol: str, current_ltp: float) -> Optional[str]:
        """Determine which weekly CPR level is broken"""
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
        else:
            return 'CPR'

    def determine_weekly_trend_direction(self, symbol: str, current_ltp: float) -> Optional[str]:
        """Determine weekly trend direction based on CPR levels"""
        if symbol not in self.levels:
            return None

        levels = self.levels[symbol]

        if current_ltp > levels['tc']:
            return 'bullish'
        elif current_ltp < levels['bc']:
            return 'bearish'
        else:
            return 'sideways'

    def save_weekly_cpr_to_database(self, symbol: str, current_ltp: Optional[float] = None) -> bool:
        """Save calculated weekly CPR levels to database"""
        try:
            if symbol not in self.levels:
                logger.error(f"No weekly CPR levels calculated for {symbol}")
                return False

            levels = self.levels[symbol]
            
            # Determine break level and trend if LTP provided
            break_level = None
            trend_direction = None
            if current_ltp is not None:
                break_level = self.determine_weekly_break_level(symbol, current_ltp)
                trend_direction = self.determine_weekly_trend_direction(symbol, current_ltp)

            # Check if record already exists for this symbol and week
            existing_record = WeeklyCprLevel.query.filter_by(
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
                existing_record.tc = levels['tc']
                existing_record.bc = levels['bc']
                existing_record.r1 = levels['r1']
                existing_record.r2 = levels['r2']
                existing_record.r3 = levels['r3']
                existing_record.s1 = levels['s1']
                existing_record.s2 = levels['s2']
                existing_record.s3 = levels['s3']
                existing_record.current_ltp = current_ltp
                existing_record.break_level = break_level
                existing_record.trend_direction = trend_direction
                existing_record.updated_at = datetime.now(timezone.utc)
                
                logger.info(f"Updated weekly CPR record for {symbol} (Week {levels['year']}-W{levels['week_number']})")
            else:
                # Create new record
                cpr_record = WeeklyCprLevel(
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
                    tc=levels['tc'],
                    bc=levels['bc'],
                    r1=levels['r1'],
                    r2=levels['r2'],
                    r3=levels['r3'],
                    s1=levels['s1'],
                    s2=levels['s2'],
                    s3=levels['s3'],
                    current_ltp=current_ltp,
                    break_level=break_level,
                    trend_direction=trend_direction
                )
                
                db.session.add(cpr_record)
                logger.info(f"Created new weekly CPR record for {symbol} (Week {levels['year']}-W{levels['week_number']})")

            db.session.commit()
            return True

        except Exception as e:
            logger.error(f"Error saving weekly CPR levels for {symbol}: {e}")
            db.session.rollback()
            return False

    def calculate_and_save_all_weekly_cpr(self) -> Dict[str, int]:
        """Calculate and save weekly CPR levels for all symbols with weekly data"""
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

                    # Calculate weekly CPR levels
                    levels = self.calculate_weekly_cpr_levels(
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
                        if self.save_weekly_cpr_to_database(current_week.symbol, float(current_week.close_price)):
                            results['saved'] += 1
                        else:
                            results['errors'] += 1
                    else:
                        results['errors'] += 1

                except Exception as e:
                    logger.error(f"Error processing weekly CPR for {current_week.symbol}: {e}")
                    results['errors'] += 1

            logger.info(f"Weekly CPR calculation completed: {results}")
            return results

        except Exception as e:
            logger.error(f"Error in calculate_and_save_all_weekly_cpr: {e}")
            return {'calculated': 0, 'saved': 0, 'errors': 1}

    def get_weekly_cpr_data(self) -> list:
        """Get all weekly CPR data from database"""
        try:
            # Get the most recent weekly CPR data for all symbols
            subquery = db.session.query(
                WeeklyCprLevel.symbol,
                func.max(WeeklyCprLevel.week_end_date).label('max_week')
            ).group_by(WeeklyCprLevel.symbol).subquery()
            
            weekly_cpr_records = db.session.query(WeeklyCprLevel).join(
                subquery,
                and_(
                    WeeklyCprLevel.symbol == subquery.c.symbol,
                    WeeklyCprLevel.week_end_date == subquery.c.max_week
                )
            ).order_by(WeeklyCprLevel.symbol).all()

            return [record.to_dict() for record in weekly_cpr_records]

        except Exception as e:
            logger.error(f"Error getting weekly CPR data: {e}")
            return []