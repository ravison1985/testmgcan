"""
Technical Indicators Calculator
Calculates RSI, MACD, Stochastic, and ADX indicators for stocks
"""
import logging
from typing import Dict, List, Optional
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class TechnicalIndicators:
    """Calculate various technical indicators from OHLC data"""
    
    @staticmethod
    def calculate_rsi(prices: List[float], period: int = 14) -> Optional[float]:
        """Calculate Relative Strength Index (RSI)"""
        try:
            if len(prices) < period + 1:
                return None
            
            deltas = np.diff(prices)
            gains = np.where(deltas > 0, deltas, 0)
            losses = np.where(deltas < 0, -deltas, 0)
            
            avg_gain = np.mean(gains[:period])
            avg_loss = np.mean(losses[:period])
            
            for i in range(period, len(gains)):
                avg_gain = (avg_gain * (period - 1) + gains[i]) / period
                avg_loss = (avg_loss * (period - 1) + losses[i]) / period
            
            if avg_loss == 0:
                return 100
            
            rs = avg_gain / avg_loss
            rsi = 100 - (100 / (1 + rs))
            return round(rsi, 2)
        except Exception as e:
            logger.error(f"Error calculating RSI: {e}")
            return None
    
    @staticmethod
    def calculate_macd(prices: List[float], fast: int = 12, slow: int = 26, signal: int = 9) -> Dict:
        """Calculate MACD, Signal line, and Histogram"""
        try:
            if len(prices) < slow + signal:
                return {'macd': None, 'signal': None, 'histogram': None}
            
            prices_series = pd.Series(prices)
            
            # Calculate EMAs
            ema_fast = prices_series.ewm(span=fast, adjust=False).mean()
            ema_slow = prices_series.ewm(span=slow, adjust=False).mean()
            
            # MACD line
            macd_line = ema_fast - ema_slow
            
            # Signal line
            signal_line = macd_line.ewm(span=signal, adjust=False).mean()
            
            # Histogram
            histogram = macd_line - signal_line
            
            return {
                'macd': round(macd_line.iloc[-1], 2),
                'signal': round(signal_line.iloc[-1], 2),
                'histogram': round(histogram.iloc[-1], 2)
            }
        except Exception as e:
            logger.error(f"Error calculating MACD: {e}")
            return {'macd': None, 'signal': None, 'histogram': None}
    
    @staticmethod
    def calculate_stochastic(high: List[float], low: List[float], close: List[float], 
                            k_period: int = 14, k_smooth: int = 1, d_smooth: int = 3) -> Dict:
        """Calculate Fast Stochastic Oscillator (%K and %D) - Fyers standard (14,1,3)"""
        try:
            # Need enough data for lookback + smoothing
            if len(close) < k_period + d_smooth:
                return {'k': None, 'd': None}
            
            # Step 1: Calculate raw %K for multiple periods
            k_values = []
            for i in range(k_period, len(close) + 1):
                lowest_low = min(low[i-k_period:i])
                highest_high = max(high[i-k_period:i])
                
                if highest_high - lowest_low == 0:
                    k_values.append(50)
                else:
                    k_raw = 100 * (close[i-1] - lowest_low) / (highest_high - lowest_low)
                    k_values.append(k_raw)
            
            # Step 2: %K with smoothing = 1 means use raw %K (no smoothing)
            if k_smooth == 1:
                k_smoothed_values = k_values
            else:
                # Apply smoothing if k_smooth > 1
                k_smoothed_values = []
                for i in range(k_smooth - 1, len(k_values)):
                    k_sma = np.mean(k_values[i-k_smooth+1:i+1])
                    k_smoothed_values.append(k_sma)
            
            # Step 3: Calculate %D (SMA of %K)
            if len(k_smoothed_values) < d_smooth:
                return {'k': None, 'd': None}
            
            # Current %K
            k_value = k_smoothed_values[-1]
            
            # %D is SMA of the last d_smooth %K values
            d_value = np.mean(k_smoothed_values[-d_smooth:])
            
            return {
                'k': round(k_value, 2) if k_value is not None else None,
                'd': round(d_value, 2) if d_value is not None else None
            }
        except Exception as e:
            logger.error(f"Error calculating Stochastic: {e}")
            return {'k': None, 'd': None}
    
    @staticmethod
    def calculate_adx(high: List[float], low: List[float], close: List[float], period: int = 14, adx_smoothing: int = 14) -> Dict:
        """Calculate ADX with DI+ and DI- using TradingView/Fyers formula (RMA smoothing)"""
        try:
            if len(close) < period * 2 + adx_smoothing:
                return {'adx': None, 'di_plus': None, 'di_minus': None}
            
            # Step 1: Calculate True Range and Directional Movements
            tr_list = []
            dm_plus_list = []
            dm_minus_list = []
            
            for i in range(1, len(close)):
                up = high[i] - high[i-1]
                down = -(low[i] - low[i-1])  # -change(low)
                
                # True Range
                tr = max(
                    high[i] - low[i],
                    abs(high[i] - close[i-1]),
                    abs(low[i] - close[i-1])
                )
                tr_list.append(tr)
                
                # Directional Movement (TradingView logic)
                plusDM = up if (up > down and up > 0) else 0
                minusDM = down if (down > up and down > 0) else 0
                
                dm_plus_list.append(plusDM)
                dm_minus_list.append(minusDM)
            
            # Step 2: Apply RMA (Wilder's smoothing) to TR, +DM, -DM
            # Initial RMA values (first 'period' values averaged)
            tr_rma = np.mean(tr_list[:period])
            dm_plus_rma = np.mean(dm_plus_list[:period])
            dm_minus_rma = np.mean(dm_minus_list[:period])
            
            # Continue RMA smoothing
            for i in range(period, len(tr_list)):
                tr_rma = (tr_rma * (period - 1) + tr_list[i]) / period
                dm_plus_rma = (dm_plus_rma * (period - 1) + dm_plus_list[i]) / period
                dm_minus_rma = (dm_minus_rma * (period - 1) + dm_minus_list[i]) / period
            
            # Step 3: Calculate DI+ and DI-
            di_plus = 100 * (dm_plus_rma / tr_rma) if tr_rma != 0 else 0
            di_minus = 100 * (dm_minus_rma / tr_rma) if tr_rma != 0 else 0
            
            # Step 4: Calculate DX for each period and apply RMA to get ADX
            dx_values = []
            
            # Reset for DX calculation with RMA
            tr_rma = np.mean(tr_list[:period])
            dm_plus_rma = np.mean(dm_plus_list[:period])
            dm_minus_rma = np.mean(dm_minus_list[:period])
            
            for i in range(period - 1, len(tr_list)):
                if i >= period:
                    tr_rma = (tr_rma * (period - 1) + tr_list[i]) / period
                    dm_plus_rma = (dm_plus_rma * (period - 1) + dm_plus_list[i]) / period
                    dm_minus_rma = (dm_minus_rma * (period - 1) + dm_minus_list[i]) / period
                
                # Calculate DI+ and DI- for this point
                plus = 100 * (dm_plus_rma / tr_rma) if tr_rma != 0 else 0
                minus = 100 * (dm_minus_rma / tr_rma) if tr_rma != 0 else 0
                
                # Calculate DX: abs(DI+ - DI-) / (DI+ + DI-)
                sum_di = plus + minus
                if sum_di != 0:
                    dx = abs(plus - minus) / sum_di
                else:
                    dx = 0
                dx_values.append(dx)
            
            # Step 5: Apply RMA smoothing to DX to get ADX
            if len(dx_values) < adx_smoothing:
                return {'adx': None, 'di_plus': None, 'di_minus': None}
            
            # Initial ADX (average of first adx_smoothing DX values)
            adx = np.mean(dx_values[:adx_smoothing])
            
            # Continue RMA smoothing for ADX
            for i in range(adx_smoothing, len(dx_values)):
                adx = (adx * (adx_smoothing - 1) + dx_values[i]) / adx_smoothing
            
            # Multiply by 100 as per TradingView formula
            adx = adx * 100
            
            return {
                'adx': round(adx, 2),
                'di_plus': round(di_plus, 2),
                'di_minus': round(di_minus, 2)
            }
        except Exception as e:
            logger.error(f"Error calculating ADX: {e}")
            return {'adx': None, 'di_plus': None, 'di_minus': None}
    
    @staticmethod
    def get_rsi_status(rsi: Optional[float]) -> str:
        """Get RSI status based on value"""
        if rsi is None:
            return 'N/A'
        if rsi > 70:
            return 'Overbought'
        elif rsi >= 60:
            return 'Neutral to Slight Bullish'
        elif rsi > 40:
            return 'Neutral'
        elif rsi >= 30:
            return 'Neutral to Slightly Bearish'
        else:
            return 'Oversold'
    
    @staticmethod
    def get_macd_status(macd: Optional[float], signal: Optional[float]) -> str:
        """Get MACD status"""
        if macd is None or signal is None:
            return 'N/A'
        if macd > signal:
            return 'Bullish'
        else:
            return 'Bearish'
    
    @staticmethod
    def get_stochastic_status(k: Optional[float]) -> str:
        """Get Stochastic status based on %K"""
        if k is None:
            return 'N/A'
        if k > 80:
            return 'Overbought'
        elif k < 20:
            return 'Oversold'
        else:
            return 'Neutral'
    
    @staticmethod
    def get_adx_status(adx: Optional[float], di_plus: Optional[float], di_minus: Optional[float]) -> str:
        """Get ADX trend status"""
        if adx is None or di_plus is None or di_minus is None:
            return 'N/A'
        
        trend_strength = 'Weak' if adx < 25 else 'Strong' if adx > 50 else 'Moderate'
        trend_direction = 'Bullish' if di_plus > di_minus else 'Bearish'
        
        return f"{trend_strength} {trend_direction}"
