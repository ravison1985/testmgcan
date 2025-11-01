# Stock Market Dashboard - Complete User Manual

## Table of Contents
1. [Dashboard Overview](#dashboard-overview)
2. [Real-Time Data System](#real-time-data-system)
3. [Market Overview Section](#market-overview-section)
4. [RVOL Analysis Chart](#rvol-analysis-chart)
5. [F&O Stocks Summary](#fo-stocks-summary)
6. [Technical Analysis Systems](#technical-analysis-systems)
7. [Data Refresh Timings](#data-refresh-timings)
8. [Calculation Methodologies](#calculation-methodologies)
9. [Color Coding System](#color-coding-system)
10. [Troubleshooting](#troubleshooting)

---

## Dashboard Overview

The Stock Market Dashboard is a comprehensive real-time trading analysis tool featuring:
- Live WebSocket data streaming for 228 F&O stocks and INDEX symbols
- Real-time RVOL (Relative Volume) calculations and visualization
- Technical analysis with CPR, Camarilla, and Fibonacci levels
- Automatic end-of-day data storage at 3:45 PM IST
- Interactive market statistics and pattern detection

**Main Dashboard Layout:**
- Top: Market Overview with Index Cards (NIFTY 50, SENSEX, BANK NIFTY, etc.)
- Middle: RVOL Analysis Chart spanning full width
- Bottom: F&O Stocks Summary with 9 analytical cards
- Side: Technical Analysis Tables (CPR, Camarilla, Fibonacci)

---

## Real-Time Data System

### WebSocket Connection
- **Status**: Always displayed in top navigation
- **Symbols**: 228 F&O stocks + INDEX symbols
- **Update Frequency**: Real-time (sub-second updates)
- **Connection Indicator**: Green dot = Connected, Red dot = Disconnected

### Data Sources
- **Primary**: Fyers API via WebSocket
- **Backup**: Historical data from PostgreSQL database
- **Symbols Covered**: 228 subscribed symbols (206 calculated for RVOL), NSE F&O stocks, major indices, sectoral indices

---

## Market Overview Section

### Index Cards Display
**Layout**: Horizontal scrollable row with major indices
- NIFTY 50, SENSEX, BANK NIFTY, NIFTY IT, FIN NIFTY
- MIDCAP SELECT, NIFTY NEXT 50, NIFTY FMCG, NIFTY PHARMA
- NIFTY AUTO, NIFTY METAL, NIFTY REALTY, and more

### Card Information Display
Each index card shows:
- **Index Name**: Abbreviated form (e.g., "NIFTY 50")
- **Current Price**: Real-time LTP (Last Traded Price)
- **Change**: Absolute price change from previous close
- **Change %**: Percentage change with color coding
- **Status Tags**: O=H/O=L pattern indicators and CPR level tags

### Pattern Tags
- **O=H Tag**: Blue badge when Open = High (within 0.1% tolerance)
- **O=L Tag**: Yellow badge when Open = Low (within 0.1% tolerance)
- **CPR Tags**: Show current price position relative to CPR levels
  - Examples: "R2-R3", "TC-R1", "CPR", "S1-S2"

---

## RVOL Analysis Chart

### Chart Display
**Type**: Full-width vertical bar chart
**Position**: Below Market Overview, spanning all 4 columns
**Data**: Top 50 stocks by RVOL value

### RVOL Calculation Method
```
RVOL = Current Volume / 5-Day Average Volume

Where:
- Current Volume = Today's accumulated volume at current time
- 5-Day Average Volume = Average of last 5 trading days' total volume
```

### Color Coding System
- **Red Bars**: RVOL ≥ 2.0 (Extremely High Volume)
- **Yellow Bars**: RVOL 1.5-2.0 (High Volume)
- **Green Bars**: RVOL 0.7-1.5 (Normal Volume)
- **Blue Bars**: RVOL < 0.7 (Low Volume)

### Chart Features
- **Interactive**: Hover for exact RVOL values
- **Auto-Update**: Refreshes every 30 seconds
- **Dynamic Scaling**: Y-axis adjusts based on maximum RVOL
- **Symbol Labels**: Stock symbols on X-axis

---

## F&O Stocks Summary

### Summary Cards (9 Cards Total)

#### Market Movement Cards
1. **Gainers**: Stocks with positive change %
2. **Losers**: Stocks with negative change %
3. **Recovery**: Stocks that opened down but turned positive
4. **Declining**: Stocks that opened up but turned negative

#### Market Analytics Cards
5. **Gap Up**: Stocks with opening gap > 0.5% above previous close
6. **Gap Down**: Stocks with opening gap > 0.5% below previous close
7. **Turn+**: Stocks that turned positive during the day
8. **Turn-**: Stocks that turned negative during the day
9. **Avg %**: Average percentage change across all F&O stocks

#### Pattern Detection Cards
10. **O=H**: Count of stocks where Open = High
11. **O=L**: Count of stocks where Open = Low

### Card Color Schemes
- **Green Cards**: Positive metrics (Gainers, Recovery, Turn+)
- **Red Cards**: Negative metrics (Losers, Declining, Turn-)
- **Blue Cards**: Neutral metrics (Gap analysis)
- **Yellow Cards**: Pattern metrics (O=H, O=L)

---

## Technical Analysis Systems

### CPR (Central Pivot Range) Analysis

#### Calculation Formula
```
Pivot Point (PP) = (High + Low + Close) / 3
Bottom Central (BC) = (High + Low) / 2
Top Central (TC) = (2 * PP) - BC

Resistance Levels:
R1 = (2 * PP) - Low
R2 = PP + (High - Low)
R3 = High + 2 * (PP - Low)

Support Levels:
S1 = (2 * PP) - High
S2 = PP - (High - Low)
S3 = Low - 2 * (High - PP)
```

#### Level Interpretations
- **Above R3**: Strong bullish momentum
- **R2-R3**: Bullish with resistance
- **R1-R2**: Moderate bullish
- **TC-R1**: Weak bullish, near resistance
- **CPR Range**: Consolidation zone (between BC and TC)
- **BC-S1**: Weak bearish, near support
- **S1-S2**: Moderate bearish
- **S2-S3**: Bearish with support
- **Below S3**: Strong bearish momentum

### Camarilla Levels

#### Calculation Method
```
Range = High - Low
Base Factor = 1.1 / 12

Resistance Levels:
H1 = Close + (Range * Base Factor)
H2 = Close + (Range * Base Factor * 2)  // 1.1/6
H3 = Close + (Range * Base Factor * 3)  // 1.1/4
H4 = Close + (Range * Base Factor * 6)  // 1.1/2
H5 = (High / Low) * Close

Support Levels:
L1 = Close - (Range * Base Factor)
L2 = Close - (Range * Base Factor * 2)  // 1.1/6
L3 = Close - (Range * Base Factor * 3)  // 1.1/4
L4 = Close - (Range * Base Factor * 6)  // 1.1/2
L5 = Close - (H5 - Close)
```

#### Trading Significance
- **H4/L4**: Primary reversal levels (strongest support/resistance)
- **H3/L3**: Secondary support/resistance levels
- **H2/L2, H1/L1**: Minor support/resistance levels
- **H5/L5**: Extreme breakout levels for major trending moves

### Fibonacci Retracements

#### Standard Levels
- **23.6%**: Minor retracement
- **38.2%**: Moderate retracement
- **50.0%**: Half retracement
- **61.8%**: Golden ratio retracement
- **78.6%**: Deep retracement

#### Calculation Base
Uses previous day's High-Low range applied to current day's movement

---

## Data Refresh Timings

### Real-Time Updates
- **WebSocket Data**: Continuous (sub-second)
- **RVOL Chart**: Every 30 seconds
- **Index Cards**: Real-time with WebSocket data
- **WebSocket Status Check**: Every 10 seconds
- **Index Analysis Charts**: Every 10 seconds
- **Stock Analysis Charts**: Every 10 seconds
- **Technical Levels**: Calculated once at market open, updated with new data

### Scheduled Operations
- **EOD Data Save**: 3:45 PM IST (15:45:54 IST exactly)
- **Technical Analysis Refresh**: Market open (9:15 AM IST)
- **Database Cleanup**: Weekly maintenance
- **RVOL Base Calculation**: Daily at market close

### Manual Refresh Options
- **Browser Refresh**: Reloads all data
- **WebSocket Reconnect**: Automatic on connection loss
- **Force Refresh**: Available in admin panel

---

## Calculation Methodologies

### Volume Analysis
```
Daily Volume Accumulation:
- Starts from market open (9:15 AM)
- Accumulates throughout trading session
- Resets daily

RVOL Base Calculation:
- Uses last 5 trading days' complete volume data (minimum 3 days required)
- Queries historical_data table with resolution = '1D'
- Excludes current day from average
- Updates daily post-market close
- SQL Query: SELECT AVG(volume) FROM last 5 trading days WHERE volume > 0
```

### Pattern Detection Logic
```
O=H Detection:
if abs(Open - High) <= (High * 0.001):  # 0.1% tolerance
    pattern = "O=H"

O=L Detection:
if abs(Open - Low) <= (Low * 0.001):   # 0.1% tolerance
    pattern = "O=L"
```

### Price Change Calculations
```
Absolute Change = Current LTP - Previous Close
Percentage Change = (Absolute Change / Previous Close) * 100

Gap Analysis (Summary Cards):
Gap Up = (Open - Previous Close) / Previous Close > 0.5%
Gap Down = (Open - Previous Close) / Previous Close < -0.5%

Gap Analysis (Pattern Badges):
Gap Up Pattern = (Open - Previous Close) / Previous Close > 2.0%
Gap Down Pattern = (Open - Previous Close) / Previous Close < -2.0%

Note: Summary cards use ±0.5% threshold for counts, while individual stock pattern badges use ±2.0% threshold.
```

---

## Color Coding System

### Universal Color Scheme
- **Green**: Positive/Bullish (gains, recovery, above levels)
- **Red**: Negative/Bearish (losses, decline, below levels)
- **Blue**: Neutral/Informational (patterns, gap analysis)
- **Yellow**: Warning/Attention (moderate levels, O=L patterns)
- **Purple**: Special cases (INDIAVIX, unique indices)

### Status Indicators
- **Live Green Dot**: Real-time data flowing
- **Yellow Dot**: Stale data (>30 seconds old)
- **Red Dot**: Connection error or no data

### Badge Sizing
- **Index Cards**: 0.3rem font size for O=H/O=L and CPR tags
- **Main Tables**: 0.4rem font size for status badges
- **Summary Cards**: 0.7rem for main metrics

---

## Troubleshooting

### Common Issues

#### WebSocket Connection Problems
**Symptoms**: Red status indicator, no real-time updates
**Solutions**:
1. Check internet connection
2. Refresh browser page
3. Verify Fyers API token validity
4. Check admin panel for authentication status

#### Missing RVOL Data
**Symptoms**: Empty RVOL chart, zero values
**Solutions**:
1. Ensure sufficient historical data (minimum 5 days)
2. Check WebSocket connectivity
3. Verify market hours (9:15 AM - 3:30 PM IST)
4. Force refresh from admin panel

#### Slow Performance
**Symptoms**: Delayed updates, browser lag
**Solutions**:
1. Close unnecessary browser tabs
2. Clear browser cache
3. Check system resources
4. Use modern browser (Chrome/Firefox recommended)

### Data Accuracy Notes
- **Pre-Market**: Data may be limited before 9:15 AM IST
- **Post-Market**: RVOL calculations continue until 4:00 PM IST
- **Holidays**: No live updates on market holidays
- **Corporate Actions**: May affect historical calculations

### Support Information
- **Technical Issues**: Check browser console for error messages
- **Data Discrepancies**: Compare with official exchange data
- **Feature Requests**: Document specific requirements
- **Performance Issues**: Note system specifications and browser version

---

## Appendix

### Keyboard Shortcuts
- **F5**: Refresh page and reload all data
- **Ctrl+Shift+R**: Hard refresh (clear cache)
- **F12**: Open browser developer tools for debugging

### Browser Compatibility
- **Recommended**: Chrome 90+, Firefox 88+, Safari 14+
- **Minimum**: Any modern browser with WebSocket support
- **Not Supported**: Internet Explorer

### System Requirements
- **RAM**: Minimum 4GB (8GB recommended for smooth operation)
- **Internet**: Stable broadband connection (minimum 1 Mbps)
- **Screen**: 1366x768 minimum (1920x1080 recommended for full layout)

---

## Section Photos and Visual References

**Important Note**: This manual provides comprehensive text descriptions of all dashboard sections. For visual references and section photos as requested, please take screenshots of your live dashboard while using it, as the exact appearance will vary based on:
- Current market data and real-time updates
- Browser type and screen resolution  
- Market hours vs. after-hours display states
- Individual stock performance and color coding

**Recommended Screenshots to Take**:
1. **Market Overview Section**: Index cards showing NIFTY 50, SENSEX, BANK NIFTY with O=H/O=L and CPR tags
2. **RVOL Analysis Chart**: Full-width bar chart with color-coded volume analysis
3. **F&O Stocks Summary**: 9-card summary layout with market statistics
4. **Technical Analysis Tables**: CPR, Camarilla, and Fibonacci level tables with break status
5. **WebSocket Status**: Connection indicator and real-time data flow status

---

*This manual covers all features of the Stock Market Dashboard as of September 2025. For updates and additional features, refer to the latest version of this documentation.*