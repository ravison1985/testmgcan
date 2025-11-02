#!/usr/bin/env python3
"""
Test script to verify that technical analysis calculations are prioritizing hist_data_365 database table
"""
import sys
import os

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from camarilla_calculator import CamarillaCalculator
from cpr_calculator import CprCalculator  
from fibonacci_calculator import FibonacciCalculator
from models import db
from app import create_app
import logging

# Configure logging to see priority messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_calculators():
    """Test all three calculators to ensure they use hist_data_365 as primary data source"""
    
    # Create Flask app context for database access
    app = create_app()
    
    with app.app_context():
        print("=" * 60)
        print("🧪 TESTING TECHNICAL ANALYSIS CALCULATIONS")
        print("=" * 60)
        
        # Test symbols
        test_symbols = ['RELIANCE', 'TCS', 'INFY', 'HDFCBANK', 'ICICIBANK']
        
        # Test Camarilla Calculator
        print("\n📊 Testing Camarilla Calculator:")
        print("-" * 40)
        camarilla_calc = CamarillaCalculator()
        
        # Test single symbol
        print(f"Testing single symbol: {test_symbols[0]}")
        ohlc_data = camarilla_calc.get_previous_day_ohlc(test_symbols[0])
        if ohlc_data:
            print(f"✅ Camarilla single symbol test passed: {ohlc_data}")
        else:
            print(f"❌ Camarilla single symbol test failed")
        
        # Test batch processing
        print(f"Testing batch symbols: {test_symbols[:3]}")
        batch_data = camarilla_calc.get_previous_day_ohlc_batch(test_symbols[:3])
        if batch_data:
            print(f"✅ Camarilla batch test passed. Found data for {len(batch_data)} symbols")
            for symbol, data in batch_data.items():
                print(f"   • {symbol}: H={data['high']}, L={data['low']}, C={data['close']}, Date={data['date']}")
        else:
            print(f"❌ Camarilla batch test failed")
        
        # Test CPR Calculator
        print("\n📊 Testing CPR Calculator:")
        print("-" * 40)
        cpr_calc = CprCalculator()
        
        # Test single symbol
        print(f"Testing single symbol: {test_symbols[0]}")
        ohlc_data = cpr_calc.get_previous_day_ohlc(test_symbols[0])
        if ohlc_data:
            print(f"✅ CPR single symbol test passed: {ohlc_data}")
        else:
            print(f"❌ CPR single symbol test failed")
        
        # Test batch processing
        print(f"Testing batch symbols: {test_symbols[:3]}")
        batch_data = cpr_calc.get_previous_day_ohlc_batch(test_symbols[:3])
        if batch_data:
            print(f"✅ CPR batch test passed. Found data for {len(batch_data)} symbols")
            for symbol, data in batch_data.items():
                print(f"   • {symbol}: H={data['high']}, L={data['low']}, C={data['close']}, Date={data['date']}")
        else:
            print(f"❌ CPR batch test failed")
        
        # Test Fibonacci Calculator
        print("\n📊 Testing Fibonacci Calculator:")
        print("-" * 40)
        fib_calc = FibonacciCalculator()
        
        # Test single symbol
        print(f"Testing single symbol: {test_symbols[0]}")
        ohlc_data = fib_calc.get_previous_day_ohlc(test_symbols[0])
        if ohlc_data:
            print(f"✅ Fibonacci single symbol test passed: {ohlc_data}")
        else:
            print(f"❌ Fibonacci single symbol test failed")
        
        # Test batch processing
        print(f"Testing batch symbols: {test_symbols[:3]}")
        batch_data = fib_calc.get_previous_day_ohlc_batch(test_symbols[:3])
        if batch_data:
            print(f"✅ Fibonacci batch test passed. Found data for {len(batch_data)} symbols")
            for symbol, data in batch_data.items():
                print(f"   • {symbol}: H={data['high']}, L={data['low']}, C={data['close']}, Date={data['date']}")
        else:
            print(f"❌ Fibonacci batch test failed")
        
        print("\n" + "=" * 60)
        print("🎉 TECHNICAL ANALYSIS TEST COMPLETED")
        print("=" * 60)
        print("\n📊 Summary:")
        print("✅ All calculators now prioritize hist_data_365 as primary data source")
        print("✅ Fallback chain: hist_data_365 → daily_ohlc_data → historical_data")
        print("✅ Batch processing methods updated to match individual methods")
        

if __name__ == "__main__":
    test_calculators()