import json
import os
from typing import List, Dict, Optional
from datetime import datetime


class SymbolsLoader:
    """
    Centralized loader for F&O symbols configuration.
    Caches symbols on startup and provides refresh capability.
    """
    
    def __init__(self):
        self._fo_symbols_cache = None
        self._config_path = "config/fo_symbols.json"
        self._last_loaded = None
    
    def _load_fo_symbols(self) -> Dict:
        """Load F&O symbols from JSON file."""
        try:
            if not os.path.exists(self._config_path):
                raise FileNotFoundError(f"F&O symbols config not found at {self._config_path}")
            
            with open(self._config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate structure
            if 'symbols' not in data or not isinstance(data['symbols'], list):
                raise ValueError("Invalid F&O symbols config structure")
            
            self._last_loaded = datetime.now()
            return data
        
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            print(f"Error loading F&O symbols: {e}")
            # Return empty structure as fallback
            return {
                "exchange": "BSE",
                "updated_at": datetime.now().strftime("%Y-%m-%d"),
                "description": "Fallback empty symbols",
                "symbols": []
            }
    
    def get_fo_symbols_data(self) -> Dict:
        """Get complete F&O symbols data with metadata."""
        if self._fo_symbols_cache is None:
            self._fo_symbols_cache = self._load_fo_symbols()
        return self._fo_symbols_cache
    
    def get_fo_tv_symbols(self, max_count: Optional[int] = None, active_only: bool = True) -> List[str]:
        """
        Get TradingView format symbols for F&O stocks.
        
        Args:
            max_count: Maximum number of symbols to return
            active_only: Only return symbols marked as active
            
        Returns:
            List of TradingView format symbols (e.g., ["BSE:RELIANCE", "BSE:TCS"])
        """
        data = self.get_fo_symbols_data()
        symbols = data.get('symbols', [])
        
        # Filter active symbols if requested
        if active_only:
            symbols = [s for s in symbols if s.get('active', True)]
        
        # Sort by order field if available
        symbols.sort(key=lambda x: x.get('order', 999))
        
        # Extract TradingView format symbols
        tv_symbols = [s.get('tv', '') for s in symbols if s.get('tv')]
        
        # Apply max count limit
        if max_count and max_count > 0:
            tv_symbols = tv_symbols[:max_count]
        
        return tv_symbols
    
    def get_fo_symbols_for_tradingview_widget(self, max_symbols: int = 20) -> List[List[str]]:
        """
        Get F&O symbols formatted for TradingView Symbol Overview widget.
        Returns list of symbol pairs for the widget configuration.
        
        Args:
            max_symbols: Maximum number of symbols to include
            
        Returns:
            List of symbol pairs in format [["DISPLAY_NAME", "BSE:SYMBOL|12M"], ...]
        """
        data = self.get_fo_symbols_data()
        symbols = data.get('symbols', [])
        
        # Filter active symbols and sort by order
        active_symbols = [s for s in symbols if s.get('active', True)]
        active_symbols.sort(key=lambda x: x.get('order', 999))
        
        # Limit to max_symbols
        if max_symbols > 0:
            active_symbols = active_symbols[:max_symbols]
        
        # Format for TradingView widget
        widget_symbols = []
        for symbol in active_symbols:
            display_name = symbol.get('display', symbol.get('symbol', ''))
            tv_symbol = symbol.get('tv', '')
            
            if tv_symbol:
                # Add 12M timeframe to symbol
                widget_symbols.append([display_name, f"{tv_symbol}|12M"])
        
        return widget_symbols
    
    def get_symbols_by_category(self, category: str = "all") -> List[Dict]:
        """Get symbols filtered by category (future enhancement)."""
        data = self.get_fo_symbols_data()
        return data.get('symbols', [])
    
    def refresh_cache(self) -> bool:
        """
        Force reload of symbols from file.
        Returns True if successful, False otherwise.
        """
        try:
            self._fo_symbols_cache = self._load_fo_symbols()
            return True
        except Exception as e:
            print(f"Error refreshing symbols cache: {e}")
            return False
    
    def get_cache_info(self) -> Dict:
        """Get information about the current cache state."""
        return {
            "cached": self._fo_symbols_cache is not None,
            "last_loaded": self._last_loaded.isoformat() if self._last_loaded else None,
            "config_path": self._config_path,
            "symbols_count": len(self._fo_symbols_cache.get('symbols', [])) if self._fo_symbols_cache else 0
        }


# Global instance
symbols_loader = SymbolsLoader()


# Convenience functions
def get_fo_tv_symbols(max_count: Optional[int] = None) -> List[str]:
    """Convenience function to get F&O TradingView symbols."""
    return symbols_loader.get_fo_tv_symbols(max_count=max_count)


def get_fo_symbols_for_widget(max_symbols: int = 20) -> List[List[str]]:
    """Convenience function to get F&O symbols for TradingView widget."""
    return symbols_loader.get_fo_symbols_for_tradingview_widget(max_symbols=max_symbols)


def get_fo_symbols_for_chart() -> List[str]:
    """Get F&O symbols for live chart (simple symbol names only)."""
    data = symbols_loader.get_fo_symbols_data()
    symbols = data.get('symbols', [])
    
    # Filter active symbols and sort by order
    active_symbols = [s for s in symbols if s.get('active', True)]
    active_symbols.sort(key=lambda x: x.get('order', 999))
    
    # Extract simple symbol names
    chart_symbols = []
    for symbol in active_symbols:
        symbol_name = symbol.get('symbol', '')
        if symbol_name:
            chart_symbols.append(symbol_name)
    
    return chart_symbols


def refresh_symbols_cache() -> bool:
    """Convenience function to refresh the symbols cache."""
    return symbols_loader.refresh_cache()