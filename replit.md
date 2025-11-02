# Overview

This is a real-time stock market dashboard application that provides live streaming data for Nifty 50 stocks using the Fyers API. The application features a Flask-based web server with WebSocket connectivity for real-time market data updates, user authentication through Fyers OAuth, and a responsive web interface for monitoring stock prices, changes, and trading volumes.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Technology Stack**: HTML5, CSS3, Bootstrap 5 (dark theme), JavaScript ES6+, Font Awesome icons
- **Design Pattern**: Single Page Application (SPA) with dynamic content updates
- **Real-time Updates**: WebSocket connections for live data streaming to the frontend
- **Responsive Design**: Mobile-first approach using Bootstrap grid system
- **State Management**: Client-side JavaScript classes for authentication and data handling

### Backend Architecture
- **Web Framework**: Flask (Python) with session management
- **Authentication Flow**: OAuth 2.0 integration with Fyers API using authorization code grant
- **WebSocket Management**: Custom WebSocketManager class for handling real-time market data
- **API Integration**: Fyers API v3 for market data and authentication
- **Data Processing**: Real-time message parsing and stock data normalization
- **Security**: Session-based authentication with configurable secret keys

### Data Flow Architecture
- **Real-time Streaming**: WebSocket connection to Fyers for live market data
- **Data Queue**: In-memory queue system for handling incoming market updates (legacy - bypassed for performance)
- **Stock Data Storage**: Thread-safe in-memory dictionary for current stock prices and metadata
- **Client Updates**: HTTP polling with broadcast pattern for multi-user scalability
- **Performance Optimization** (Oct 2025):
  - Eliminated queue consumption bottleneck - all users now receive identical cached snapshots
  - Implemented thread-safe locks (`stock_data_lock`, `alerts_cache_lock`) to prevent RuntimeError on concurrent access
  - Broadcast pattern for alerts with 10-second auto-expiry cache
  - Scales efficiently with 10-20+ concurrent users without data depletion or slowdowns

### Authentication System
- **OAuth Provider**: Fyers API OAuth 2.0 implementation
- **Token Management**: Access token generation and validation
- **Session Handling**: Flask sessions for maintaining user authentication state
- **Redirect Flow**: External URL redirection for OAuth callback handling

## External Dependencies

### Third-Party APIs
- **Fyers API v3**: Primary integration for stock market data and authentication
  - Real-time WebSocket data feeds
  - OAuth 2.0 authentication endpoints
  - Market data for Nifty 50 stocks

### Libraries and Frameworks
- **Flask**: Web application framework and routing
- **fyers_apiv3**: Official Fyers API Python SDK for market data and authentication
- **Bootstrap 5**: Frontend CSS framework with dark theme
- **Font Awesome**: Icon library for UI components
- **WebSocket**: Real-time bidirectional communication

### Market Data Coverage
- **Nifty 50 Index**: Complete coverage of all 50 constituent stocks
- **Real-time Data**: Live price updates, volume, and percentage changes
- **Market Hours**: Live streaming during market operating hours

### Configuration Dependencies
- **Environment Variables**: Session secrets and API configuration
- **Static Assets**: CSS, JavaScript, and image files served by Flask
- **Template Engine**: Jinja2 for HTML template rendering

### Email Integration
- **Service**: Gmail SMTP (via App Password)
- **Environment Variables**: SMTP_EMAIL, SMTP_PASSWORD
- **Implementation**: Custom email sending function using smtplib
- **Trigger Points**: 
  - After successful Razorpay payment
  - After 100% coupon activation (free subscription)
- **Email Content**: Professional HTML email with subscription details, plan info, and dashboard link
- **Note**: Using Gmail SMTP instead of Replit integrations as per user preference