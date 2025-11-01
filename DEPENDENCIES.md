# Python Dependencies

This file lists all Python packages used in this trading dashboard application.

## Core Framework
- **flask** - Web framework for the application
- **gunicorn** - WSGI HTTP server for production deployment
- **jinja2** - Template engine for Flask

## Authentication & Security
- **flask-login** - User session management
- **flask-dance** - OAuth integration (Google login)
- **oauthlib** - OAuth client and server library
- **pyjwt** - JSON Web Token implementation

## Database
- **flask-sqlalchemy** - SQLAlchemy integration for Flask
- **sqlalchemy** - SQL toolkit and ORM
- **psycopg2-binary** - PostgreSQL database adapter

## Data Processing & Analysis
- **numpy** - Numerical computing library
- **pandas** - Data manipulation and analysis

## Trading & Market Data
- **fyers-apiv3** - Fyers API client for market data and trading

## Payment Processing
- **razorpay** - Payment gateway integration

## Utilities
- **email-validator** - Email validation
- **pillow** - Image processing library
- **pytz** - Timezone calculations
- **requests** - HTTP library for API calls
- **schedule** - Job scheduling for automated tasks
- **werkzeug** - WSGI utility library

## Installation

On Replit, packages are automatically managed. If deploying elsewhere, install using:

```bash
pip install email-validator flask flask-dance flask-login flask-sqlalchemy fyers-apiv3 gunicorn jinja2 numpy oauthlib pandas pillow psycopg2-binary pyjwt pytz razorpay requests schedule sqlalchemy werkzeug
```

Or create a traditional requirements.txt file with these packages and run:
```bash
pip install -r requirements.txt
```
