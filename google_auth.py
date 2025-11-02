# Google OAuth authentication blueprint - Reference: blueprint:flask_google_oauth

import json
import os
from datetime import datetime

import requests
from flask import Blueprint, redirect, request, url_for, session, flash, make_response
from flask_login import login_user, logout_user, login_required, current_user
from oauthlib.oauth2 import WebApplicationClient
import logging

from models import db, User, UserSession

logger = logging.getLogger(__name__)

# Import session management functions from app.py
# These will be set during blueprint registration
get_client_ip = None
create_user_session = None
deactivate_user_sessions = None
send_subscription_email = None

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Make sure to use this redirect URL. It has to match the one in the whitelist
if 'REPLIT_DEV_DOMAIN' in os.environ:
    DEV_REDIRECT_URL = f'https://{os.environ["REPLIT_DEV_DOMAIN"]}/google_login/callback'
    
    # Display setup instructions
    logger.info(f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║ To make Google authentication work:                                       ║
║ 1. Go to https://console.cloud.google.com/apis/credentials               ║
║ 2. Create a new OAuth 2.0 Client ID                                      ║
║ 3. Add {DEV_REDIRECT_URL}                                                   ║
║    to Authorized redirect URIs                                            ║
║                                                                           ║
║ For detailed instructions, see:                                          ║
║ https://docs.replit.com/additional-resources/google-auth-in-flask        ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)

client = WebApplicationClient(GOOGLE_CLIENT_ID) if GOOGLE_CLIENT_ID else None

google_auth = Blueprint("google_auth", __name__)


@google_auth.route("/google_login")
def login():
    """Initiate Google OAuth login"""
    import secrets
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth is not configured. Please contact the administrator.', 'danger')
        return redirect(url_for('landing'))
    
    # Generate and store OAuth state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Store the plan selection if it exists
    plan = request.args.get('plan')
    amount = request.args.get('amount')
    validity = request.args.get('validity')
    
    if plan:
        session['pending_plan'] = {
            'plan': plan,
            'amount': amount,
            'validity': validity
        }
    
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        # Replacing http:// with https:// is important as the external
        # protocol must be https to match the URI whitelisted
        redirect_uri=request.base_url.replace("http://", "https://") + "/callback",
        scope=["openid", "email", "profile"],
        state=state,
    )
    return redirect(request_uri)


@google_auth.route("/google_login/callback")
def callback():
    """Handle Google OAuth callback"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth is not configured. Please contact the administrator.', 'danger')
        return redirect(url_for('landing'))
    
    # Validate OAuth state for CSRF protection
    state = request.args.get("state")
    expected_state = session.pop('oauth_state', None)
    
    if not state or not expected_state or state != expected_state:
        logger.warning(f"OAuth state validation failed. Expected: {expected_state}, Got: {state}")
        flash("Invalid authentication request. Please try again.", "danger")
        return redirect(url_for('landing'))
    
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        # Replacing http:// with https:// is important as the external
        # protocol must be https to match the URI whitelisted
        authorization_response=request.url.replace("http://", "https://"),
        redirect_url=request.base_url.replace("http://", "https://"),
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    userinfo = userinfo_response.json()
    
    if not userinfo.get("email_verified"):
        flash("User email not available or not verified by Google.", "danger")
        return redirect(url_for('landing'))
    
    users_email = userinfo["email"]
    users_name = userinfo.get("given_name", userinfo.get("name", users_email.split('@')[0]))
    google_user_id = userinfo["sub"]  # Google's unique user ID
    profile_picture = userinfo.get("picture", "")  # Get profile picture URL

    # Validate profile picture URL (must be HTTPS)
    if profile_picture and not profile_picture.startswith("https://"):
        profile_picture = ""

    # Check if user exists by google_id or email
    try:
        user = User.query.filter(
            (User.google_id == google_user_id) | (User.email == users_email)
        ).first()
        
        if not user:
            # Create new user
            # Generate unique username from email
            base_username = users_email.split('@')[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User()
            user.username = username
            user.email = users_email
            user.google_id = google_user_id
            user.profile_image_url = profile_picture
            user.role = 'user'
            user.account_active = True
            
            # Generate random password for auto-created user
            import secrets
            random_password = secrets.token_urlsafe(32)
            user.set_password(random_password)
            
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user created via Google OAuth: {users_email}")
        else:
            # Update google_id and profile picture if user exists
            if not user.google_id:
                user.google_id = google_user_id
            # Update profile picture on each login to keep it fresh (only if valid URL)
            if profile_picture:
                user.profile_image_url = profile_picture
            db.session.commit()
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        logger.error(f"Database error during user creation/update: {e}")
        db.session.rollback()
        flash("An error occurred during sign-up. Please try again.", "danger")
        return redirect(url_for('landing'))
    
    # Log in the user
    login_user(user, remember=True)
    logger.info(f"User logged in via Google: {users_email}")
    
    # Create user session for IP-based security tracking
    if get_client_ip and create_user_session:
        try:
            client_ip = get_client_ip()
            user_agent = request.headers.get('User-Agent', '')
            create_user_session(user.id, client_ip, user_agent)
        except Exception as e:
            logger.error(f"Error creating user session: {e}")
            # Continue login even if session creation fails
    
    # Check if there's a pending plan selection
    pending_plan = session.pop('pending_plan', None)
    
    if pending_plan:
        # Check if it's a free plan (amount = 0)
        if pending_plan.get('amount') == '0' or pending_plan.get('amount') == 0:
            # Check if user has already used trial
            if user.has_used_trial:
                flash("Free trial can only be used once per account. Please select a paid plan.", "warning")
                return redirect(url_for('account'))
            
            # Free plan - activate 3-day trial and redirect to account page
            from datetime import date, timedelta
            user.subscription_period = 'free'
            user.subscription_start = date.today()
            user.subscription_end = date.today() + timedelta(days=3)
            user.account_active = True
            user.has_used_trial = True  # Mark trial as used
            db.session.commit()
            logger.info(f"Free trial activated for user {users_email}")
            
            # Send subscription activation email
            if send_subscription_email:
                try:
                    send_subscription_email(
                        user_email=user.email,
                        username=user.username,
                        plan_name='Free Trial (3 Days)',
                        start_date=user.subscription_start.strftime('%B %d, %Y'),
                        end_date=user.subscription_end.strftime('%B %d, %Y')
                    )
                except Exception as email_error:
                    logger.error(f"Failed to send subscription email: {str(email_error)}")
            
            # Free trial activated - redirect to dashboard
            return redirect(url_for('dashboard'))
        else:
            # Paid plan - redirect to payment
            flash(f"Welcome! Please complete your payment for the {pending_plan['plan']} plan.", "success")
            return redirect(url_for('landing') + f"#payment?plan={pending_plan['plan']}&amount={pending_plan['amount']}&validity={pending_plan['validity']}")
    else:
        # No pending plan - check if user has active subscription
        if user.is_subscription_active():
            # User has active plan - redirect to dashboard
            return redirect(url_for('dashboard'))
        else:
            # No active plan - redirect to account page
            return redirect(url_for('account', success=1))


@google_auth.route("/google_logout", methods=['POST'])
@login_required
def google_logout():
    """Logout user"""
    # Deactivate all user sessions
    if current_user.is_authenticated:
        user_id = current_user.id
        if deactivate_user_sessions:
            deactivate_user_sessions(user_id)
            logger.info(f"All sessions deactivated for user {user_id}")
    
    logout_user()
    session.clear()
    flash("You have been logged out successfully.", "info")
    response = make_response(redirect(url_for('landing')))
    # Delete the remember me cookie
    response.set_cookie('remember_token', '', expires=0)
    response.set_cookie('session', '', expires=0)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
