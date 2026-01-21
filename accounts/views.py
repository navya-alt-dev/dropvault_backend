# accounts/views.py

import os
import json
import logging
import requests
import secrets
import re

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Sum
from django.contrib.auth import update_session_auth_hash
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings

from rest_framework.authtoken.models import Token

from .models import UserProfile, Notification, LoginAttempt

logger = logging.getLogger(__name__)
User = get_user_model()


# =============================================================================
# HELPER: GET FRONTEND URL
# =============================================================================

def get_frontend_url():
    """Get the frontend URL from environment or use default"""
    return os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-ybkd.onrender.com')

# =============================================================================
# EMAIL VALIDATION HELPERS
# =============================================================================

def is_valid_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_disposable_email(email):
    disposable_domains = [
        'tempmail.com', 'throwaway.email', 'guerrillamail.com', 
        'mailinator.com', '10minutemail.com', 'temp-mail.org',
        'fakeinbox.com', 'trashmail.com', 'yopmail.com',
    ]
    domain = email.split('@')[1].lower() if '@' in email else ''
    return domain in disposable_domains


def validate_email_complete(email):
    if not email:
        return False, "Email is required"
    
    email = email.strip().lower()
    
    if not is_valid_email_format(email):
        return False, "Please enter a valid email address"
    
    if is_disposable_email(email):
        return False, "Disposable email addresses are not allowed"
    
    return True, None

# =============================================================================
# EMAIL SENDING FUNCTIONS
# =============================================================================
def send_verification_email(user, verification_link):
    """Send verification email using Resend API"""
    try:
        resend_api_key = os.environ.get('RESEND_API_KEY', '')
        
        if not resend_api_key:
            logger.error("❌ RESEND_API_KEY not configured!")
            return False
        
        subject = "Verify your DropVault account"
        
        html_message = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; background: #667eea; color: white !important; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 DropVault</h1>
            <p>Secure File Storage</p>
        </div>
        <div class="content">
            <h2>Hi {user.first_name or user.username}!</h2>
            <p>Welcome to DropVault! Please verify your email address to complete your registration.</p>
            
            <p style="text-align: center;">
                <a href="{verification_link}" class="button">✓ Verify My Email</a>
            </p>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #667eea; font-size: 14px;">{verification_link}</p>
            
            <p><strong>This link will expire in 24 hours.</strong></p>
            
            <p>If you didn't create an account with DropVault, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2024 DropVault. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
        
        plain_message = f"""
Hi {user.first_name or user.username},

Welcome to DropVault! Please verify your email by clicking:

{verification_link}

This link expires in 24 hours.

- DropVault Team
"""
        
        # Send via Resend API
        from_email = os.environ.get('DEFAULT_FROM_EMAIL', 'DropVault <onboarding@resend.dev>')
        
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {resend_api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': from_email,
                'to': [user.email],
                'subject': subject,
                'html': html_message,
                'text': plain_message,
            },
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            logger.info(f"✅ Verification email sent to: {user.email}")
            logger.info(f"   Resend response: {response.json()}")
            return True
        else:
            logger.error(f"❌ Resend API error: {response.status_code}")
            logger.error(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to send verification email: {e}")
        import traceback
        traceback.print_exc()
        return False

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def authenticate_request(request):
    if request.user.is_authenticated:
        return request.user
    
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            token = Token.objects.get(key=token_key)
            return token.user
        except Token.DoesNotExist:
            pass
    
    return None


def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"

# =============================================================================
# WEB VIEWS
# =============================================================================

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'signup.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'login.html')


@login_required
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')
    return render(request, 'logout_confirm.html')


@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


def verify_email(request, token):
    """Verify email from link (web view)"""
    try:
        profile = UserProfile.objects.get(verification_token=token)
        
        if profile.is_verification_token_valid(token):
            profile.email_verified = True
            profile.clear_verification_token()
            
            messages.success(request, "Email verified successfully!")
            login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('dashboard')
        else:
            messages.error(request, "Verification link has expired.")
            return redirect('home')
            
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid verification link.")
        return redirect('home')


@login_required
def verify_email_prompt(request):
    return render(request, 'verify_prompt.html')


@login_required
def upload_test(request):
    return render(request, 'upload_test.html')

# =============================================================================
# API: SIGNUP - WITH EMAIL VERIFICATION REQUIRED
# =============================================================================

@csrf_exempt
def api_signup(request):
    """User signup with email verification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        logger.info("=" * 60)
        logger.info(f"📝 SIGNUP REQUEST: {email}")
        
        # Validate email
        is_valid, error = validate_email_complete(email)
        if not is_valid:
            logger.warning(f"   ❌ Invalid email: {error}")
            return JsonResponse({'success': False, 'error': error}, status=400)
        
        # Validate password
        if not password or len(password) < 8:
            return JsonResponse({
                'success': False, 
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            existing = User.objects.get(email=email)
            
            try:
                profile = existing.profile
                if not profile.email_verified:
                    # Resend verification email
                    verification_token = profile.generate_verification_token()
                    verification_link = f"{get_frontend_url()}/verify-email?token={verification_token}"
                    send_verification_email(existing, verification_link)
                    
                    logger.info(f"   📧 Resent verification: {email}")
                    return JsonResponse({
                        'success': True,
                        'requires_verification': True,
                        'message': 'Verification email sent. Please check your inbox.',
                        'email': email
                    })
            except UserProfile.DoesNotExist:
                pass
            
            if not existing.has_usable_password():
                existing.set_password(password)
                existing.save()
                
                login(request, existing, backend='django.contrib.auth.backends.ModelBackend')
                token, _ = Token.objects.get_or_create(user=existing)
                
                return JsonResponse({
                    'success': True,
                    'token': token.key,
                    'sessionid': request.session.session_key,
                    'user': {
                        'id': existing.id,
                        'email': existing.email,
                        'username': existing.username,
                        'name': f"{existing.first_name} {existing.last_name}".strip() or existing.username,
                        'email_verified': True,
                    }
                })
            
            return JsonResponse({
                'success': False, 
                'error': 'An account with this email already exists. Please login.'
            }, status=400)
        
        # Create username
        username = email.split('@')[0]
        counter = 1
        base = username
        while User.objects.filter(username=username).exists():
            username = f"{base}{counter}"
            counter += 1
        
        parts = name.split() if name else [username]
        first = parts[0] if parts else ''
        last = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        # Create user
        with transaction.atomic():
            user = User(
                username=username,
                email=email,
                first_name=first,
                last_name=last,
                is_active=True
            )
            user.set_password(password)
            user.save()
            
            if not check_password(password, user.password):
                user.delete()
                return JsonResponse({'success': False, 'error': 'Signup failed'}, status=500)
            
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.signup_method = 'email'
            profile.email_verified = False
            profile.save()
        
        # Send verification email
        verification_token = profile.generate_verification_token()
        verification_link = f"{get_frontend_url()}/verify-email?token={verification_token}"
        
        logger.info(f"   🔗 Verification link: {verification_link}")
        
        email_sent = send_verification_email(user, verification_link)
        
        logger.info(f"✅ SIGNUP SUCCESS: {email}, email_sent={email_sent}")
        logger.info("=" * 60)
        
        return JsonResponse({
            'success': True,
            'requires_verification': True,
            'message': 'Account created! Please check your email to verify.',
            'email': email,
            'email_sent': email_sent
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Signup failed'}, status=500)


# =============================================================================
# API: VERIFY EMAIL TOKEN
# =============================================================================

@csrf_exempt
def api_verify_email_token(request):
    """Verify email using token from link"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        try:
            data = json.loads(request.body)
            token = data.get('token', '')
        except:
            pass
    
    if not token:
        return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
    
    logger.info(f"🔑 Verifying token: {token[:20]}...")
    
    try:
        profile = UserProfile.objects.get(verification_token=token)
        user = profile.user
        
        if profile.email_verified:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            return JsonResponse({
                'success': True,
                'message': 'Email already verified!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        
        if profile.is_verification_token_valid(token):
            profile.email_verified = True
            profile.clear_verification_token()
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            auth_token, _ = Token.objects.get_or_create(user=user)
            
            Notification.create_notification(
                user=user,
                notification_type='EMAIL_VERIFIED',
                title='Welcome to DropVault!',
                message='Your email has been verified successfully.'
            )
            
            logger.info(f"✅ Email verified: {user.email}")
            
            return JsonResponse({
                'success': True,
                'message': 'Email verified successfully!',
                'token': auth_token.key,
                'sessionid': request.session.session_key,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email_verified': True,
                }
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Verification link has expired.',
                'expired': True,
                'email': user.email
            }, status=400)
            
    except UserProfile.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Invalid verification link'}, status=400)


# =============================================================================
# API: RESEND VERIFICATION EMAIL
# =============================================================================

@csrf_exempt
def api_resend_verification(request):
    """Resend verification email"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email required'}, status=400)
        
        logger.info(f"📧 Resend verification: {email}")
        
        try:
            user = User.objects.get(email=email)
            profile = user.profile
            
            if profile.email_verified:
                return JsonResponse({
                    'success': False, 
                    'error': 'Email already verified. Please login.'
                }, status=400)
            
            # Rate limit: 1 minute
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 60:
                    wait = int(60 - time_since.total_seconds())
                    return JsonResponse({
                        'success': False,
                        'error': f'Please wait {wait} seconds'
                    }, status=429)
            
            verification_token = profile.generate_verification_token()
            verification_link = f"{get_frontend_url()}/verify-email?token={verification_token}"
            
            if send_verification_email(user, verification_link):
                return JsonResponse({'success': True, 'message': 'Email sent!'})
            else:
                return JsonResponse({'success': False, 'error': 'Failed to send email'}, status=500)
                
        except User.DoesNotExist:
            return JsonResponse({'success': True, 'message': 'If account exists, email will be sent.'})
        except UserProfile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Account error'}, status=500)
            
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return JsonResponse({'success': False, 'error': 'Failed'}, status=500)


# =============================================================================
# API: LOGIN - WITH EMAIL VERIFICATION CHECK
# =============================================================================

@csrf_exempt
def api_login(request):
    """User login with email verification check"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        logger.info("=" * 60)
        logger.info(f"🔐 LOGIN ATTEMPT: {email}")
        
        if not email or not is_valid_email_format(email):
            return JsonResponse({'success': False, 'error': 'Valid email required'}, status=400)
        
        if not password:
            return JsonResponse({'success': False, 'error': 'Password required'}, status=400)
        
        # Find user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"   ❌ User not found: {email}")
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        if not user.is_active:
            return JsonResponse({'success': False, 'error': 'Account disabled'}, status=403)
        
        if not user.has_usable_password():
            return JsonResponse({
                'success': False, 
                'error': 'Please use Google login for this account.'
            }, status=400)
        
        if not check_password(password, user.password):
            logger.warning(f"   ❌ Wrong password: {email}")
            return JsonResponse({'success': False, 'error': 'Invalid email or password'}, status=401)
        
        # Check email verification
        try:
            profile = user.profile
            email_verified = profile.email_verified
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=user, email_verified=False)
            email_verified = False
        
        if not email_verified:
            logger.warning(f"   ⚠️ Email not verified: {email}")
            
            # Auto-resend if not sent recently
            should_resend = True
            if profile.verification_sent_at:
                time_since = timezone.now() - profile.verification_sent_at
                if time_since.total_seconds() < 300:
                    should_resend = False
            
            if should_resend:
                verification_token = profile.generate_verification_token()
                verification_link = f"{get_frontend_url()}/verify-email?token={verification_token}"
                send_verification_email(user, verification_link)
            
            return JsonResponse({
                'success': False,
                'error': 'Please verify your email first. Check your inbox.',
                'requires_verification': True,
                'email': email,
                'email_sent': should_resend
            }, status=403)
        
        # Login success!
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ LOGIN SUCCESS: {email}")
        logger.info("=" * 60)
        
        return JsonResponse({
            'success': True,
            'message': 'Login successful',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': True,
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
    except Exception as e:
        logger.error(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Login failed'}, status=500)


# =============================================================================
# API: GOOGLE OAUTH - EMAIL IS VERIFIED BY GOOGLE
# =============================================================================

@csrf_exempt
def api_google_login(request):
    """Google OAuth login - Google verifies the email"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        code = data.get('code')
        
        if not code:
            return JsonResponse({'success': False, 'error': 'Authorization code required'}, status=400)
        
        client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        
        if not client_id or not client_secret:
            logger.error("❌ Google OAuth not configured - missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET")
            return JsonResponse({'success': False, 'error': 'Google OAuth not configured on server'}, status=501)
        
        # Determine redirect URI based on origin
        origin = request.META.get('HTTP_ORIGIN', '')
        if 'localhost' in origin or '127.0.0.1' in origin:
            redirect_uri = 'http://localhost:3000/google-callback'
        else:
            redirect_uri = f"{get_frontend_url()}/google-callback"
        
        logger.info(f"🔐 Google OAuth - exchanging code with redirect: {redirect_uri}")
        
        # Exchange code for token
        token_response = requests.post('https://oauth2.googleapis.com/token', data={
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }, timeout=15)
        
        if token_response.status_code != 200:
            logger.error(f"❌ Google token exchange failed: {token_response.text}")
            return JsonResponse({
                'success': False, 
                'error': 'Failed to exchange authorization code'
            }, status=401)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            logger.error("❌ No access token in Google response")
            return JsonResponse({'success': False, 'error': 'No access token received'}, status=401)
        
        # Get user info from Google
        user_info_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if user_info_response.status_code != 200:
            logger.error(f"❌ Failed to get user info from Google: {user_info_response.text}")
            return JsonResponse({'success': False, 'error': 'Failed to get user info from Google'}, status=401)
        
        google_data = user_info_response.json()
        email = google_data.get('email', '').lower().strip()
        name = google_data.get('name', '')
        first_name = google_data.get('given_name', '')
        last_name = google_data.get('family_name', '')
        
        if not email:
            return JsonResponse({'success': False, 'error': 'No email received from Google'}, status=400)
        
        logger.info(f"🔐 Google user info: {email}")
        
        # Find or create user
        created = False
        try:
            user = User.objects.get(email=email)
            logger.info(f"   Found existing user: {email}")
        except User.DoesNotExist:
            # Create new user
            username = email.split('@')[0]
            counter = 1
            base_username = username
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name or (name.split()[0] if name else ''),
                last_name=last_name or (' '.join(name.split()[1:]) if name and len(name.split()) > 1 else ''),
                is_active=True
            )
            # Google users don't have passwords - this is correct!
            user.set_unusable_password()
            user.save()
            created = True
            logger.info(f"   Created new user: {email}")
        
        # Update/Create profile - Google verifies email automatically
        profile, profile_created = UserProfile.objects.get_or_create(user=user)
        profile.email_verified = True  # ✅ Google verified the email
        profile.signup_method = 'google'  # ✅ Mark as Google user
        profile.save()
        
        logger.info(f"   Profile updated: email_verified=True, signup_method=google")
        
        # Login the user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        # Create/get auth token
        token, _ = Token.objects.get_or_create(user=user)
        
        logger.info(f"✅ Google login SUCCESS: {email} (new_user={created})")
        
        return JsonResponse({
            'success': True,
            'message': 'Google login successful',
            'token': token.key,
            'sessionid': request.session.session_key,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'has_password': False,  # Google users don't have passwords
                'email_verified': True,
                'is_google_user': True,
                'signup_method': 'google',
            },
            'is_new_user': created
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request data'}, status=400)
    except Exception as e:
        logger.error(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': 'Google authentication failed'}, status=500)


# =============================================================================
# API: LOGOUT
# =============================================================================

@csrf_exempt
def api_logout(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        Token.objects.filter(user=user).delete()
    logout(request)
    return JsonResponse({'success': True, 'message': 'Logged out successfully'})


# =============================================================================
# API: CHECK AUTH - FIXED TO INCLUDE SIGNUP METHOD
# =============================================================================

@csrf_exempt
def api_check_auth(request):
    """Check if user is authenticated - includes Google user info"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if user:
        try:
            profile = user.profile
            email_verified = profile.email_verified
            signup_method = profile.signup_method
        except:
            email_verified = False
            signup_method = 'email'
        
        # ✅ Include signup_method and is_google_user in response
        is_google_user = signup_method == 'google'
        
        return JsonResponse({
            'authenticated': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'email_verified': email_verified,
                'has_password': user.has_usable_password(),
                'is_google_user': is_google_user,
                'signup_method': signup_method,
            }
        })
    
    return JsonResponse({'authenticated': False})


# =============================================================================
# API: DASHBOARD - WITH EMAIL VERIFICATION CHECK
# =============================================================================


@csrf_exempt
def api_dashboard(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File, SharedLink
        
        total_files = File.objects.filter(user=user, deleted=False).count()
        total_trash = File.objects.filter(user=user, deleted=True).count()
        shared_links = SharedLink.objects.filter(owner=user, is_active=True)
        shared_count = sum(1 for link in shared_links if not link.is_expired())
        total_storage = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        recent_files = File.objects.filter(user=user, deleted=False).order_by('-uploaded_at')[:5]
        recent_data = [{'id': f.id, 'name': f.original_name, 'size': f.size} for f in recent_files]
        
        return JsonResponse({
            'success': True,
            'data': {
                'storageUsed': total_storage,
                'storageTotal': 10737418240,
                'totalFiles': total_files,
                'trashFiles': total_trash,
                'sharedFiles': shared_count,
                'recentFiles': recent_data,
            },
            'user': {
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}".strip() or user.username,
            }
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# =============================================================================
# API: NOTIFICATIONS
# =============================================================================

@csrf_exempt
def api_notifications(request):
    """Get all visible notifications for the user"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        Notification.cleanup_old_notifications(user)
        notifications = Notification.get_visible_notifications(user)
        
        notification_list = []
        unread_count = 0
        
        for notif in notifications:
            notification_list.append({
                'id': notif.id,
                'type': notif.notification_type,
                'title': notif.title,
                'message': notif.message,
                'file_name': notif.file_name,
                'file_id': notif.file_id,
                'is_read': notif.is_read,
                'created_at': notif.created_at.isoformat(),
                'read_at': notif.read_at.isoformat() if notif.read_at else None,
            })
            
            if not notif.is_read:
                unread_count += 1
        
        return JsonResponse({
            'success': True,
            'notifications': notification_list,
            'unread_count': unread_count,
            'total_count': len(notification_list)
        })
        
    except Exception as e:
        logger.error(f"Notification error: {e}")
        return JsonResponse({
            'success': True,
            'notifications': [],
            'unread_count': 0,
            'total_count': 0
        })


@csrf_exempt
def api_notification_read(request, notification_id):
    """Mark a single notification as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        notification = Notification.objects.get(id=notification_id, user=user)
        notification.mark_as_read()
        return JsonResponse({'success': True})
    except Notification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notifications_read_all(request):
    """Mark all notifications as read"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        updated = Notification.objects.filter(
            user=user,
            is_read=False
        ).update(
            is_read=True,
            read_at=timezone.now()
        )
        return JsonResponse({'success': True, 'count': updated})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_notification_delete(request, notification_id):
    """Delete a notification"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        Notification.objects.filter(id=notification_id, user=user).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# API: USER PROFILE & STORAGE
# =============================================================================

@csrf_exempt
def api_user_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'data': {
            'id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'has_password': user.has_usable_password(),
        }
    })

@csrf_exempt
def api_user_storage(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        from files.models import File
        total = File.objects.filter(user=user, deleted=False).aggregate(total=Sum('size'))['total'] or 0
        count = File.objects.filter(user=user, deleted=False).count()
        limit = 10 * 1024 * 1024 * 1024
        
        return JsonResponse({
            'success': True,
            'storage': {
                'used': total,
                'used_formatted': format_file_size(total),
                'limit': limit,
                'percentage': round((total / limit) * 100, 2),
                'file_count': count,
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# =============================================================================
# API: PASSWORD MANAGEMENT
# =============================================================================

@csrf_exempt
def api_set_password(request):
    """Allow OAuth users to set a password"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        data = json.loads(request.body)
        new_password = data.get('password', '')
        confirm_password = data.get('confirm_password', new_password)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({
                'success': False,
                'error': 'Passwords do not match'
            }, status=400)
        
        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        
        return JsonResponse({
            'success': True,
            'message': 'Password set successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_forgot_password(request):
    """Request password reset"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        
        if not email:
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)
        
        try:
            user = User.objects.get(email=email)
            
            reset_token = secrets.token_urlsafe(32)
            cache_key = f'password_reset:{reset_token}'
            cache.set(cache_key, {'user_id': user.id, 'email': email}, timeout=3600)
            
            frontend_url = os.environ.get('FRONTEND_URL', 'https://dropvault-frontend-1.onrender.com')
            reset_link = f"{frontend_url}/reset-password?token={reset_token}"
            
            # TODO: Send reset email
            logger.info(f"Password reset link for {email}: {reset_link}")
            
        except User.DoesNotExist:
            pass
        
        return JsonResponse({
            'success': True,
            'message': 'If an account exists, a reset link has been sent.'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': 'Request failed'}, status=500)


@csrf_exempt
def api_reset_password(request):
    """Reset password with token"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        new_password = data.get('password', '')
        
        if not token:
            return JsonResponse({'success': False, 'error': 'Token required'}, status=400)
        
        if not new_password or len(new_password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }, status=400)
        
        cache_key = f'password_reset:{token}'
        reset_data = cache.get(cache_key)
        
        if not reset_data:
            return JsonResponse({
                'success': False,
                'error': 'Invalid or expired reset link'
            }, status=400)
        
        try:
            user = User.objects.get(id=reset_data['user_id'])
            user.set_password(new_password)
            user.save()
            
            cache.delete(cache_key)
            Token.objects.filter(user=user).delete()
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully! Please login.'
            })
            
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_request_password_reset(request):
    return api_forgot_password(request)


@csrf_exempt
def api_verify_reset_token(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    token = request.GET.get('token', '')
    if not token:
        return JsonResponse({'valid': False}, status=400)
    
    cache_key = f'password_reset:{token}'
    reset_data = cache.get(cache_key)
    
    return JsonResponse({'valid': bool(reset_data)})


@csrf_exempt
def api_check_user_password_status(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    return JsonResponse({
        'success': True,
        'has_password': user.has_usable_password(),
        'email': user.email
    })


# =============================================================================
# API: ADMIN/DEBUG ENDPOINTS
# =============================================================================

@csrf_exempt
def api_debug_user(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    email = request.GET.get('email', '').strip().lower()
    if not email:
        return JsonResponse({'error': 'Email required'}, status=400)
    
    try:
        user = User.objects.get(email=email)
        try:
            profile = user.profile
            email_verified = profile.email_verified
        except:
            email_verified = False
        
        return JsonResponse({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'has_password': user.has_usable_password(),
                'is_active': user.is_active,
                'email_verified': email_verified,
            }
        })
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


@csrf_exempt
def api_debug_list_users(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    users = User.objects.all().order_by('id')
    user_list = []
    
    for u in users:
        try:
            email_verified = u.profile.email_verified
        except:
            email_verified = False
        
        user_list.append({
            'id': u.id,
            'email': u.email,
            'username': u.username,
            'has_password': u.has_usable_password(),
            'is_active': u.is_active,
            'email_verified': email_verified,
        })
    
    return JsonResponse({
        'success': True,
        'count': len(user_list),
        'users': user_list
    })


@csrf_exempt
def api_debug_fix_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        new_password = data.get('new_password', '')
        
        if not email or not new_password:
            return JsonResponse({'success': False, 'error': 'Email and new_password required'}, status=400)
        
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        
        verified = check_password(new_password, user.password)
        Token.objects.filter(user=user).delete()
        
        return JsonResponse({
            'success': True,
            'email': email,
            'password_verified': verified
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def api_admin_delete_all_users(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    if request.method != "POST":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        admin_key = data.get('admin_key', '')
        confirm = data.get('confirm', False)
        
        expected_key = os.environ.get('ADMIN_FIX_KEY', 'dropvault-admin-fix-2024')
        if admin_key != expected_key:
            return JsonResponse({'success': False, 'error': 'Invalid admin key'}, status=403)
        
        users = User.objects.filter(is_superuser=False)
        
        if not confirm:
            return JsonResponse({
                'success': False,
                'message': 'Add "confirm": true to delete',
                'would_delete': users.count()
            })
        
        count = users.count()
        
        from files.models import File, SharedLink
        user_ids = list(users.values_list('id', flat=True))
        
        Token.objects.filter(user_id__in=user_ids).delete()
        File.objects.filter(user_id__in=user_ids).delete()
        SharedLink.objects.filter(owner_id__in=user_ids).delete()
        UserProfile.objects.filter(user_id__in=user_ids).delete()
        Notification.objects.filter(user_id__in=user_ids).delete()
        
        users.delete()
        
        return JsonResponse({'success': True, 'deleted_count': count})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# =============================================================================
# STUB ENDPOINTS
# =============================================================================

@csrf_exempt
def api_verify_email(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    return JsonResponse({'success': True})


@csrf_exempt
def api_update_profile(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True})


@csrf_exempt
def api_change_password(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True})


@csrf_exempt
def api_preferences(request):
    if request.method == "OPTIONS":
        return JsonResponse({})
    user = authenticate_request(request)
    if not user:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    return JsonResponse({'success': True, 'data': {}})


def test_email(request):
    return HttpResponse("OK")


# MFA endpoints
@login_required
def setup_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    device, _ = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False, defaults={'name': 'Auth'})
    if request.method == 'POST' and device.verify_token(request.POST.get('token', '')):
        device.confirmed = True
        device.save()
        return redirect('dashboard')
    return render(request, 'setup_mfa.html', {'device': device})


@login_required
def otp_verify(request):
    from django_otp import match_token
    if request.method == 'POST' and match_token(request.user, request.POST.get('otp', '')):
        return redirect('dashboard')
    return render(request, 'otp_verify.html')


@login_required
def disable_mfa(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        return redirect('dashboard')
    return render(request, 'disable_mfa.html')


@csrf_exempt
def api_test_email(request):
    """Test email sending"""
    if request.method == "OPTIONS":
        return JsonResponse({})
    
    import os
    resend_api_key = os.environ.get('RESEND_API_KEY', '')
    
    if not resend_api_key:
        return JsonResponse({
            'success': False,
            'error': 'RESEND_API_KEY not configured',
            'env_vars': {
                'RESEND_API_KEY': 'NOT SET' if not resend_api_key else 'SET (hidden)',
                'FRONTEND_URL': os.environ.get('FRONTEND_URL', 'NOT SET'),
            }
        })
    
    # Try sending a test email
    try:
        import requests
        
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {resend_api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'from': 'DropVault <onboarding@resend.dev>',
                'to': ['delivered@resend.dev'],  # Resend test email
                'subject': 'DropVault Email Test',
                'html': '<p>This is a test email from DropVault</p>',
            },
            timeout=10
        )
        
        return JsonResponse({
            'success': response.status_code in [200, 201],
            'status_code': response.status_code,
            'response': response.json() if response.status_code in [200, 201] else response.text,
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })