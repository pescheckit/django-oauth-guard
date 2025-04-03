import logging
import time
import random
import json
import urllib.request
import urllib.error
import base64
import hmac
import hashlib
import importlib
import inspect
from datetime import datetime, timedelta
from django.utils import timezone

from django.contrib.auth import logout
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.module_loading import import_string
from allauth.socialaccount.models import SocialAccount, SocialToken
from allauth.account.utils import get_next_redirect_url

# Import signals
from django_oauth_guard.signals import (
    token_validation_failed, token_refreshed, 
    session_fingerprint_mismatch, session_age_exceeded,
    user_inactivity_timeout, token_expired, validation_system_error
)

logger = logging.getLogger(__name__)

class OAuthValidationMiddleware:
    """
    Enhanced middleware for OAuth session validation and security.
    
    This middleware implements multiple security measures:
    1. Token validation - Verifies OAuth tokens are still valid with providers
    2. Session fingerprinting - Detects session hijacking attempts
    3. Activity tracking - Forces re-authentication for inactive users
    4. Token expiry monitoring - Handles token refreshing or session termination
    5. Provider-specific validation - Customized for each OAuth provider
    
    This addresses security issues where:
    - Users revoke application access via OAuth providers but remain logged in
    - Sessions might be hijacked or used across different devices/browsers
    - Inactive sessions remain valid indefinitely
    """
    
    # How often to validate tokens (percentage of requests)
    VALIDATION_PROBABILITY = 0.05  # 5% of requests
    
    # How long to wait between validations for the same user
    VALIDATION_INTERVAL = 600  # 10 minutes
    
    # Inactivity threshold before requiring re-authentication
    MAX_INACTIVITY = 86400  # 24 hours (in seconds)
    
    # Maximum session age regardless of activity
    MAX_SESSION_AGE = 604800  # 7 days (in seconds)
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Store last validation time per user
        self.validation_timestamps = {}
        # Store session fingerprints for comparison
        self.session_fingerprints = {}
        # Provider-specific validation methods
        self.provider_validators = {
            'google': self._validate_google_token,
            'facebook': self._validate_facebook_token,
            'microsoft': self._validate_microsoft_token,
            'github': self._validate_github_token,
            'linkedin_oauth2': self._validate_linkedin_token,  # Updated to match new provider name
        }
        # Provider-specific token refresh methods
        self.provider_refreshers = {
            'google': self._refresh_google_token,
            'facebook': self._refresh_facebook_token,
            'microsoft': self._refresh_microsoft_token,
            'github': self._refresh_github_token,
            'linkedin_oauth2': self._refresh_linkedin_token,  # Updated to match new provider name
        }
        # Load additional providers from settings
        self._load_additional_providers()
        # Apply configuration from settings if available
        self._apply_settings()
        # Load custom failure handlers
        self._load_failure_handlers()

    def _load_additional_providers(self):
        """Load additional OAuth providers from settings"""
        additional_providers = getattr(settings, 'OAUTH_SESSION_VALIDATOR_PROVIDERS', {})
        
        for provider_id, provider_config in additional_providers.items():
            if 'validator' in provider_config:
                try:
                    validator_func = import_string(provider_config['validator'])
                    self.provider_validators[provider_id] = validator_func
                except (ImportError, AttributeError) as e:
                    logger.warning(f"Could not load validator for provider {provider_id}: {e}")
            
            if 'refresher' in provider_config:
                try:
                    refresher_func = import_string(provider_config['refresher'])
                    self.provider_refreshers[provider_id] = refresher_func
                except (ImportError, AttributeError) as e:
                    logger.warning(f"Could not load refresher for provider {provider_id}: {e}")

    def _apply_settings(self):
        """Apply configuration from Django settings if available"""
        config = getattr(settings, 'OAUTH_SESSION_VALIDATOR', {})
        
        self.VALIDATION_PROBABILITY = config.get('VALIDATION_PROBABILITY', self.VALIDATION_PROBABILITY)
        self.VALIDATION_INTERVAL = config.get('VALIDATION_INTERVAL', self.VALIDATION_INTERVAL)
        self.MAX_INACTIVITY = config.get('MAX_INACTIVITY', self.MAX_INACTIVITY)
        self.MAX_SESSION_AGE = config.get('MAX_SESSION_AGE', self.MAX_SESSION_AGE)
        self.SENSITIVE_PATHS = config.get('SENSITIVE_PATHS', [
            '/password/change/',
            '/settings/',
            '/payment/',
            '/admin/',
            '/delete/',
            '/email/change/',
        ])
        self.FINGERPRINT_SIMILARITY_THRESHOLD = config.get('FINGERPRINT_SIMILARITY_THRESHOLD', 0.9)
        
        # Enhanced fingerprinting settings
        self.FINGERPRINT_COMPONENTS = config.get('FINGERPRINT_COMPONENTS', [
            'HTTP_USER_AGENT',
            'REMOTE_ADDR',
            'HTTP_ACCEPT_LANGUAGE',
        ])
        
        self.FINGERPRINT_IP_MASK = config.get('FINGERPRINT_IP_MASK', 24)  # Default to /24 subnet mask
        self.FINGERPRINT_USE_GEOLOCATION = config.get('FINGERPRINT_USE_GEOLOCATION', False)  # Off by default
        self.FINGERPRINT_HASH_ALGORITHM = config.get('FINGERPRINT_HASH_ALGORITHM', 'sha256')
        
        # Token refresh settings
        self.REFRESH_TOKEN_ENABLED = config.get('REFRESH_TOKEN_ENABLED', True)
        self.REFRESH_TOKEN_BEFORE_EXPIRY = config.get('REFRESH_TOKEN_BEFORE_EXPIRY', 300)  # 5 minutes

    def _load_failure_handlers(self):
        """Load custom failure handlers from settings"""
        self.failure_handlers = {}
        handlers_config = getattr(settings, 'OAUTH_SESSION_VALIDATOR_HANDLERS', {})
        
        for failure_type, handler_path in handlers_config.items():
            try:
                handler = import_string(handler_path)
                if callable(handler):
                    self.failure_handlers[failure_type] = handler
                else:
                    logger.warning(f"Failure handler for {failure_type} is not callable")
            except (ImportError, AttributeError) as e:
                logger.warning(f"Could not load failure handler for {failure_type}: {e}")

    def __call__(self, request):
        """Process the request and apply security validations"""
        if self._should_perform_security_checks(request):
            # Create a combined security check that runs multiple validations
            security_check_result = self._perform_security_checks(request)
            
            if not security_check_result['valid']:
                # Security check failed, handle based on reason
                response = self._handle_security_failure(request, security_check_result)
                if response:
                    return response
        
        # Update last activity timestamp if user is authenticated
        self._update_activity_timestamp(request)
        
        # Continue with the request
        response = self.get_response(request)
        return response
    
    def _should_perform_security_checks(self, request):
        """
        Determine if we should run security checks on this request.
        Uses a combination of time-based throttling and random sampling.
        """
        # Skip if user isn't authenticated
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return False
        
        # Skip if user doesn't have social accounts
        has_social = hasattr(request.user, 'socialaccount_set') and request.user.socialaccount_set.exists()
        if not has_social:
            return False
        
        # Always check on sensitive actions
        if self._is_sensitive_action(request):
            return True
        
        user_id = str(request.user.id)
        current_time = time.time()
        
        # Check if we've validated recently
        if user_id in self.validation_timestamps:
            last_validation = self.validation_timestamps[user_id]
            if current_time - last_validation < self.VALIDATION_INTERVAL:
                return False
        
        # Random sampling to distribute load
        return random.random() < self.VALIDATION_PROBABILITY
    
    def _is_sensitive_action(self, request):
        """Check if the current request is for a sensitive action requiring validation"""
        return any(path in request.path for path in self.SENSITIVE_PATHS)
    
    def _perform_security_checks(self, request):
        """
        Run comprehensive security checks on the session.
        Returns a dict with validation results and reason for failure.
        """
        result = {
            'valid': True,
            'reason': None,
            'provider': None,
            'details': {},
        }
        
        user = request.user
        
        try:
            # 1. Check session age
            if not self._validate_session_age(request):
                result['valid'] = False
                result['reason'] = 'session_age_exceeded'
                # Send signal
                session_age_exceeded.send(
                    sender=self.__class__,
                    request=request,
                    user=user
                )
                return result
            
            # 2. Check user inactivity
            if not self._validate_user_activity(request):
                result['valid'] = False
                result['reason'] = 'inactivity_timeout'
                # Send signal
                user_inactivity_timeout.send(
                    sender=self.__class__,
                    request=request,
                    user=user
                )
                return result
            
            # 3. Check session fingerprint (detect hijacking)
            fingerprint_result = self._validate_session_fingerprint(request)
            if not fingerprint_result['valid']:
                result['valid'] = False
                result['reason'] = 'session_mismatch'
                result['details']['similarity'] = fingerprint_result.get('similarity')
                result['details']['threshold'] = fingerprint_result.get('threshold')
                # Send signal
                session_fingerprint_mismatch.send(
                    sender=self.__class__,
                    request=request,
                    user=user,
                    similarity=fingerprint_result.get('similarity'),
                    threshold=fingerprint_result.get('threshold')
                )
                return result
            
            # 4. Validate OAuth tokens with providers
            social_accounts = SocialAccount.objects.filter(user=user)
            
            for account in social_accounts:
                # Get the latest token for this account
                token = SocialToken.objects.filter(account=account).order_by('-expires_at').first()
                
                if not token:
                    result['valid'] = False
                    result['reason'] = 'missing_token'
                    result['provider'] = account.provider
                    return result
                
                # Check if token will expire soon and needs refreshing
                should_refresh = False
                if token.expires_at:
                    # Use Django's timezone-aware now
                    now = timezone.now()
                    seconds_until_expiry = (token.expires_at - now).total_seconds()
                    
                    if seconds_until_expiry < 0:
                        # Token has expired
                        should_refresh = True
                    elif self.REFRESH_TOKEN_ENABLED and seconds_until_expiry < self.REFRESH_TOKEN_BEFORE_EXPIRY:
                        # Token will expire soon, try to refresh proactively
                        should_refresh = True
                
                if should_refresh:
                    # Try to refresh token
                    refreshed = self._try_refresh_token(account, token)
                    if not refreshed:
                        result['valid'] = False
                        result['reason'] = 'token_expired'
                        result['provider'] = account.provider
                        # Send signal
                        token_expired.send(
                            sender=self.__class__,
                            request=request,
                            user=user,
                            account=account,
                            token=token
                        )
                        return result
                
                # Validate with provider-specific method if available
                if account.provider in self.provider_validators:
                    validator = self.provider_validators[account.provider]
                    token_valid = validator(token.token)
                    if not token_valid:
                        result['valid'] = False
                        result['reason'] = 'token_invalid'
                        result['provider'] = account.provider
                        # Send signal
                        token_validation_failed.send(
                            sender=self.__class__,
                            request=request,
                            user=user,
                            account=account,
                            token=token
                        )
                        return result
            
            # All checks passed, update the validation timestamp
            self.validation_timestamps[str(user.id)] = time.time()
            return result
            
        except Exception as e:
            logger.exception("Error in security checks: %s", str(e))
            result['valid'] = False
            result['reason'] = 'system_error'
            result['details']['error'] = str(e)
            # Send signal
            validation_system_error.send(
                sender=self.__class__,
                request=request,
                user=user,
                error=e
            )
            return result
    
    def _handle_security_failure(self, request, result):
        """Handle security check failures with appropriate responses"""
        reason = result.get('reason')
        provider = result.get('provider', 'unknown')
        
        # Check if there's a custom handler for this failure reason
        if reason in self.failure_handlers:
            custom_handler = self.failure_handlers[reason]
            try:
                return custom_handler(request, result)
            except Exception as e:
                logger.exception(f"Error in custom failure handler for {reason}: {e}")
                # Fall back to default handling
        
        # Default handling
        user = request.user
        logger.warning(
            "Session security check failed for user %s. Reason: %s, Provider: %s",
            user.email, reason, provider
        )
        
        # Different messages for different failure reasons
        if reason == 'session_age_exceeded':
            messages.warning(
                request, 
                _("Your session has exceeded the maximum allowed duration. "
                  "Please log in again for security reasons.")
            )
        elif reason == 'inactivity_timeout':
            messages.warning(
                request, 
                _("Your session has timed out due to inactivity. "
                  "Please log in again to continue.")
            )
        elif reason == 'session_mismatch':
            messages.warning(
                request, 
                _("Your session appears to be compromised or accessed from a new device. "
                  "Please log in again for security reasons.")
            )
        elif reason == 'token_invalid':
            messages.warning(
                request, 
                _("Your authorization with {provider} has been revoked or is no longer valid. "
                  "Please log in again.").format(provider=provider.title())
            )
        elif reason == 'token_expired':
            messages.warning(
                request, 
                _("Your {provider} authorization has expired. "
                  "Please log in again.").format(provider=provider.title())
            )
        else:
            messages.warning(
                request, 
                _("Your session has been terminated for security reasons. "
                  "Please log in again.")
            )
        
        # Log the user out
        logout(request)
        
        # Redirect to login page
        return HttpResponseRedirect(reverse('account_login'))
    
    def _validate_session_age(self, request):
        """Check if the session has exceeded the maximum allowed age"""
        if 'session_start_time' not in request.session:
            # Set session start time if not present
            request.session['session_start_time'] = time.time()
            return True
        
        start_time = request.session.get('session_start_time', 0)
        session_age = time.time() - start_time
        
        return session_age < self.MAX_SESSION_AGE
    
    def _validate_user_activity(self, request):
        """Check if user has been inactive for too long"""
        if 'last_activity' not in request.session:
            # Set last activity time if not present
            request.session['last_activity'] = time.time()
            return True
        
        last_activity = request.session.get('last_activity', 0)
        inactivity_time = time.time() - last_activity
        
        return inactivity_time < self.MAX_INACTIVITY
    
    def _update_activity_timestamp(self, request):
        """Update the last activity timestamp for the user"""
        if hasattr(request, 'user') and request.user.is_authenticated:
            request.session['last_activity'] = time.time()
    
    def _validate_session_fingerprint(self, request):
        """
        Validate that the session is being used from the same environment.
        This helps detect session hijacking by comparing browser/device information.
        
        Returns a dict with validation result and details.
        """
        result = {
            'valid': True,
            'similarity': 1.0,
            'threshold': self.FINGERPRINT_SIMILARITY_THRESHOLD
        }
        
        # Generate current fingerprint based on request
        current_fingerprint = self._generate_fingerprint(request)
        
        # If no fingerprint stored, store it and return valid
        if 'session_fingerprint' not in request.session:
            request.session['session_fingerprint'] = current_fingerprint
            return result
        
        # Compare with stored fingerprint
        stored_fingerprint = request.session.get('session_fingerprint')
        similarity = self._calculate_similarity(stored_fingerprint, current_fingerprint)
        
        result['similarity'] = similarity
        result['valid'] = similarity >= self.FINGERPRINT_SIMILARITY_THRESHOLD
        
        return result
    
    def _generate_fingerprint(self, request):
        """
        Generate a fingerprint of the user's environment.
        Combines user agent, IP address, and other available identifiers.
        
        Enhanced version adds more detailed fingerprinting including
        masked IP address for subnet comparison and optional geolocation.
        """
        components = []
        
        # Gather basic fingerprint components from request META
        for component_name in self.FINGERPRINT_COMPONENTS:
            component_value = request.META.get(component_name, '')
            
            # Special handling for IP address to mask subnet
            if component_name == 'REMOTE_ADDR' and component_value:
                component_value = self._mask_ip_address(component_value)
            
            if component_value:
                components.append(component_value)
        
        # Add geolocation data if enabled
        if self.FINGERPRINT_USE_GEOLOCATION:
            geo_data = self._get_geolocation_data(request.META.get('REMOTE_ADDR', ''))
            if geo_data:
                components.append(geo_data)
        
        # Add a portion of the secret key to prevent tampering
        components.append(getattr(settings, 'SECRET_KEY', '')[:10])
        
        # Add user ID if available
        if hasattr(request, 'user') and request.user.is_authenticated:
            components.append(str(request.user.id))
        
        # Combine components and create a hash
        fingerprint_base = '|'.join(filter(None, components))
        
        # Use the configured hash algorithm
        hash_func = getattr(hashlib, self.FINGERPRINT_HASH_ALGORITHM, hashlib.sha256)
        fingerprint_hash = hash_func(fingerprint_base.encode()).hexdigest()
        
        return fingerprint_hash
    
    def _mask_ip_address(self, ip_address):
        """
        Mask an IP address based on the subnet mask to allow for dynamic IPs
        within the same network while still catching major changes.
        """
        if not ip_address or '.' not in ip_address:
            return ip_address
        
        try:
            # Handle IPv4 addresses
            if ip_address.count('.') == 3:
                # Split into octets
                octets = ip_address.split('.')
                
                # Apply the subnet mask (default /24 means keep first 3 octets)
                mask_octets = min(4, self.FINGERPRINT_IP_MASK // 8)
                masked_ip = '.'.join(octets[:mask_octets]) + '.0' * (4 - mask_octets)
                return masked_ip
                
            # Basic handling for IPv6 addresses
            elif ':' in ip_address:
                return ip_address.split(':')[0] + ':'
                
            return ip_address
        except Exception:
            # In case of any error, return the original IP
            return ip_address
    
    def _get_geolocation_data(self, ip_address):
        """
        Get geolocation data for an IP address.
        This is a placeholder method; in a real implementation, you would
        use a geolocation service or database like GeoIP2.
        """
        # Placeholder for geolocation implementation
        # In a real application, you would use a geolocation database or service
        # Example with GeoIP2: return f"{geo_data.country.iso_code}|{geo_data.city.name}"
        return ""
    
    def _compare_fingerprints(self, stored, current):
        """
        Compare fingerprints with some tolerance for minor changes.
        
        This prevents logouts due to small changes in environment
        (like IP changes within the same network) while still
        catching significant changes that might indicate session hijacking.
        """
        # For full security, we can do an exact match
        # return stored == current
        
        # For better user experience with some security trade-off,
        # we can use a similarity threshold (e.g., 90% similar)
        similarity = self._calculate_similarity(stored, current)
        return similarity >= self.FINGERPRINT_SIMILARITY_THRESHOLD
    
    def _calculate_similarity(self, str1, str2):
        """Calculate similarity between two strings (0.0 to 1.0)"""
        # Simple similarity measure - ratio of matching characters
        if not str1 or not str2:
            return 0.0
            
        matches = sum(a == b for a, b in zip(str1, str2))
        return matches / max(len(str1), len(str2))
    
    def _try_refresh_token(self, account, token):
        """
        Try to refresh an expired OAuth token if the provider supports it.
        Returns True if successfully refreshed, False otherwise.
        """
        if not self.REFRESH_TOKEN_ENABLED:
            return False
            
        # Check if there's a refresh method for this provider
        provider = account.provider
        if provider not in self.provider_refreshers:
            return False
            
        try:
            # Call the provider-specific refresh method
            refresher = self.provider_refreshers[provider]
            refresh_result = refresher(account, token)
            
            if refresh_result:
                # Token was successfully refreshed
                # Send signal
                token_refreshed.send(
                    sender=self.__class__,
                    account=account,
                    old_token=token,
                    new_token=refresh_result
                )
                return True
                
            return False
        except Exception as e:
            logger.warning(f"Error refreshing token for {provider}: {e}")
            return False
            
    # Provider-specific token validation methods
    
    def _validate_google_token(self, access_token):
        """
        Validate a Google OAuth token by calling Google's tokeninfo API.
        
        This catches revoked tokens because Google's API will return an error
        for tokens that have been revoked by the user.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        # Check cache first to reduce API calls
        cache_key = f'google_token_valid_{access_token[:10]}'  # Don't cache full token for security
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            # Call Google's tokeninfo API to validate the token
            url = f'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}'
            
            # Use urllib from the standard library instead of requests
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    # If we get here, the response is 200 OK
                    is_valid = True
                    # Optionally parse the response if needed
                    # response_body = json.loads(response.read().decode('utf-8'))
            except urllib.error.HTTPError as http_err:
                # Token is invalid or has been revoked
                is_valid = False
                
                # Log specific error for revoked tokens (401 with error=invalid_token)
                if http_err.code == 401:
                    try:
                        error_data = json.loads(http_err.read().decode('utf-8'))
                        if error_data.get('error') == 'invalid_token':
                            logger.warning("Google OAuth token has been revoked or is invalid")
                    except Exception:
                        pass
            
            # Cache the result for 5 minutes to reduce API calls
            # Using a shorter TTL since token validity can change
            cache.set(cache_key, is_valid, timeout=300)
            
            return is_valid
            
        except Exception as e:
            logger.warning("Error validating Google token: %s", str(e))
            # Default to considering token valid on connection errors
            # to avoid logging users out due to temporary API issues
            return True
            
    def _validate_facebook_token(self, access_token):
        """
        Validate a Facebook OAuth token by calling Facebook's debug_token endpoint.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        # Check cache first to reduce API calls
        cache_key = f'facebook_token_valid_{access_token[:10]}'
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            # Facebook requires an app token to validate user tokens
            # In a real implementation, you would get these from settings
            app_id = getattr(settings, 'FACEBOOK_APP_ID', '')
            app_secret = getattr(settings, 'FACEBOOK_APP_SECRET', '')
            
            if not app_id or not app_secret:
                # If settings aren't available, fall back to assuming token is valid
                return True
            
            # Facebook's token validation endpoint
            url = f'https://graph.facebook.com/debug_token?input_token={access_token}&access_token={app_id}|{app_secret}'
            
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    response_data = json.loads(response.read().decode('utf-8'))
                    data = response_data.get('data', {})
                    
                    # Check if token is valid and not expired
                    is_valid = data.get('is_valid', False)
                    
                    # Cache the result
                    cache.set(cache_key, is_valid, timeout=300)
                    return is_valid
                    
            except urllib.error.HTTPError:
                # Token validation failed
                cache.set(cache_key, False, timeout=300)
                return False
                
        except Exception as e:
            logger.warning("Error validating Facebook token: %s", str(e))
            # Default to considering token valid on errors
            return True
            
    def _validate_microsoft_token(self, access_token):
        """
        Validate a Microsoft OAuth token.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        # Microsoft token validation is complex and requires understanding the specific
        # Microsoft OAuth flow being used (Azure AD v1, v2, etc.)
        # For now, we'll just check token structure and assume valid
        
        # For full implementation, you would call Microsoft's validation endpoint
        # which varies based on tenant and other factors
        
        # Placeholder implementation
        try:
            # Check if token has basic JWT structure
            parts = access_token.split('.')
            if len(parts) != 3:
                return False
                
            # In a real implementation, you would validate with Microsoft's endpoints
            # For now, assume valid if it has correct structure
            return True
            
        except Exception:
            # If we can't parse the token, assume it's invalid
            return False
            
    def _validate_github_token(self, access_token):
        """
        Validate a GitHub OAuth token by calling GitHub's API.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        cache_key = f'github_token_valid_{access_token[:10]}'
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            # GitHub API endpoint to check token
            url = 'https://api.github.com/user'
            
            request = urllib.request.Request(url)
            request.add_header('Authorization', f'token {access_token}')
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    # If we get a 200 response, the token is valid
                    is_valid = response.status == 200
                    cache.set(cache_key, is_valid, timeout=300)
                    return is_valid
                    
            except urllib.error.HTTPError:
                # Token validation failed
                cache.set(cache_key, False, timeout=300)
                return False
                
        except Exception as e:
            logger.warning("Error validating GitHub token: %s", str(e))
            # Default to considering token valid on errors
            return True
            
    def _validate_linkedin_token(self, access_token):
        """
        Validate a LinkedIn OAuth token by calling LinkedIn's API.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        cache_key = f'linkedin_token_valid_{access_token[:10]}'
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            # LinkedIn API endpoint to check token (get current user profile)
            url = 'https://api.linkedin.com/v2/me'
            
            request = urllib.request.Request(url)
            request.add_header('Authorization', f'Bearer {access_token}')
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    # If we get a 200 response, the token is valid
                    is_valid = response.status == 200
                    cache.set(cache_key, is_valid, timeout=300)
                    return is_valid
                    
            except urllib.error.HTTPError:
                # Token validation failed
                cache.set(cache_key, False, timeout=300)
                return False
                
        except Exception as e:
            logger.warning("Error validating LinkedIn token: %s", str(e))
            # Default to considering token valid on errors
            return True
    
    # Provider-specific token refresh methods
    
    def _refresh_google_token(self, account, token):
        """
        Refresh a Google OAuth token using the refresh token.
        
        Args:
            account: The SocialAccount instance
            token: The SocialToken instance to refresh
            
        Returns:
            The refreshed SocialToken instance if successful, None otherwise
        """
        # Check if we have a refresh token
        refresh_token = token.token_secret
        if not refresh_token:
            logger.warning("No refresh token available for Google account")
            return None
            
        try:
            # Get the app credentials
            app = token.app
            client_id = app.client_id
            client_secret = app.secret
            
            # Google's token endpoint
            url = 'https://oauth2.googleapis.com/token'
            
            # Prepare the request data
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            # Encode data for the request
            post_data = urllib.parse.urlencode(data).encode()
            
            # Create the request
            request = urllib.request.Request(url, data=post_data, method='POST')
            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            # Send the request
            with urllib.request.urlopen(request, timeout=10) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                # Extract the new access token and expiry
                new_token = response_data.get('access_token')
                expires_in = response_data.get('expires_in', 3600)  # Default to 1 hour
                
                if new_token:
                    # Calculate new expiry time using Django's timezone-aware now
                    new_expires_at = timezone.now() + timedelta(seconds=expires_in)
                    
                    # Update the token in the database
                    token.token = new_token
                    token.expires_at = new_expires_at
                    token.save()
                    
                    logger.info(f"Successfully refreshed Google token for user {account.user.id}")
                    return token
                else:
                    logger.warning("Google token refresh response did not contain a new token")
                    return None
                    
        except Exception as e:
            logger.exception(f"Error refreshing Google token: {e}")
            return None
    
    def _refresh_facebook_token(self, account, token):
        """
        Refresh a Facebook OAuth token.
        
        Facebook access tokens can't be refreshed in the same way as other providers.
        Long-lived tokens can be obtained, but they still eventually expire.
        
        Returns:
            None as Facebook tokens aren't refreshable in the traditional sense
        """
        # Facebook doesn't support traditional token refreshing
        # Long-lived tokens can be requested but not refreshed once expired
        return None
        
    def _refresh_microsoft_token(self, account, token):
        """
        Refresh a Microsoft OAuth token using the refresh token.
        
        Args:
            account: The SocialAccount instance
            token: The SocialToken instance to refresh
            
        Returns:
            The refreshed SocialToken instance if successful, None otherwise
        """
        # Check if we have a refresh token
        refresh_token = token.token_secret
        if not refresh_token:
            logger.warning("No refresh token available for Microsoft account")
            return None
            
        try:
            # Get the app credentials
            app = token.app
            client_id = app.client_id
            client_secret = app.secret
            
            # Microsoft's token endpoint (Azure AD v2.0)
            # Note: This URL may differ based on the specific Microsoft OAuth flow being used
            url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
            
            # Prepare the request data
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token',
                'scope': 'openid profile email'  # Adjust scopes as needed
            }
            
            # Encode data for the request
            post_data = urllib.parse.urlencode(data).encode()
            
            # Create the request
            request = urllib.request.Request(url, data=post_data, method='POST')
            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            # Send the request
            with urllib.request.urlopen(request, timeout=10) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                # Extract the new tokens
                new_token = response_data.get('access_token')
                new_refresh_token = response_data.get('refresh_token')
                expires_in = response_data.get('expires_in', 3600)  # Default to 1 hour
                
                if new_token:
                    # Calculate new expiry time using Django's timezone-aware now
                    new_expires_at = timezone.now() + timedelta(seconds=expires_in)
                    
                    # Update the token in the database
                    token.token = new_token
                    if new_refresh_token:
                        token.token_secret = new_refresh_token
                    token.expires_at = new_expires_at
                    token.save()
                    
                    logger.info(f"Successfully refreshed Microsoft token for user {account.user.id}")
                    return token
                else:
                    logger.warning("Microsoft token refresh response did not contain a new token")
                    return None
                    
        except Exception as e:
            logger.exception(f"Error refreshing Microsoft token: {e}")
            return None
    
    def _refresh_github_token(self, account, token):
        """
        GitHub does not support refreshing OAuth tokens.
        
        Returns:
            None as GitHub tokens aren't refreshable
        """
        # GitHub doesn't support token refreshing
        return None
        
    def _refresh_linkedin_token(self, account, token):
        """
        Refresh a LinkedIn OAuth token using the refresh token.
        
        Args:
            account: The SocialAccount instance
            token: The SocialToken instance to refresh
            
        Returns:
            The refreshed SocialToken instance if successful, None otherwise
        """
        # Check if we have a refresh token
        refresh_token = token.token_secret
        if not refresh_token:
            logger.warning("No refresh token available for LinkedIn account")
            return None
            
        try:
            # Get the app credentials
            app = token.app
            client_id = app.client_id
            client_secret = app.secret
            
            # LinkedIn's token endpoint
            url = 'https://www.linkedin.com/oauth/v2/accessToken'
            
            # Prepare the request data
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            # Encode data for the request
            post_data = urllib.parse.urlencode(data).encode()
            
            # Create the request
            request = urllib.request.Request(url, data=post_data, method='POST')
            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
            request.add_header('User-Agent', 'OAuth-Session-Validator/1.0')
            
            # Send the request
            with urllib.request.urlopen(request, timeout=10) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
                # Extract the new tokens
                new_token = response_data.get('access_token')
                new_refresh_token = response_data.get('refresh_token')
                expires_in = response_data.get('expires_in', 86400)  # Default to 1 day
                
                if new_token:
                    # Calculate new expiry time using Django's timezone-aware now
                    new_expires_at = timezone.now() + timedelta(seconds=expires_in)
                    
                    # Update the token in the database
                    token.token = new_token
                    if new_refresh_token:
                        token.token_secret = new_refresh_token
                    token.expires_at = new_expires_at
                    token.save()
                    
                    logger.info(f"Successfully refreshed LinkedIn token for user {account.user.id}")
                    return token
                else:
                    logger.warning("LinkedIn token refresh response did not contain a new token")
                    return None
                    
        except Exception as e:
            logger.exception(f"Error refreshing LinkedIn token: {e}")
            return None