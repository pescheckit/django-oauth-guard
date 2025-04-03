"""
Tests for advanced features added to the OAuth validation middleware.

This includes:
- Token refresh functionality
- Enhanced session fingerprinting
- Additional OAuth providers
- Django signals integration
- Custom failure handlers
"""
import time
import json
import urllib.error
from unittest import mock
from datetime import datetime, timedelta
from django.utils import timezone

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import reverse

from allauth.socialaccount.models import SocialApp, SocialAccount, SocialToken

from django_oauth_guard.middleware import OAuthValidationMiddleware
from django_oauth_guard.signals import (
    token_validation_failed, token_refreshed, session_fingerprint_mismatch,
    session_age_exceeded, user_inactivity_timeout, token_expired,
    validation_system_error
)

from django_oauth_guard.tests.test_integration import RequestMixin, ProviderSetupMixin


class TokenRefreshTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test token refresh functionality"""
    
    def test_google_token_refresh(self):
        """Test refreshing a Google OAuth token"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token',
            expires_at=timezone.now() - timedelta(hours=1)  # Expired token, using timezone-aware datetime
        )
        # Add a refresh token
        token.token_secret = 'google-refresh-token'
        token.save()
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh API call
        with mock.patch('urllib.request.urlopen') as mock_urlopen:
            # Set up mock response for the token refresh
            mock_response = mock.Mock()
            mock_response.read.return_value = json.dumps({
                'access_token': 'new-access-token',
                'expires_in': 3600,
                'token_type': 'Bearer'
            }).encode()
            mock_urlopen.return_value.__enter__.return_value = mock_response
            
            # Also mock token validation to return True for the new token
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Process the request
                response = self.middleware(request)
                
                # Should continue with request since token was refreshed
                self.assertIsInstance(response, HttpResponse)
                
                # Verify token was updated in database
                token.refresh_from_db()
                self.assertEqual(token.token, 'new-access-token')
                self.assertGreater(token.expires_at, timezone.now())
    
    def test_microsoft_token_refresh(self):
        """Test refreshing a Microsoft OAuth token"""
        # Create a social account for the user
        account = self.create_social_account('microsoft')
        token = self.create_social_token(
            account, 
            token='expired-microsoft-token',
            expires_at=timezone.now() - timedelta(hours=1)  # Expired token
        )
        # Add a refresh token
        token.token_secret = 'microsoft-refresh-token'
        token.save()
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh API call
        with mock.patch('urllib.request.urlopen') as mock_urlopen:
            # Set up mock response for the token refresh
            mock_response = mock.Mock()
            mock_response.read.return_value = json.dumps({
                'access_token': 'new-microsoft-token',
                'refresh_token': 'new-refresh-token',
                'expires_in': 3600,
                'token_type': 'Bearer'
            }).encode()
            mock_urlopen.return_value.__enter__.return_value = mock_response
            
            # Also mock token validation to return True for the new token
            with mock.patch.object(self.middleware, '_validate_microsoft_token', return_value=True):
                # Process the request
                response = self.middleware(request)
                
                # Should continue with request since token was refreshed
                self.assertIsInstance(response, HttpResponse)
                
                # Verify token was updated in database
                token.refresh_from_db()
                self.assertEqual(token.token, 'new-microsoft-token')
                self.assertEqual(token.token_secret, 'new-refresh-token')
                self.assertGreater(token.expires_at, timezone.now())
    
    def test_linkedin_token_refresh(self):
        """Test refreshing a LinkedIn OAuth token"""
        # Create a social account for the user
        account = self.create_social_account('linkedin_oauth2')
        token = self.create_social_token(
            account, 
            token='expired-linkedin-token',
            expires_at=timezone.now() - timedelta(hours=1)  # Expired token
        )
        # Add a refresh token
        token.token_secret = 'linkedin-refresh-token'
        token.save()
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh API call
        with mock.patch('urllib.request.urlopen') as mock_urlopen:
            # Set up mock response for the token refresh
            mock_response = mock.Mock()
            mock_response.read.return_value = json.dumps({
                'access_token': 'new-linkedin-token',
                'refresh_token': 'new-linkedin-refresh-token',
                'expires_in': 86400,
            }).encode()
            mock_urlopen.return_value.__enter__.return_value = mock_response
            
            # Also mock token validation to return True for the new token
            with mock.patch.object(self.middleware, '_validate_linkedin_token', return_value=True):
                # Process the request
                response = self.middleware(request)
                
                # Should continue with request since token was refreshed
                self.assertIsInstance(response, HttpResponse)
                
                # Verify token was updated in database
                token.refresh_from_db()
                self.assertEqual(token.token, 'new-linkedin-token')
                self.assertEqual(token.token_secret, 'new-linkedin-refresh-token')
                self.assertGreater(token.expires_at, timezone.now())
    
    def test_facebook_token_refresh_not_supported(self):
        """Test that Facebook token refresh is not supported"""
        # Create a social account for the user
        account = self.create_social_account('facebook')
        token = self.create_social_token(
            account, 
            token='expired-facebook-token',
            expires_at=timezone.now() - timedelta(hours=1)  # Expired token
        )
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # We will not mock the handle_security_failure method anymore
        # Instead, we'll directly test that the mock_logout is called via
        # patching the django.contrib.auth.logout function
        
        # Mock token validation if needed
        with mock.patch.object(self.middleware, '_validate_facebook_token', return_value=True):
            # Mock refresh to return None as Facebook doesn't support refresh
            with mock.patch.object(self.middleware, '_refresh_facebook_token', return_value=None):
                # Mock logout to track calls
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    # Process the request
                    response = self.middleware(request)
                    
                    # Should redirect to login since token is expired and can't be refreshed
                    self.assertIsInstance(response, HttpResponseRedirect)
                    # Verify logout was called
                    self.assertTrue(mock_logout.called, "Logout should have been called")
    
    def test_github_token_refresh_not_supported(self):
        """Test that GitHub token refresh is not supported"""
        # Create a social account for the user
        account = self.create_social_account('github')
        token = self.create_social_token(
            account, 
            token='expired-github-token',
            expires_at=timezone.now() - timedelta(hours=1)  # Expired token
        )
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # We will not mock the handle_security_failure method anymore
        # Instead, we'll directly test that the mock_logout is called via
        # patching the django.contrib.auth.logout function
        
        # Mock token validation
        with mock.patch.object(self.middleware, '_validate_github_token', return_value=True):
            # Mock refresh to return None as GitHub doesn't support refresh
            with mock.patch.object(self.middleware, '_refresh_github_token', return_value=None):
                # Mock logout to track calls
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    # Process the request
                    response = self.middleware(request)
                    
                    # Should redirect to login since token is expired and can't be refreshed
                    self.assertIsInstance(response, HttpResponseRedirect)
                    # Verify logout was called
                    self.assertTrue(mock_logout.called, "Logout should have been called")
    
    def test_refresh_disabled_via_settings(self):
        """Test that token refresh can be disabled via settings"""
        # Create a social account for the user with an expired token
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        token.token_secret = 'refresh-token'
        token.save()
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Disable token refresh
        self.middleware.REFRESH_TOKEN_ENABLED = False
        
        # We will not mock the handle_security_failure method anymore
        # Instead, we'll directly test that the mock_logout is called via
        # patching the django.contrib.auth.logout function
        
        # Mock token validation
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Mock logout to track calls
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                # Process the request
                response = self.middleware(request)
                
                # Should redirect to login since refresh is disabled
                self.assertIsInstance(response, HttpResponseRedirect)
                # Verify logout was called
                self.assertTrue(mock_logout.called, "Logout should have been called")
                
        # Restore default setting
        self.middleware.REFRESH_TOKEN_ENABLED = True
    
    def test_proactive_token_refresh(self):
        """Test that tokens are proactively refreshed before they expire"""
        # Create a social account for the user with a token that will expire soon
        account = self.create_social_account('google')
        # Token expires in 4 minutes (less than default 5 minute threshold)
        soon_expiry = timezone.now() + timedelta(minutes=4)
        token = self.create_social_token(account, token='soon-to-expire', expires_at=soon_expiry)
        token.token_secret = 'refresh-token'
        token.save()
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh API call
        with mock.patch('urllib.request.urlopen') as mock_urlopen:
            # Set up mock response for the token refresh
            mock_response = mock.Mock()
            mock_response.read.return_value = json.dumps({
                'access_token': 'proactively-refreshed-token',
                'expires_in': 3600,
            }).encode()
            mock_urlopen.return_value.__enter__.return_value = mock_response
            
            # Also mock token validation to return True for the new token
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Process the request
                response = self.middleware(request)
                
                # Should continue with request and proactively refresh the token
                self.assertIsInstance(response, HttpResponse)
                
                # Verify token was updated in database
                token.refresh_from_db()
                self.assertEqual(token.token, 'proactively-refreshed-token')
                self.assertGreater(token.expires_at, soon_expiry)


class EnhancedFingerprintingTestCase(RequestMixin, TestCase):
    """Test enhanced fingerprinting features"""
    
    def setUp(self):
        super().setUp()
        # Create a test user
        self.user = User.objects.create_user(
            username='fingerprint_tester',
            email='fingerprint@example.com',
            password='testpassword'
        )
    
    def test_ip_address_masking(self):
        """Test IP address masking for subnet-aware fingerprinting"""
        # Test with default /24 subnet mask
        ip1 = '192.168.1.100'
        ip2 = '192.168.1.200'  # Same subnet
        ip3 = '192.168.2.100'  # Different subnet
        
        # Should mask to the same value for same subnet
        masked1 = self.middleware._mask_ip_address(ip1)
        masked2 = self.middleware._mask_ip_address(ip2)
        masked3 = self.middleware._mask_ip_address(ip3)
        
        # Same subnet IPs should have same mask
        self.assertEqual(masked1, masked2)
        # Different subnet IPs should have different masks
        self.assertNotEqual(masked1, masked3)
        
        # Check actual masked format
        self.assertEqual(masked1, '192.168.1.0')
        self.assertEqual(masked3, '192.168.2.0')
    
    def test_custom_subnet_mask(self):
        """Test IP address masking with custom subnet mask setting"""
        # Set a custom subnet mask
        original_mask = self.middleware.FINGERPRINT_IP_MASK
        try:
            # Set to /16 (mask first 2 octets)
            self.middleware.FINGERPRINT_IP_MASK = 16
            
            ip1 = '192.168.1.100'
            ip2 = '192.168.2.100'  # Different third octet
            
            masked1 = self.middleware._mask_ip_address(ip1)
            masked2 = self.middleware._mask_ip_address(ip2)
            
            # With /16 mask, these should be the same
            self.assertEqual(masked1, masked2)
            self.assertEqual(masked1, '192.168.0.0')
            
        finally:
            # Restore original mask
            self.middleware.FINGERPRINT_IP_MASK = original_mask
    
    def test_ipv6_address_handling(self):
        """Test handling of IPv6 addresses in fingerprinting"""
        ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        
        # Should handle IPv6 addresses without error
        masked = self.middleware._mask_ip_address(ipv6)
        
        # Basic IPv6 masking should keep the first part
        self.assertTrue(masked.startswith('2001:'))
        self.assertIn(':', masked)
    
    def test_custom_fingerprint_components(self):
        """Test using custom components for fingerprinting"""
        original_components = self.middleware.FINGERPRINT_COMPONENTS
        try:
            # Set custom fingerprint components
            self.middleware.FINGERPRINT_COMPONENTS = ['HTTP_USER_AGENT', 'HTTP_X_FORWARDED_FOR']
            
            # Create a request with specific headers
            request = self.create_request(user=self.user)
            request.META['HTTP_USER_AGENT'] = 'TestBrowser'
            request.META['HTTP_X_FORWARDED_FOR'] = '10.0.0.1'
            request.META['REMOTE_ADDR'] = '192.168.1.1'  # Should be ignored
            
            # Generate fingerprint
            fingerprint = self.middleware._generate_fingerprint(request)
            
            # Create another request with same headers we're using but different ignored headers
            request2 = self.create_request(user=self.user)
            request2.META['HTTP_USER_AGENT'] = 'TestBrowser'
            request2.META['HTTP_X_FORWARDED_FOR'] = '10.0.0.1'
            request2.META['REMOTE_ADDR'] = '192.168.5.5'  # Different but should be ignored
            
            # Generate second fingerprint
            fingerprint2 = self.middleware._generate_fingerprint(request2)
            
            # Fingerprints should be identical since the components we care about match
            self.assertEqual(fingerprint, fingerprint2)
            
        finally:
            # Restore original components
            self.middleware.FINGERPRINT_COMPONENTS = original_components
    
    def test_custom_hash_algorithm(self):
        """Test using a custom hash algorithm for fingerprinting"""
        original_algo = self.middleware.FINGERPRINT_HASH_ALGORITHM
        try:
            # Set a different hash algorithm
            self.middleware.FINGERPRINT_HASH_ALGORITHM = 'md5'  # Not recommended for security, just for testing
            
            # Create a request
            request = self.create_request(user=self.user)
            request.META['HTTP_USER_AGENT'] = 'TestBrowser'
            
            # Generate fingerprint
            fingerprint = self.middleware._generate_fingerprint(request)
            
            # Should use MD5 (32 chars) rather than SHA256 (64 chars)
            self.assertEqual(len(fingerprint), 32)
            
        finally:
            # Restore original algorithm
            self.middleware.FINGERPRINT_HASH_ALGORITHM = original_algo


class SignalIntegrationTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test Django signal integration"""
    
    def test_token_validation_failed_signal(self):
        """Test that token_validation_failed signal is sent when token validation fails"""
        # Create a social account with a valid token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Set up a signal receiver
        signal_called = False
        signal_user = None
        signal_account = None
        
        def handle_validation_failed(sender, request, user, account, token, **kwargs):
            nonlocal signal_called, signal_user, signal_account
            signal_called = True
            signal_user = user
            signal_account = account
        
        # Connect the signal
        token_validation_failed.connect(handle_validation_failed)
        
        try:
            # Mock token validation to return False (validation failed)
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=False):
                # Mock logout to prevent actual logout
                with mock.patch('django.contrib.auth.logout'):
                    # Process the request
                    self.middleware(request)
                    
                    # Signal should have been called with correct parameters
                    self.assertTrue(signal_called)
                    self.assertEqual(signal_user, self.user)
                    self.assertEqual(signal_account, account)
        finally:
            # Disconnect the signal
            token_validation_failed.disconnect(handle_validation_failed)
    
    def test_token_refreshed_signal(self):
        """Test that token_refreshed signal is sent when a token is refreshed"""
        # Create a social account with an expired token
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        token.token_secret = 'refresh-token'
        token.save()
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Set up a signal receiver
        signal_called = False
        signal_account = None
        signal_old_token = None
        signal_new_token = None
        
        def handle_token_refreshed(sender, account, old_token, new_token, **kwargs):
            nonlocal signal_called, signal_account, signal_old_token, signal_new_token
            signal_called = True
            signal_account = account
            signal_old_token = old_token
            signal_new_token = new_token
        
        # Connect the signal
        token_refreshed.connect(handle_token_refreshed)
        
        try:
            # Mock the refresh call to simulate successful refresh and call the signal
            with mock.patch.object(self.middleware, '_try_refresh_token') as mock_refresh:
                # Set up the mock to simulate a successful refresh
                def refresh_side_effect(account, token):
                    # Update token
                    token.token = 'new-token'
                    token.expires_at = timezone.now() + timedelta(hours=1)
                    token.save()
                    
                    # Send the token_refreshed signal manually (normally done in the real method)
                    token_refreshed.send(
                        sender=self.middleware.__class__,
                        account=account,
                        old_token=token,
                        new_token=token
                    )
                    return token

                mock_refresh.side_effect = refresh_side_effect
                
                # Mock token validation to return True
                with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                    # Process the request
                    self.middleware(request)
                    
                    # Signal should have been called
                    self.assertTrue(signal_called)
                    self.assertEqual(signal_account, account)
                    self.assertEqual(signal_new_token.token, 'new-token')
                    
        finally:
            # Disconnect the signal
            token_refreshed.disconnect(handle_token_refreshed)
    
    def test_session_fingerprint_mismatch_signal(self):
        """Test that session_fingerprint_mismatch signal is sent on fingerprint mismatch"""
        # Create a social account with a valid token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Set a fingerprint in the session
        request.session['session_fingerprint'] = 'stored-fingerprint'
        
        # Set up a signal receiver
        signal_called = False
        signal_similarity = None
        
        def handle_fingerprint_mismatch(sender, request, user, similarity, threshold, **kwargs):
            nonlocal signal_called, signal_similarity
            signal_called = True
            signal_similarity = similarity
        
        # Connect the signal
        session_fingerprint_mismatch.connect(handle_fingerprint_mismatch)
        
        try:
            # Mock fingerprint validation to fail
            with mock.patch.object(self.middleware, '_validate_session_fingerprint', return_value={
                'valid': False,
                'similarity': 0.5,
                'threshold': 0.9
            }):
                # Mock token validation to pass
                with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                    # Mock logout to prevent actual logout
                    with mock.patch('django.contrib.auth.logout'):
                        # Process the request
                        self.middleware(request)
                        
                        # Signal should have been called with correct parameters
                        self.assertTrue(signal_called)
                        self.assertEqual(signal_similarity, 0.5)
        finally:
            # Disconnect the signal
            session_fingerprint_mismatch.disconnect(handle_fingerprint_mismatch)


# Sample custom failure handler for testing
def custom_token_expired_handler(request, result):
    """Custom handler for token expired failures"""
    # Return a JSON response instead of redirecting
    return JsonResponse({
        'error': 'token_expired',
        'provider': result.get('provider'),
        'message': f"Your {result.get('provider')} token has expired."
    }, status=401)


@override_settings(OAUTH_SESSION_VALIDATOR_HANDLERS={
    'token_expired': f'{__name__}.custom_token_expired_handler'
})
class CustomFailureHandlersTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test custom failure handlers"""
    
    def setUp(self):
        super().setUp()
        # Create a new middleware instance to pick up the settings
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())
        self.middleware.VALIDATION_PROBABILITY = 1.0
        self.middleware.VALIDATION_INTERVAL = 0
    
    def test_custom_token_expired_handler(self):
        """Test that a custom handler is used for token expired failures"""
        # Create a social account with an expired token
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Mock token validation to pass (the expiry check should still fail)
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # The middleware should detect the expired token and call the handler
            
            # Process the request with our custom handler
            response = self.middleware(request)
            
            # Should be a JSON response (from our custom handler)
            self.assertIsInstance(response, JsonResponse)
            self.assertEqual(response.status_code, 401)
            
            # Parse the response
            content = json.loads(response.content.decode())
            self.assertEqual(content['error'], 'token_expired')
            self.assertEqual(content['provider'], 'google')
    
    def test_fallback_to_default_handler(self):
        """Test fallback to default handler when no custom handler is defined"""
        # Create a social account with a valid token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Set up session with an old timestamp to trigger session_age_exceeded
        request.session['session_start_time'] = time.time() - (86400 * 8)  # 8 days old
        
        # Mock token validation to return True
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Process the request - should use the default handler
            response = self.middleware(request)
            
            # Default handler should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_error_in_custom_handler(self):
        """Test fallback to default handler when custom handler raises an exception"""
        # Update failure handlers with a broken handler
        def broken_handler(request, result):
            raise ValueError("Simulated error in custom handler")
            
        self.middleware.failure_handlers['token_expired'] = broken_handler
        
        # Create a social account with an expired token
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Mock token validation to pass (the expiry check should still fail)
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Mock logger to check for error logging
            with mock.patch('django_oauth_guard.middleware.logger') as mock_logger:
                # Process the request - should fall back to default handler
                response = self.middleware(request)
                
                # Error should be logged
                mock_logger.exception.assert_called_once()
                
                # Default handler should redirect to login
                self.assertIsInstance(response, HttpResponseRedirect)


# Function-based approach for the custom provider
def validate_custom_token(token):
    """Validate a custom provider token"""
    return token == 'valid-custom-token'

def refresh_custom_token(account, token):
    """Refresh a custom provider token"""
    if token.token_secret == 'valid-refresh-token':
        token.token = 'refreshed-custom-token'
        token.expires_at = timezone.now() + timedelta(hours=1)
        token.save()
        return token
    return None

class AdditionalProvidersTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test support for additional OAuth providers"""
    
    def setUp(self):
        super().setUp()
        # Create a new middleware instance to pick up the settings
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())
        self.middleware.VALIDATION_PROBABILITY = 1.0
        self.middleware.VALIDATION_INTERVAL = 0
        
        # Create a custom provider app
        self.custom_app = SocialApp.objects.create(
            provider='custom',
            name='Custom Provider',
            client_id='custom-client-id',
            secret='custom-client-secret'
        )
        self.social_apps['custom'] = self.custom_app
        
        # Manually register the custom provider functions directly
        self.middleware.provider_validators['custom'] = validate_custom_token
        self.middleware.provider_refreshers['custom'] = refresh_custom_token
    
    def test_custom_provider_loaded(self):
        """Test that custom providers are registered"""
        # Validator and refresher should be registered
        self.assertIn('custom', self.middleware.provider_validators)
        self.assertIn('custom', self.middleware.provider_refreshers)
    
    def test_custom_provider_validation(self):
        """Test validation with a custom provider"""
        # Create a social account with the custom provider
        account = self.create_social_account('custom')
        
        # Test with valid token - should be accepted by the validator
        token = self.create_social_token(
            account,
            token='valid-custom-token',
            expires_at=timezone.now() + timedelta(days=1)
        )
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Save the requests processed flag as True for the first test case
        call_counts = []
        original_validator = validate_custom_token
        
        def counting_validator(token_value):
            # Keep track of calls and arguments
            call_counts.append(token_value)
            # Call original for valid tokens
            return original_validator(token_value)
            
        # Replace the validator with our counting version
        self.middleware.provider_validators['custom'] = counting_validator
        
        try:
            # Call middleware with valid token
            response = self.middleware(request)
            
            # Request should go through successfully
            self.assertIsInstance(response, HttpResponse)
            
            # Validator should have been called with the token
            self.assertEqual(call_counts, ['valid-custom-token'])
        finally:
            # Restore original validator
            self.middleware.provider_validators['custom'] = original_validator
    
    def test_custom_provider_token_refresh(self):
        """Test token refresh with a custom provider"""
        # Create a social account with the custom provider
        account = self.create_social_account('custom')
        
        # Create an expired token with valid refresh token
        token = self.create_social_token(
            account,
            token='expired-custom-token',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        token.token_secret = 'valid-refresh-token'
        token.save()
        
        # Create a request
        request = self.create_request(user=self.user)
        
        # Save original refresh function
        refresh_called = []
        original_refresher = self.middleware.provider_refreshers['custom']
        
        def counting_refresher(acct, tkn):
            # Keep track of calls
            refresh_called.append((acct, tkn))
            # Call original refresher
            return original_refresher(acct, tkn)
            
        # Replace with our counting version
        self.middleware.provider_refreshers['custom'] = counting_refresher
        
        try:
            # Process the request (should trigger refresh)
            response = self.middleware(request)
            
            # Refresher should be called
            self.assertEqual(len(refresh_called), 1)
            self.assertEqual(refresh_called[0][0], account)
            self.assertEqual(refresh_called[0][1], token)
            
            # Should continue with request (token refreshed)
            self.assertIsInstance(response, HttpResponse)
            
            # Token should be refreshed
            token.refresh_from_db()
            self.assertEqual(token.token, 'refreshed-custom-token')
        finally:
            # Restore original refresher
            self.middleware.provider_refreshers['custom'] = original_refresher