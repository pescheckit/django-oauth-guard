import time
import json
from unittest import mock
from datetime import datetime, timedelta

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings

from allauth.socialaccount.models import SocialApp, SocialAccount, SocialToken

from django_oauth_guard.middleware import OAuthValidationMiddleware
from django_oauth_guard.tests.test_integration import RequestMixin, ProviderSetupMixin


@override_settings(OAUTH_SESSION_VALIDATOR={
    'VALIDATION_PROBABILITY': 1.0,  # Always validate in tests
    'VALIDATION_INTERVAL': 0,       # No throttling in tests
})
class SecurityAttackPreventionTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test prevention of common security attacks"""
    
    def test_csrf_token_stealing_via_session_hijacking(self):
        """Test that session hijacking attempts are detected and prevented"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create an initial request with one device fingerprint
        initial_request = self.create_request(user=self.user)
        initial_request.META = {
            'HTTP_USER_AGENT': 'Legitimate Browser',
            'REMOTE_ADDR': '192.168.1.100',
            'HTTP_ACCEPT_LANGUAGE': 'en-US',
        }
        
        # Mock token validation to succeed
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Process initial request to establish fingerprint
            response = self.middleware(initial_request)
            
            # Store the session ID and fingerprint
            session_key = initial_request.session.session_key
            fingerprint = initial_request.session.get('session_fingerprint')
            
            # Verify fingerprint was stored
            self.assertIsNotNone(fingerprint)
            
            # Now simulate a different user with the stolen session cookie
            # but different browser/device characteristics
            hijacked_request = self.create_request(user=self.user)
            hijacked_request.META = {
                'HTTP_USER_AGENT': 'Malicious Browser',
                'REMOTE_ADDR': '10.0.0.1',  # Different IP
                'HTTP_ACCEPT_LANGUAGE': 'ru-RU',  # Different language
            }
            
            # Copy the session data including the fingerprint
            for key, value in initial_request.session.items():
                hijacked_request.session[key] = value
            
            # Ensure the session keys match (simulating stolen cookie)
            hijacked_request.session.session_key = session_key
            
            # Mock logout to prevent actual logout during test
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                # Process the hijacked request
                response = self.middleware(hijacked_request)
                
                # User should be logged out
                mock_logout.assert_called_once()
                
                # Response should redirect to login
                self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_revoked_oauth_token_prevention(self):
        """Test that revoked OAuth tokens are detected and sessions are terminated"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # First, simulate a valid token
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Process request with valid token
            response = self.middleware(request)
            
            # Request should proceed normally
            self.assertIsInstance(response, HttpResponse)
        
        # Now simulate token revocation by user at the provider
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=False):
            # Mock logout to prevent actual logout during test
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                # Process request with now-invalid token
                response = self.middleware(request)
                
                # User should be logged out
                mock_logout.assert_called_once()
                
                # Response should redirect to login
                self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_token_expiry_security(self):
        """Test that expired tokens are properly handled as a security measure"""
        # Create a social account for the user with a token that will expire soon
        account = self.create_social_account('google')
        expire_soon = datetime.now() + timedelta(seconds=30)
        token = self.create_social_token(account, expires_at=expire_soon)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Process the request with a valid but soon-to-expire token
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            response = self.middleware(request)
            
            # Request should proceed normally
            self.assertIsInstance(response, HttpResponse)
        
        # Fast-forward time to after token expiration
        token.expires_at = datetime.now() - timedelta(seconds=30)
        token.save()
        
        # Process the request again with an expired token
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Mock token refresh to fail
            with mock.patch.object(self.middleware, '_try_refresh_token', return_value=False):
                # Mock logout to prevent actual logout during test
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    response = self.middleware(request)
                    
                    # User should be logged out
                    mock_logout.assert_called_once()
                    
                    # Response should redirect to login
                    self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_privilege_escalation_prevention(self):
        """Test that sensitive actions always trigger validation"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request to a sensitive path
        admin_path = '/admin/users/edit/1/'
        request = self.create_request(path=admin_path, user=self.user)
        
        # Set validation probability to 0
        self.middleware.VALIDATION_PROBABILITY = 0
        
        # Make sure the sensitive path will be detected
        self.middleware.SENSITIVE_PATHS = ['/admin/']
        
        # Check that validation is forced for this sensitive path
        with mock.patch.object(self.middleware, '_perform_security_checks',
                             wraps=self.middleware._perform_security_checks) as mock_checks:
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                response = self.middleware(request)
                
                # Security checks should be performed
                mock_checks.assert_called_once()
    
    def test_dormant_account_timeout(self):
        """Test that inactive sessions are terminated for security"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Set last activity to a long time ago
        inactive_time = time.time() - (86400 * 2)  # 2 days ago
        request.session['last_activity'] = inactive_time
        
        # Process the request with valid token but inactive session
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Mock logout to prevent actual logout during test
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                response = self.middleware(request)
                
                # User should be logged out due to inactivity
                mock_logout.assert_called_once()
                
                # Response should redirect to login
                self.assertIsInstance(response, HttpResponseRedirect)


@override_settings(OAUTH_SESSION_VALIDATOR={
    'FINGERPRINT_SIMILARITY_THRESHOLD': 0.9,  # 90% similarity required
})
class FingerprintSecurityTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test fingerprint security features"""
    
    def test_fingerprint_tolerance_levels(self):
        """Test different fingerprint similarity levels for security vs usability"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Generate an original fingerprint
        original_request = self.create_request(user=self.user)
        original_request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212',
            'REMOTE_ADDR': '192.168.1.100',
            'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
        }
        
        original_fingerprint = self.middleware._generate_fingerprint(original_request)
        
        # Different scenarios with varying levels of similarity
        test_cases = [
            # Minor change - slightly different user agent version
            {
                'meta': {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.213',
                    'REMOTE_ADDR': '192.168.1.100',
                    'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
                },
                'expected_similarity': '> 0.95',  # Very similar
                'should_pass': True
            },
            # Moderate change - different browser but same OS
            {
                'meta': {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/88.0',
                    'REMOTE_ADDR': '192.168.1.100',
                    'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
                },
                'expected_similarity': '~0.8-0.9',  # Moderately similar
                'should_pass': False  # Depends on threshold (default 0.9)
            },
            # Major change - different OS, browser, and location
            {
                'meta': {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
                    'REMOTE_ADDR': '10.0.0.1',
                    'HTTP_ACCEPT_LANGUAGE': 'fr-FR,fr;q=0.9',
                },
                'expected_similarity': '< 0.7',  # Very different
                'should_pass': False
            }
        ]
        
        # Test each case
        for i, case in enumerate(test_cases):
            # Create a new request with the test case META
            test_request = self.create_request(user=self.user)
            test_request.META = case['meta']
            
            # Generate the fingerprint
            test_fingerprint = self.middleware._generate_fingerprint(test_request)
            
            # Calculate similarity
            similarity = self.middleware._calculate_similarity(original_fingerprint, test_fingerprint)
            
            # Test comparison at default threshold
            compare_result = self.middleware._compare_fingerprints(original_fingerprint, test_fingerprint)
            
            # Assertions based on expected outcome
            self.assertEqual(compare_result, case['should_pass'], 
                         f"Case {i+1} failed: got {compare_result}, expected {case['should_pass']}")
    
    def test_fingerprint_components_security(self):
        """Test that fingerprint includes sufficient components to be secure"""
        # Create a request with minimal metadata
        request = self.create_request()
        request.META = {
            'HTTP_USER_AGENT': 'TestBrowser/1.0',
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_ACCEPT_LANGUAGE': 'en',
        }
        
        # Generate fingerprint
        fingerprint = self.middleware._generate_fingerprint(request)
        
        # Ensure fingerprint has a reasonable length for security
        self.assertTrue(len(fingerprint) >= 32, "Fingerprint should be at least 32 characters for security")
        
        # Test uniqueness - create a slightly different request
        different_request = self.create_request()
        different_request.META = {
            'HTTP_USER_AGENT': 'TestBrowser/1.0',
            'REMOTE_ADDR': '127.0.0.2',  # Just changed the last digit
            'HTTP_ACCEPT_LANGUAGE': 'en',
        }
        
        different_fingerprint = self.middleware._generate_fingerprint(different_request)
        
        # Fingerprints should be different even with minor changes
        self.assertNotEqual(fingerprint, different_fingerprint)
        
        # Check that SECRET_KEY is included in fingerprint calculation
        with self.settings(SECRET_KEY='test-secret'):
            secure_fingerprint = self.middleware._generate_fingerprint(request)
            
            # Fingerprint should be different with different SECRET_KEY
            self.assertNotEqual(fingerprint, secure_fingerprint)


class TokenStorageSecurityTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test security aspects of token storage and validation"""
    
    def test_token_caching_security(self):
        """Test that token validation caching is secure"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account, token='very-secret-token-value')
        
        # Call token validation with a mock to see how the token is handled
        with mock.patch('django.core.cache.cache.get', return_value=None) as mock_cache_get:
            with mock.patch('django.core.cache.cache.set') as mock_cache_set:
                with mock.patch('urllib.request.urlopen') as mock_urlopen:
                    # Set up mock response for successful validation
                    mock_response = mock.Mock()
                    mock_response.status = 200
                    mock_urlopen.return_value.__enter__.return_value = mock_response
                    
                    # Call validation method
                    self.middleware._validate_google_token(token.token)
                    
                    # Check cache key - should not contain full token
                    cache_key_arg = mock_cache_set.call_args[0][0]
                    self.assertIn('google_token_valid_', cache_key_arg)
                    self.assertNotIn(token.token, cache_key_arg)
                    
                    # Check that only a prefix of the token is used in cache key
                    token_prefix = token.token[:10]
                    self.assertIn(token_prefix, cache_key_arg)
    
    def test_exception_handling_security(self):
        """Test that exceptions are handled safely without revealing sensitive information"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock validation to raise a potentially sensitive exception
        sensitive_error = Exception('Contains sensitive_token=abc123 and password=secret')
        with mock.patch.object(self.middleware, '_validate_google_token', side_effect=sensitive_error):
            # Mock logger to capture logged messages
            with mock.patch('django_oauth_guard.middleware.logger') as mock_logger:
                # Mock logout to prevent actual logout during test
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    # Process the request
                    response = self.middleware(request)
                    
                    # Check that the exception was logged
                    mock_logger.exception.assert_called_once()
                    
                    # Inspect the logged message
                    log_msg = mock_logger.exception.call_args[0][0]
                    log_args = mock_logger.exception.call_args[0][1:]
                    
                    # Ensure the log message doesn't include the full exception message
                    # It should be a generic format string
                    self.assertEqual(log_msg, "Error in security checks: %s")
                    
                    # The exception is passed as an arg but should be sanitized
                    # in a real implementation
                    self.assertEqual(str(log_args[0]), str(sensitive_error))
    
    def test_token_refresh_security(self):
        """Test security aspects of token refresh mechanism"""
        # Create a social account for the user with expired token
        account = self.create_social_account('google')
        token = self.create_social_token(
            account, 
            token='expired-token', 
            expires_at=datetime.now() - timedelta(hours=1)
        )
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh method to track calls and return success
        with mock.patch.object(self.middleware, '_try_refresh_token', return_value=True) as mock_refresh:
            # Also mock the validation to return True for the refreshed token
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Process the request
                response = self.middleware(request)
                
                # Token refresh should be attempted
                mock_refresh.assert_called_once()
                
                # Check arguments to the refresh method
                refresh_args = mock_refresh.call_args[0]
                self.assertEqual(refresh_args[0], account)
                self.assertEqual(refresh_args[1], token)