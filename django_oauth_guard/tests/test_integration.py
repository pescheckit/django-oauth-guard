import time
import json
from unittest import mock
from datetime import datetime, timedelta
from django.utils import timezone

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from allauth.socialaccount.models import SocialApp, SocialAccount, SocialToken
from allauth.socialaccount.providers.google.provider import GoogleProvider
from allauth.socialaccount.providers.facebook.provider import FacebookProvider
from allauth.socialaccount.providers.github.provider import GitHubProvider
from allauth.socialaccount.providers.microsoft.provider import MicrosoftGraphProvider as MicrosoftProvider
from allauth.socialaccount.providers.linkedin_oauth2.provider import LinkedInOAuth2Provider as LinkedInProvider

from django_oauth_guard.middleware import OAuthValidationMiddleware


class RequestMixin:
    """Mixin to set up request objects for testing"""
    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        
        # Create middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())
        
        # Force validation on every request
        self.middleware.VALIDATION_PROBABILITY = 1.0
        self.middleware.VALIDATION_INTERVAL = 0
    
    def create_request(self, path='/', user=None, session_data=None):
        """Create a request with session and messages middleware"""
        request = self.factory.get(path)
        
        # Add session
        middleware = SessionMiddleware(lambda r: HttpResponse())
        middleware.process_request(request)
        
        # Add session data if provided
        if session_data:
            for key, value in session_data.items():
                request.session[key] = value
        
        request.session.save()
        
        # Add messages framework
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)
        
        # Add user if provided
        if user:
            request.user = user
        
        return request


class ProviderSetupMixin:
    """Mixin to set up OAuth providers for testing"""
    PROVIDERS = {
        'google': {
            'class': GoogleProvider,
            'client_id': 'google-client-id',
            'secret': 'google-secret',
        },
        'facebook': {
            'class': FacebookProvider,
            'client_id': 'facebook-client-id',
            'secret': 'facebook-secret',
        },
        'github': {
            'class': GitHubProvider,
            'client_id': 'github-client-id',
            'secret': 'github-secret',
        },
        'microsoft': {
            'class': MicrosoftProvider,
            'client_id': 'microsoft-client-id',
            'secret': 'microsoft-secret',
        },
        'linkedin_oauth2': {
            'class': LinkedInProvider,
            'client_id': 'linkedin-client-id',
            'secret': 'linkedin-secret',
        },
    }
    
    def setUp(self):
        super().setUp()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123'
        )
        
        # Create social apps for each provider
        self.social_apps = {}
        for provider_id, provider_info in self.PROVIDERS.items():
            app = SocialApp.objects.create(
                provider=provider_id,
                name=f'{provider_id.title()} Test App',
                client_id=provider_info['client_id'],
                secret=provider_info['secret'],
            )
            self.social_apps[provider_id] = app
    
    def create_social_account(self, provider_id, uid=None, extra_data=None):
        """Create a social account for the test user"""
        if uid is None:
            uid = f'test-uid-{provider_id}'
        
        if extra_data is None:
            extra_data = {}
        
        account = SocialAccount.objects.create(
            user=self.user,
            provider=provider_id,
            uid=uid,
            extra_data=extra_data
        )
        
        return account
    
    def create_social_token(self, account, token='test-token', expires_at=None):
        """Create a social token for a social account"""
        if expires_at is None:
            # Token valid for 1 hour by default
            from django.utils import timezone
            expires_at = timezone.now() + timedelta(hours=1)
        
        token = SocialToken.objects.create(
            app=self.social_apps[account.provider],
            account=account,
            token=token,
            expires_at=expires_at
        )
        
        return token


class AllauthIntegrationTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test integration with django-allauth"""
    
    def test_middleware_finds_social_accounts(self):
        """Test that middleware correctly identifies users with social accounts"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the validation method to return True
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Call the middleware
            response = self.middleware(request)
            
            # Request should go through successfully
            self.assertIsInstance(response, HttpResponse)
    
    def test_all_providers_validation_methods_exist(self):
        """Test that middleware has validation methods for all supported providers"""
        for provider_id in self.PROVIDERS:
            # Check that a validator exists for this provider
            validator_method_name = f'_validate_{provider_id}_token'
            self.assertTrue(hasattr(self.middleware, validator_method_name))
            
            # Check that the validator is registered in provider_validators
            self.assertIn(provider_id, self.middleware.provider_validators)
    
    @mock.patch('urllib.request.urlopen')
    def test_google_token_revocation(self, mock_urlopen):
        """Test that middleware handles Google token revocation correctly"""
        # Create Google account
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Set up the mock to simulate a revoked token
        mock_urlopen.side_effect = mock.Mock(
            side_effect=urllib.error.HTTPError(
                url='',
                code=401,
                msg='',
                hdrs={},
                fp=mock.Mock(
                    read=mock.Mock(
                        return_value=b'{"error":"invalid_token"}'
                    )
                )
            )
        )
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    @mock.patch('urllib.request.urlopen')
    def test_facebook_token_revocation(self, mock_urlopen):
        """Test that middleware handles Facebook token revocation correctly"""
        # Create Facebook account
        account = self.create_social_account('facebook')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Set up the mock to simulate a token validation response with invalid token
        mock_response = mock.Mock()
        mock_response.read.return_value = b'{"data":{"is_valid":false}}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_token_expiration(self):
        """Test that middleware handles expired tokens correctly"""
        # Create Google account with expired token
        account = self.create_social_account('google')
        expired_date = datetime.now() - timedelta(hours=1)
        token = self.create_social_token(account, expires_at=expired_date)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_multiple_social_accounts(self):
        """Test that middleware works correctly with multiple social accounts"""
        # Create multiple social accounts for the user
        google_account = self.create_social_account('google')
        google_token = self.create_social_token(google_account)
        
        facebook_account = self.create_social_account('facebook')
        facebook_token = self.create_social_token(facebook_account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock validation methods to return True
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            with mock.patch.object(self.middleware, '_validate_facebook_token', return_value=True):
                # Call the middleware
                response = self.middleware(request)
                
                # Request should go through successfully
                self.assertIsInstance(response, HttpResponse)
    
    def test_one_invalid_token_of_many(self):
        """Test that any invalid token causes logout even if others are valid"""
        # Create multiple social accounts for the user
        google_account = self.create_social_account('google')
        google_token = self.create_social_token(google_account)
        
        facebook_account = self.create_social_account('facebook')
        facebook_token = self.create_social_token(facebook_account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock validation methods - Google valid, Facebook invalid
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            with mock.patch.object(self.middleware, '_validate_facebook_token', return_value=False):
                # Mock logout to prevent actual logout during test
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    # Call the middleware
                    response = self.middleware(request)
                    
                    # User should be logged out
                    mock_logout.assert_called_once()
                    
                    # Response should redirect to login
                    self.assertIsInstance(response, HttpResponseRedirect)


@override_settings(OAUTH_SESSION_VALIDATOR={
    'VALIDATION_PROBABILITY': 1.0,
    'VALIDATION_INTERVAL': 0,
})
class SecurityFeaturesTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test security features of the middleware"""
    
    def test_session_fingerprint_detection(self):
        """Test that session hijacking is detected via fingerprint changes"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create an initial request to establish a fingerprint
        initial_request = self.create_request(
            user=self.user,
            session_data={
                'session_start_time': time.time(),
                'last_activity': time.time(),
            }
        )
        
        # Mock request META for fingerprinting
        initial_request.META = {
            'HTTP_USER_AGENT': 'Original Browser',
            'REMOTE_ADDR': '192.168.1.1',
            'HTTP_ACCEPT_LANGUAGE': 'en-US',
        }
        
        # Mock validation for token
        with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
            # Process the initial request to establish fingerprint
            self.middleware(initial_request)
            
            # Get the established fingerprint
            fingerprint = initial_request.session.get('session_fingerprint')
            self.assertIsNotNone(fingerprint)
            
            # Now create a new request with different fingerprint data
            hijacked_request = self.create_request(
                user=self.user, 
                session_data={
                    'session_start_time': initial_request.session['session_start_time'],
                    'last_activity': initial_request.session['last_activity'],
                    'session_fingerprint': fingerprint,
                }
            )
            
            # Different user agent and IP to simulate hijacking
            hijacked_request.META = {
                'HTTP_USER_AGENT': 'Different Browser',
                'REMOTE_ADDR': '10.0.0.1',
                'HTTP_ACCEPT_LANGUAGE': 'fr-FR',
            }
            
            # Mock logout to prevent actual logout during test
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                # Process the hijacked request
                response = self.middleware(hijacked_request)
                
                # User should be logged out
                mock_logout.assert_called_once()
                
                # Response should redirect to login
                self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_session_age_enforced(self):
        """Test that session maximum age is enforced"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with an old session start time
        old_start_time = time.time() - (self.middleware.MAX_SESSION_AGE + 3600)  # 1 hour past max age
        request = self.create_request(
            user=self.user,
            session_data={
                'session_start_time': old_start_time,
                'last_activity': time.time(),  # Recent activity
            }
        )
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_inactivity_timeout_enforced(self):
        """Test that inactivity timeout is enforced"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with recent session start but old last activity
        old_activity_time = time.time() - (self.middleware.MAX_INACTIVITY + 3600)  # 1 hour past inactivity timeout
        request = self.create_request(
            user=self.user,
            session_data={
                'session_start_time': time.time(),  # Recent session
                'last_activity': old_activity_time,
            }
        )
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_token_refresh_attempt(self):
        """Test that middleware attempts to refresh expired tokens"""
        # Create a social account with expired token
        account = self.create_social_account('google')
        expired_date = datetime.now() - timedelta(hours=1)
        token = self.create_social_token(account, expires_at=expired_date)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the token refresh method to simulate successful refresh
        with mock.patch.object(self.middleware, '_try_refresh_token', return_value=True):
            # Mock the token validation to return True for the refreshed token
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Call the middleware
                response = self.middleware(request)
                
                # Request should go through successfully (no logout)
                self.assertIsInstance(response, HttpResponse)
    
    def test_sensitive_paths_always_validated(self):
        """Test that requests to sensitive paths are always validated"""
        # Create a social account for the user
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Override the validation probability to 0 (never validate)
        self.middleware.VALIDATION_PROBABILITY = 0.0
        
        # Create a request to a sensitive path
        sensitive_path = '/settings/'
        request = self.create_request(path=sensitive_path, user=self.user)
        
        # Spy on the validation methods
        with mock.patch.object(self.middleware, '_perform_security_checks', wraps=self.middleware._perform_security_checks) as mock_checks:
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Call the middleware
                response = self.middleware(request)
                
                # Security checks should be performed despite 0 probability
                mock_checks.assert_called_once()
                
                # Request should go through
                self.assertIsInstance(response, HttpResponse)


class ProviderSpecificValidationTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test provider-specific token validation methods"""
    
    @mock.patch('urllib.request.urlopen')
    def test_google_validation_success(self, mock_urlopen):
        """Test successful Google token validation"""
        # Set up mock response for successful validation
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method
        result = self.middleware._validate_google_token('test-token')
        
        # Should return True for valid token
        self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_google_validation_failure(self, mock_urlopen):
        """Test failed Google token validation"""
        # Set up mock to raise an HTTPError for invalid token
        mock_urlopen.side_effect = mock.Mock(
            side_effect=urllib.error.HTTPError(
                url='',
                code=401,
                msg='',
                hdrs={},
                fp=mock.Mock(
                    read=mock.Mock(
                        return_value=b'{"error":"invalid_token"}'
                    )
                )
            )
        )
        
        # Call the validation method
        result = self.middleware._validate_google_token('test-token')
        
        # Should return False for invalid token
        self.assertFalse(result)
    
    @mock.patch('urllib.request.urlopen')
    @override_settings(FACEBOOK_APP_ID='test-id', FACEBOOK_APP_SECRET='test-secret')
    def test_facebook_validation_success(self, mock_urlopen):
        """Test successful Facebook token validation"""
        # Set up mock response for successful validation
        mock_response = mock.Mock()
        mock_response.read.return_value = b'{"data":{"is_valid":true}}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method
        result = self.middleware._validate_facebook_token('test-token')
        
        # Should return True for valid token
        self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    @override_settings(FACEBOOK_APP_ID='test-id', FACEBOOK_APP_SECRET='test-secret')
    def test_facebook_validation_failure(self, mock_urlopen):
        """Test failed Facebook token validation"""
        # Set up mock response for invalid token
        mock_response = mock.Mock()
        mock_response.read.return_value = b'{"data":{"is_valid":false}}'
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method
        result = self.middleware._validate_facebook_token('test-token')
        
        # Should return False for invalid token
        self.assertFalse(result)
    
    def test_microsoft_validation(self):
        """Test Microsoft token validation"""
        # Microsoft validation checks JWT structure
        # Valid JWT structure (3 parts separated by dots)
        result = self.middleware._validate_microsoft_token('header.payload.signature')
        self.assertTrue(result)
        
        # Invalid JWT structure
        result = self.middleware._validate_microsoft_token('invalid-token')
        self.assertFalse(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_github_validation_success(self, mock_urlopen):
        """Test successful GitHub token validation"""
        # Set up mock response for successful validation
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method
        result = self.middleware._validate_github_token('test-token')
        
        # Should return True for valid token
        self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_github_validation_failure(self, mock_urlopen):
        """Test failed GitHub token validation"""
        # Set up mock to raise an HTTPError for invalid token
        mock_urlopen.side_effect = mock.Mock(
            side_effect=urllib.error.HTTPError(
                url='',
                code=401,
                msg='',
                hdrs={},
                fp=None
            )
        )
        
        # Call the validation method
        result = self.middleware._validate_github_token('test-token')
        
        # Should return False for invalid token
        self.assertFalse(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_linkedin_validation_success(self, mock_urlopen):
        """Test successful LinkedIn token validation"""
        # Set up mock response for successful validation
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method
        result = self.middleware._validate_linkedin_token('test-token')
        
        # Should return True for valid token
        self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_linkedin_validation_failure(self, mock_urlopen):
        """Test failed LinkedIn token validation"""
        # Set up mock to raise an HTTPError for invalid token
        mock_urlopen.side_effect = mock.Mock(
            side_effect=urllib.error.HTTPError(
                url='',
                code=401,
                msg='',
                hdrs={},
                fp=None
            )
        )
        
        # Call the validation method
        result = self.middleware._validate_linkedin_token('test-token')
        
        # Should return False for invalid token
        self.assertFalse(result)


class SecurityEdgeCasesTestCase(ProviderSetupMixin, RequestMixin, TestCase):
    """Test edge cases and security scenarios"""
    
    def test_missing_token(self):
        """Test handling of missing tokens for social accounts"""
        # Create a social account without creating a token
        account = self.create_social_account('google')
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock logout to prevent actual logout during test
        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # Call the middleware
            response = self.middleware(request)
            
            # User should be logged out
            mock_logout.assert_called_once()
            
            # Response should redirect to login
            self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_exception_during_validation(self):
        """Test that exceptions during validation are handled safely"""
        # Create a social account with token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock validation to raise an unexpected exception
        with mock.patch.object(self.middleware, '_validate_google_token', side_effect=Exception('Unexpected error')):
            # Also mock the logger to check for exception logging
            with mock.patch('django_oauth_guard.middleware.logger') as mock_logger:
                # Mock logout to prevent actual logout during test
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    # Call the middleware
                    response = self.middleware(request)
                    
                    # Exception should be logged
                    mock_logger.exception.assert_called_once()
                    
                    # User should be logged out
                    mock_logout.assert_called_once()
                    
                    # Response should redirect to login
                    self.assertIsInstance(response, HttpResponseRedirect)
    
    def test_cache_usage_for_token_validation(self):
        """Test that token validation results are cached"""
        # Create a social account with token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Mock the validation method to track calls
        with mock.patch.object(self.middleware, '_validate_google_token', 
                               wraps=self.middleware._validate_google_token) as mock_validate:
            with mock.patch('urllib.request.urlopen') as mock_urlopen:
                # Set up mock response for successful validation
                mock_response = mock.Mock()
                mock_response.status = 200
                mock_urlopen.return_value.__enter__.return_value = mock_response
                
                # First validation call
                result1 = self.middleware._validate_google_token('test-token')
                
                # Second validation call with same token should use cache
                result2 = self.middleware._validate_google_token('test-token')
                
                # Both results should be True
                self.assertTrue(result1)
                self.assertTrue(result2)
                
                # urlopen should be called only once (first validation)
                self.assertEqual(mock_urlopen.call_count, 1)
    
    @mock.patch('random.random')
    def test_validation_sampling(self, mock_random):
        """Test that validation follows the probability setting"""
        # Create a social account with token
        account = self.create_social_account('google')
        token = self.create_social_token(account)
        
        # Create a request with the user
        request = self.create_request(user=self.user)
        
        # Set a specific validation probability
        self.middleware.VALIDATION_PROBABILITY = 0.5
        
        # First test: random value below threshold (should validate)
        mock_random.return_value = 0.4  # Below 0.5 threshold
        
        with mock.patch.object(self.middleware, '_perform_security_checks', 
                               wraps=self.middleware._perform_security_checks) as mock_checks:
            with mock.patch.object(self.middleware, '_validate_google_token', return_value=True):
                # Process request
                self.middleware(request)
                
                # Security checks should be performed
                mock_checks.assert_called_once()
        
        # Reset mocks
        mock_checks.reset_mock()
        
        # Second test: random value above threshold (should skip validation)
        mock_random.return_value = 0.6  # Above 0.5 threshold
        
        with mock.patch.object(self.middleware, '_perform_security_checks', 
                               wraps=self.middleware._perform_security_checks) as mock_checks:
            # Process request
            self.middleware(request)
            
            # Security checks should be skipped
            mock_checks.assert_not_called()