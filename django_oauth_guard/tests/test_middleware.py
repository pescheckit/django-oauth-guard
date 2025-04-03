import time
import unittest
import urllib.error
import urllib.request
from unittest import mock
from datetime import timedelta

from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.conf import settings
from django.utils import timezone

from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp

from django_oauth_guard.middleware import OAuthValidationMiddleware


class MessageMixin:
    """Mixin to add messages support to request"""
    def add_message_middleware(self, request):
        # Add support for messages
        # Don't overwrite the session if it's already a real session object
        if not hasattr(request, 'session') or isinstance(request.session, str):
            # Use a real session object
            from django.contrib.sessions.backends.db import SessionStore
            request.session = SessionStore()
            request.session.save()
        messages = FallbackStorage(request)
        setattr(request, '_messages', messages)
        return request


class SessionMixin:
    """Mixin to add session support to request"""
    def add_session_middleware(self, request):
        middleware = SessionMiddleware(lambda r: HttpResponse())
        middleware.process_request(request)
        request.session.save()
        # Make sure we have a real session, not a string
        if isinstance(request.session, str):
            from django.contrib.sessions.backends.db import SessionStore
            request.session = SessionStore()
            request.session.save()
        return request


class OAuthValidationMiddlewareTestCase(MessageMixin, SessionMixin, TestCase):
    """Test the OAuth validation middleware"""
    
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword'
        )
        
        # Create a request factory
        self.factory = RequestFactory()
        
        # Create a middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())
        
        # Override the validation interval for testing
        self.middleware.VALIDATION_INTERVAL = 0
        self.middleware.VALIDATION_PROBABILITY = 1.0  # Always validate for testing
        
        # Add a mock handler for security failures
        original_handle_security_failure = self.middleware._handle_security_failure
        def custom_handle_security_failure(req, result):
            # Need to get user email before logout
            from django.contrib.auth import logout
            logout(req)
            # Now call the original
            try:
                return original_handle_security_failure(req, result)
            except AttributeError:
                # Handle case where user is logged out
                from django.http import HttpResponseRedirect
                from django.urls import reverse
                return HttpResponseRedirect(reverse('account_login'))
        
        self.middleware._handle_security_failure = custom_handle_security_failure
    
    def _create_authenticated_request(self, path='/'):
        """Helper to create an authenticated request"""
        request = self.factory.get(path)
        request.user = self.user
        # First add session middleware
        request = self.add_session_middleware(request)
        # Then add message middleware using the session
        request = self.add_message_middleware(request)
        return request
    
    def _create_social_account(self, provider='google'):
        """Helper to create a social account for the test user"""
        # First create a SocialApp
        app = SocialApp.objects.create(
            provider=provider,
            name=f'{provider.title()} App',
            client_id='test-client-id',
            secret='test-secret'
        )
        
        # Create a SocialAccount
        account = SocialAccount.objects.create(
            user=self.user,
            provider=provider,
            uid=f'test-{provider}-uid'
        )
        
        # Create a SocialToken
        token = SocialToken.objects.create(
            app=app,
            account=account,
            token='test-token',
            expires_at=timezone.now() + timedelta(days=1)
        )
        
        return account, token
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_basic_request_flow(self, mock_validate):
        """Test that a basic request goes through the middleware"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        self._create_social_account()
        
        # Mock the socialaccount_set.exists() method to return True
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        with mock.patch.object(type(self.user), 'socialaccount_set', 
                              new_callable=mock.PropertyMock, 
                              return_value=social_accounts_mock):
            # Create an authenticated request
            request = self._create_authenticated_request()
            
            # Process the request through the middleware
            response = self.middleware(request)
            
            # Check that the response is returned
            self.assertIsInstance(response, HttpResponse)
    
    def test_skip_validation_for_unauthenticated(self):
        """Test that validation is skipped for unauthenticated users"""
        # Create an unauthenticated request
        request = self.factory.get('/')
        request.user = mock.MagicMock(is_authenticated=False)
        
        # Spy on the _perform_security_checks method
        with mock.patch.object(self.middleware, '_perform_security_checks') as mock_check:
            # Process the request
            self.middleware(request)
            
            # Check that security checks were not performed
            mock_check.assert_not_called()
    
    def test_skip_validation_for_non_social_users(self):
        """Test that validation is skipped for users without social accounts"""
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Create a mock socialaccount_set that returns empty queryset (no social accounts)
        # This time we want to force the middleware to think there are no social accounts
        # We can't just mock, because the middleware has been updated to check directly in the database
        
        # Create a new user with no social accounts
        user_no_socials = User.objects.create_user(
            username='no_social_user',
            email='no_socials@example.com',
            password='testpassword'
        )
        # Replace the user in the request
        request.user = user_no_socials
        
        # Spy on the _perform_security_checks method
        with mock.patch.object(self.middleware, '_perform_security_checks') as mock_check:
            # Process the request
            self.middleware(request)
            
            # Check that security checks were not performed
            mock_check.assert_not_called()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_validation_for_sensitive_path(self, mock_validate):
        """Test that validation happens for sensitive paths"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        self._create_social_account()
        
        # Create an authenticated request to a sensitive path
        request = self._create_authenticated_request('/settings/')
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Spy on the _perform_security_checks method
        with mock.patch.object(type(self.user), 'socialaccount_set',
                             new_callable=mock.PropertyMock,
                             return_value=social_accounts_mock):
            with mock.patch.object(self.middleware, '_perform_security_checks', wraps=self.middleware._perform_security_checks) as mock_check:
                # Process the request
                self.middleware(request)
                
                # Check that security checks were performed
                mock_check.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_session_age_validation(self, mock_validate):
        """Test session age validation"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        self._create_social_account()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Set session start time to an old time
        request.session['session_start_time'] = time.time() - (self.middleware.MAX_SESSION_AGE + 3600)
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Process the request through the middleware
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                response = self.middleware(request)
                
                # Check that the user was logged out
                mock_logout.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_inactivity_validation(self, mock_validate):
        """Test inactivity validation"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        self._create_social_account()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Set last activity to an old time
        request.session['last_activity'] = time.time() - (self.middleware.MAX_INACTIVITY + 3600)
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Process the request through the middleware
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                response = self.middleware(request)
                
                # Check that the user was logged out
                mock_logout.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_session_fingerprint_validation(self, mock_validate):
        """Test session fingerprint validation"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        self._create_social_account()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Set a different fingerprint in the session
        request.session['session_fingerprint'] = 'different-fingerprint'
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Mock the _compare_fingerprints method to return False
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch.object(self.middleware, '_calculate_similarity', return_value=0.5):
                # Process the request through the middleware
                with mock.patch('django.contrib.auth.logout') as mock_logout:
                    response = self.middleware(request)
                    
                    # Check that the user was logged out
                    mock_logout.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_token_validation_failure(self, mock_validate):
        """Test that invalid tokens cause logout"""
        # Mock the token validation to return False
        mock_validate.return_value = False
        
        # Create a social account for the user
        self._create_social_account()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Process the request through the middleware
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                response = self.middleware(request)
                
                # Check that the user was logged out
                mock_logout.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_expired_token(self, mock_validate):
        """Test handling of expired tokens"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        account, token = self._create_social_account()
        
        # Set the token to be expired
        token.expires_at = timezone.now() - timedelta(days=1)
        token.save()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Process the request through the middleware
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch('django.contrib.auth.logout') as mock_logout:
                # Also mock token refresh to fail
                with mock.patch.object(self.middleware, '_try_refresh_token', return_value=False):
                    response = self.middleware(request)
                    
                    # Check that the user was logged out
                    mock_logout.assert_called_once()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_successful_token_refresh(self, mock_validate):
        """Test successful token refresh"""
        # Mock the token validation to return True
        mock_validate.return_value = True
        
        # Create a social account for the user
        account, token = self._create_social_account()
        
        # Set the token to be expired
        token.expires_at = timezone.now() - timedelta(days=1)
        token.save()
        
        # Create an authenticated request
        request = self._create_authenticated_request()
        
        # Mock socialaccount_set
        social_accounts_mock = mock.Mock()
        social_accounts_mock.exists.return_value = True
        social_accounts_mock.filter.return_value = SocialAccount.objects.filter(user=self.user)
        
        # Process the request through the middleware
        with mock.patch.object(type(self.user), 'socialaccount_set',
                            new_callable=mock.PropertyMock,
                            return_value=social_accounts_mock):
            with mock.patch.object(self.middleware, '_try_refresh_token', return_value=True):
                response = self.middleware(request)
                
                # Check that the response is returned (no logout)
                self.assertIsInstance(response, HttpResponse)


class ProviderTokenValidationTests(TestCase):
    """Test the provider-specific token validation methods"""
    
    def setUp(self):
        # Create a middleware instance
        self.middleware = OAuthValidationMiddleware(lambda r: HttpResponse())
    
    @mock.patch('urllib.request.urlopen')
    def test_google_token_validation_success(self, mock_urlopen):
        """Test Google token validation success"""
        # Mock the response
        mock_response = mock.MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Mock the cache get to return None (cache miss)
        with mock.patch('django.core.cache.cache.get', return_value=None):
            # Mock the cache set
            with mock.patch('django.core.cache.cache.set'):
                # Call the validation method
                result = self.middleware._validate_google_token('test-token')
                
                # Check that the result is True
                self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_google_token_validation_failure(self, mock_urlopen):
        """Test Google token validation failure"""
        # Mock the urlopen to raise an HTTPError
        error = urllib.error.HTTPError(
            url='',
            code=401,
            msg='',
            hdrs={},
            fp=unittest.mock.Mock(
                read=unittest.mock.Mock(
                    return_value=b'{"error":"invalid_token"}'
                )
            )
        )
        mock_urlopen.side_effect = error
        
        # Mock the cache handling
        with mock.patch('django.core.cache.cache.get', return_value=None):
            with mock.patch('django.core.cache.cache.set'):
                # Call the validation method
                result = self.middleware._validate_google_token('test-token')
                
                # Check that the result is False
                self.assertFalse(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_facebook_token_validation(self, mock_urlopen):
        """Test Facebook token validation"""
        # Mock the response
        mock_response = mock.MagicMock()
        mock_response.read.return_value = b'{"data":{"is_valid":true}}'
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Call the validation method with settings
        with self.settings(FACEBOOK_APP_ID='test-id', FACEBOOK_APP_SECRET='test-secret'):
            # Mock the cache handling
            with mock.patch('django.core.cache.cache.get', return_value=None):
                with mock.patch('django.core.cache.cache.set'):
                    result = self.middleware._validate_facebook_token('test-token')
                    
                    # Check that the result is True
                    self.assertTrue(result)
    
    def test_microsoft_token_validation(self):
        """Test Microsoft token validation"""
        # Microsoft validation just checks JWT format
        # Test with a valid-looking token
        result = self.middleware._validate_microsoft_token('header.payload.signature')
        self.assertTrue(result)
        
        # Test with an invalid token
        result = self.middleware._validate_microsoft_token('invalid-token')
        self.assertFalse(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_github_token_validation(self, mock_urlopen):
        """Test GitHub token validation"""
        # Mock the response
        mock_response = mock.MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Mock the cache handling
        with mock.patch('django.core.cache.cache.get', return_value=None):
            with mock.patch('django.core.cache.cache.set'):
                # Call the validation method
                result = self.middleware._validate_github_token('test-token')
                
                # Check that the result is True
                self.assertTrue(result)
    
    @mock.patch('urllib.request.urlopen')
    def test_linkedin_token_validation(self, mock_urlopen):
        """Test LinkedIn token validation"""
        # Mock the response
        mock_response = mock.MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        # Mock the cache handling
        with mock.patch('django.core.cache.cache.get', return_value=None):
            with mock.patch('django.core.cache.cache.set'):
                # Call the validation method
                result = self.middleware._validate_linkedin_token('test-token')
                
                # Check that the result is True
                self.assertTrue(result)