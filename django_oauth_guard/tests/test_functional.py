import time
from unittest import mock
from datetime import datetime, timedelta

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.contrib.messages import get_messages
from django.conf import settings
from django.utils import timezone

from allauth.socialaccount.models import SocialApp, SocialAccount, SocialToken


class FunctionalTestCase(TestCase):
    """Functional tests using Django's test client"""
    
    def setUp(self):
        """Set up the test case"""
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        
        # Create a test client
        self.client = Client()
        
        # Create a Google social app
        self.app = SocialApp.objects.create(
            provider='google',
            name='Google',
            client_id='test-client-id',
            secret='test-secret'
        )
        
        # Add the app to the test site
        self.app.sites.add(settings.SITE_ID)
        
        # Create a social account for the user
        self.account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            uid='test-uid'
        )
        
        # Create a token for the account
        self.token = SocialToken.objects.create(
            app=self.app,
            account=self.account,
            token='test-token',
            expires_at=timezone.now() + timedelta(days=1)
        )
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_login_and_session_activity(self, mock_validate):
        """Test login and activity tracking"""
        # Mock token validation to succeed
        mock_validate.return_value = True
        
        # Log in the user
        login_successful = self.client.login(
            username='testuser',
            password='testpassword'
        )
        self.assertTrue(login_successful)
        
        # Visit a protected page
        response = self.client.get('/admin/', follow=True)
        
        # Token validation should have been called
        mock_validate.assert_called()
        
        # Session should have activity timestamps
        session = self.client.session
        self.assertIn('last_activity', session)
        self.assertIn('session_start_time', session)
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_token_revocation_behavior(self, mock_validate):
        """Test behavior when token is revoked"""
        # First login with a valid token
        mock_validate.return_value = True
        login_successful = self.client.login(
            username='testuser',
            password='testpassword'
        )
        self.assertTrue(login_successful)
        
        # Visit a page to establish session
        response = self.client.get('/admin/', follow=True)
        
        # Now simulate token revocation
        mock_validate.return_value = False
        
        # Visit another page
        response = self.client.get('/admin/', follow=True)
        
        # Should be redirected to login
        self.assertRedirects(
            response, 
            reverse('account_login'),
            fetch_redirect_response=False
        )
        
        # Check for appropriate error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('revoked' in str(msg) for msg in messages))
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_session_expiry_behavior(self, mock_validate):
        """Test behavior when session expires"""
        # Mock token validation to succeed
        mock_validate.return_value = True
        
        # Login
        self.client.login(username='testuser', password='testpassword')
        
        # Visit a page to establish session
        response = self.client.get('/admin/', follow=True)
        
        # Manually expire the session by modifying session data
        session = self.client.session
        session['session_start_time'] = time.time() - (86400 * 8)  # 8 days old (beyond 7 day limit)
        session.save()
        
        # Visit another page
        response = self.client.get('/admin/', follow=True)
        
        # Should be redirected to login
        self.assertRedirects(
            response, 
            reverse('account_login'),
            fetch_redirect_response=False
        )
        
        # Check for appropriate error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('session has exceeded' in str(msg) for msg in messages))
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_inactivity_timeout_behavior(self, mock_validate):
        """Test behavior when user is inactive for too long"""
        # Mock token validation to succeed
        mock_validate.return_value = True
        
        # Login
        self.client.login(username='testuser', password='testpassword')
        
        # Visit a page to establish session
        response = self.client.get('/admin/', follow=True)
        
        # Manually set last activity to a long time ago
        session = self.client.session
        session['last_activity'] = time.time() - (86400 * 2)  # 2 days of inactivity
        session.save()
        
        # Visit another page
        response = self.client.get('/admin/', follow=True)
        
        # Should be redirected to login
        self.assertRedirects(
            response, 
            reverse('account_login'),
            fetch_redirect_response=False
        )
        
        # Check for appropriate error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('timed out due to inactivity' in str(msg) for msg in messages))
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    def test_multiple_requests_and_session_update(self, mock_validate):
        """Test that multiple requests update the session activity correctly"""
        # Mock token validation to succeed
        mock_validate.return_value = True
        
        # Login
        self.client.login(username='testuser', password='testpassword')
        
        # Visit a page to establish session
        response = self.client.get('/admin/', follow=True)
        
        # Get the initial activity time
        initial_activity = self.client.session.get('last_activity')
        
        # Ensure time passes (at least 1 second)
        time.sleep(1)
        
        # Visit another page
        response = self.client.get('/admin/', follow=True)
        
        # Get the updated activity time
        updated_activity = self.client.session.get('last_activity')
        
        # Activity time should be updated
        self.assertGreater(updated_activity, initial_activity)
    
    def test_anonymous_user_not_affected(self):
        """Test that anonymous users are not affected by the middleware"""
        # Don't login, just visit a page
        response = self.client.get('/', follow=True)
        
        # Page should load without issues
        self.assertEqual(response.status_code, 200)


class MultiProviderFunctionalTestCase(TestCase):
    """Functional tests with multiple OAuth providers"""
    
    def setUp(self):
        """Set up the test case with multiple providers"""
        # Create a test user
        self.user = User.objects.create_user(
            username='multiprovider',
            email='multi@example.com',
            password='testpassword'
        )
        
        # Create a test client
        self.client = Client()
        
        # Create social apps for different providers
        self.providers = ['google', 'facebook', 'github']
        self.apps = {}
        
        for provider in self.providers:
            app = SocialApp.objects.create(
                provider=provider,
                name=f'{provider.title()}',
                client_id=f'{provider}-client-id',
                secret=f'{provider}-secret'
            )
            app.sites.add(settings.SITE_ID)
            self.apps[provider] = app
            
            # Create a social account for each provider
            account = SocialAccount.objects.create(
                user=self.user,
                provider=provider,
                uid=f'{provider}-uid'
            )
            
            # Create a token for each account
            token = SocialToken.objects.create(
                app=app,
                account=account,
                token=f'{provider}-token',
                expires_at=timezone.now() + timedelta(days=1)
            )
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_facebook_token')
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_github_token')
    def test_all_providers_validated(self, mock_github, mock_facebook, mock_google):
        """Test that all providers are validated"""
        # Set all validations to succeed
        mock_google.return_value = True
        mock_facebook.return_value = True
        mock_github.return_value = True
        
        # Login
        self.client.login(username='multiprovider', password='testpassword')
        
        # Visit a page
        response = self.client.get('/admin/', follow=True)
        
        # All validators should be called
        mock_google.assert_called()
        mock_facebook.assert_called()
        mock_github.assert_called()
    
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_google_token')
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_facebook_token')
    @mock.patch('django_oauth_guard.middleware.OAuthValidationMiddleware._validate_github_token')
    def test_one_invalid_provider_fails_all(self, mock_github, mock_facebook, mock_google):
        """Test that if one provider's token is invalid, the user is logged out"""
        # Google and Github are valid, but Facebook is invalid
        mock_google.return_value = True
        mock_facebook.return_value = False  # This one fails
        mock_github.return_value = True
        
        # Login
        self.client.login(username='multiprovider', password='testpassword')
        
        # Visit a page
        response = self.client.get('/admin/', follow=True)
        
        # Should be redirected to login
        self.assertRedirects(
            response, 
            reverse('account_login'),
            fetch_redirect_response=False
        )
        
        # Check for appropriate error message about Facebook
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Facebook' in str(msg) for msg in messages))