# Django OAuth Guard - Advanced Documentation

This document contains detailed information about Django OAuth Guard's advanced features, customization options, and development guidelines.

## Table of Contents

- [Advanced Features](#advanced-features)
- [Complete Configuration Options](#complete-configuration-options)
- [Signal Integration](#signal-integration)
- [Custom Failure Handlers](#custom-failure-handlers)
- [Adding Custom OAuth Providers](#adding-custom-oauth-providers)
- [Development and Testing](#development-and-testing)
- [GitHub Actions and PyPI Publishing](#github-actions-and-pypi-publishing)
- [Troubleshooting](#troubleshooting)

## Advanced Features

In addition to the core features mentioned in the README, Django OAuth Guard includes:

- **Extensible Provider System**: Add support for any OAuth provider
- **Signal Integration**: Django signals for security events to hook into your application logic
- **Custom Failure Handlers**: Configure custom behavior for different security failures
- **Enhanced Fingerprinting**: Advanced session fingerprinting with IP subnet matching and geolocation
- **Performance Optimizations**: Caching, throttling, and sampling to minimize API calls
- **Detailed Error Messages**: User-friendly explanations of security actions
- **Robust Logging**: Comprehensive logging of security events

## Complete Configuration Options

All available configuration options for `settings.py`:

```python
# OAuth Session Validator Settings
OAUTH_SESSION_VALIDATOR = {
    # Basic settings
    'VALIDATION_PROBABILITY': 0.05,  # 5% of requests
    'VALIDATION_INTERVAL': 600,  # 10 minutes between checks
    'MAX_INACTIVITY': 86400,  # 24 hours inactivity timeout
    'MAX_SESSION_AGE': 604800,  # 7 days maximum session age
    'SENSITIVE_PATHS': [
        '/password/change/',
        '/settings/',
        '/payment/',
        '/admin/',
        '/delete/',
        '/email/change/',
    ],
    
    # Enhanced fingerprinting settings
    'FINGERPRINT_SIMILARITY_THRESHOLD': 0.9,  # 90% similarity required
    'FINGERPRINT_COMPONENTS': [
        'HTTP_USER_AGENT',
        'REMOTE_ADDR',
        'HTTP_ACCEPT_LANGUAGE',
    ],
    'FINGERPRINT_IP_MASK': 24,  # /24 subnet mask
    'FINGERPRINT_USE_GEOLOCATION': False,  # Enable to use geolocation in fingerprinting
    'FINGERPRINT_HASH_ALGORITHM': 'sha256',  # Hash algorithm for fingerprints
    
    # Token refresh settings
    'REFRESH_TOKEN_ENABLED': True,
    'REFRESH_TOKEN_BEFORE_EXPIRY': 300,  # Refresh tokens 5 minutes before expiry
}

# Provider-specific settings
FACEBOOK_APP_ID = 'your-facebook-app-id'
FACEBOOK_APP_SECRET = 'your-facebook-app-secret'

# Custom failure handlers
OAUTH_SESSION_VALIDATOR_HANDLERS = {
    'token_expired': 'myapp.security.handlers.handle_token_expired',
    'session_mismatch': 'myapp.security.handlers.handle_session_mismatch',
    'inactivity_timeout': 'myapp.security.handlers.handle_inactivity_timeout',
    'session_age_exceeded': 'myapp.security.handlers.handle_session_age_exceeded',
    'token_invalid': 'myapp.security.handlers.handle_token_invalid',
    'missing_token': 'myapp.security.handlers.handle_missing_token',
    'system_error': 'myapp.security.handlers.handle_system_error',
}

# Additional OAuth providers
OAUTH_SESSION_VALIDATOR_PROVIDERS = {
    'custom_provider': {
        'validator': 'myapp.oauth.custom_provider.validate_token',
        'refresher': 'myapp.oauth.custom_provider.refresh_token',
    },
    'discord': {
        'validator': 'myapp.oauth.discord.validate_token',
        'refresher': 'myapp.oauth.discord.refresh_token',
    }
}
```

## Signal Integration

Django OAuth Guard exposes several signals that allow you to hook into security events:

```python
from django.dispatch import receiver
from django_oauth_guard.signals import (
    token_validation_failed, token_refreshed, 
    session_fingerprint_mismatch, session_age_exceeded,
    user_inactivity_timeout, token_expired, validation_system_error
)

# Example: React to token validation failures
@receiver(token_validation_failed)
def handle_token_validation_failed(sender, request, user, account, token, **kwargs):
    # Log or notify security team
    security_logger.info(f"Token validation failed for user {user.email} with provider {account.provider}")
    
    # You could also send notifications, update user records, etc.
    send_security_notification(user, f"Your {account.provider} token validation failed")

# Example: Perform actions when tokens are refreshed
@receiver(token_refreshed)
def handle_token_refreshed(sender, account, old_token, new_token, **kwargs):
    # Update any related data that depends on the token
    user_services.update_provider_information(account.user, account.provider)
```

Available signals and their parameters:

| Signal | Parameters | Description |
|--------|------------|-------------|
| `token_validation_failed` | sender, request, user, account, token | Sent when a token validation fails |
| `token_refreshed` | sender, account, old_token, new_token | Sent when a token is successfully refreshed |
| `session_fingerprint_mismatch` | sender, request, user, similarity, threshold | Sent when a session fingerprint doesn't match |
| `session_age_exceeded` | sender, request, user | Sent when a session exceeds its maximum age |
| `user_inactivity_timeout` | sender, request, user | Sent when a user session times out due to inactivity |
| `token_expired` | sender, request, user, account, token | Sent when a token is expired and can't be refreshed |
| `validation_system_error` | sender, request, user, error | Sent when a system error occurs during validation |

## Custom Failure Handlers

You can create custom handlers for different security failure scenarios:

```python
def handle_token_expired(request, result):
    """Custom handler for expired tokens"""
    # Get information about the failure
    provider = result.get('provider')
    user = request.user
    
    # Log the event
    logger.info(f"Token expired for user {user.email} with provider {provider}")
    
    # Perform custom actions, e.g. send an API response instead of redirecting
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'error': 'session_expired',
            'message': f"Your {provider} session has expired. Please log in again."
        }, status=401)
    
    # Default behavior: logout and redirect
    messages.warning(request, f"Your {provider} session has expired. Please log in again.")
    logout(request)
    return HttpResponseRedirect(reverse('account_login'))
```

To register your custom handlers, add them to your Django settings:

```python
OAUTH_SESSION_VALIDATOR_HANDLERS = {
    'token_expired': 'myapp.security.handlers.handle_token_expired',
    'session_mismatch': 'myapp.security.handlers.handle_session_mismatch',
}
```

Each handler must:
1. Accept `request` and `result` parameters
2. Return an HttpResponse object (or None to fall back to default handling)
3. Handle user logout if needed

## Adding Custom OAuth Providers

You can add support for additional OAuth providers by implementing validator and refresher functions:

```python
def validate_discord_token(access_token):
    """Validate a Discord OAuth token"""
    try:
        response = requests.get(
            'https://discord.com/api/v10/users/@me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error validating Discord token: {e}")
        return False

def refresh_discord_token(account, token):
    """Refresh a Discord OAuth token"""
    try:
        # Only proceed if we have a refresh token
        if not token.token_secret:
            return None
            
        # Use the refresh token to get a new access token
        response = requests.post(
            'https://discord.com/api/v10/oauth2/token',
            data={
                'client_id': account.app.client_id,
                'client_secret': account.app.secret,
                'refresh_token': token.token_secret,
                'grant_type': 'refresh_token'
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Update the token
            token.token = data['access_token']
            if 'refresh_token' in data:
                token.token_secret = data['refresh_token']
            token.expires_at = datetime.now() + timedelta(seconds=data.get('expires_in', 604800))
            token.save()
            
            return token
    except Exception as e:
        logger.error(f"Error refreshing Discord token: {e}")
    
    return None
```

Register your custom provider in Django settings:

```python
OAUTH_SESSION_VALIDATOR_PROVIDERS = {
    'discord': {
        'validator': 'myapp.oauth.discord.validate_discord_token',
        'refresher': 'myapp.oauth.discord.refresh_discord_token',
    }
}
```

## Development and Testing

### Setting Up a Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/django-oauth-guard.git
cd django-oauth-guard

# Create a virtual environment
python -m venv dev-env
source dev-env/bin/activate  # On Windows: dev-env\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running the Tests

There are several ways to run the tests:

```bash
# Using the built-in test runner
python runtests.py

# Using pytest
pytest
pytest --cov=django_oauth_guard  # With coverage

# Using tox for multiple Python/Django versions
tox                 # All environments
tox -e py39-django32  # Specific environment
```

### Test Coverage

To generate a coverage report:

```bash
pytest --cov=django_oauth_guard --cov-report=html
```

Then open `htmlcov/index.html` in your browser.

### Code Style

The project follows PEP 8 with a few customizations. To check and format your code:

```bash
# Check code style
flake8 django_oauth_guard

# Format code
black django_oauth_guard
isort django_oauth_guard
```

## GitHub Actions and PyPI Publishing

The repository includes GitHub Actions workflows for testing and publishing the package.

### GitHub Secrets for PyPI Publishing

To publish to PyPI, you need to set up GitHub repository secrets:

1. Go to your repository on GitHub
2. Navigate to Settings > Secrets and variables > Actions
3. Add the following secrets:
   - `PYPI_API_TOKEN`: Your PyPI API token for publishing
   - `TEST_PYPI_API_TOKEN`: Your Test PyPI API token for testing the publishing workflow

To generate a PyPI API token:
1. Go to https://pypi.org/manage/account/token/
2. Create a new API token with scope "Project: django-oauth-guard"
3. Copy the token value and add it as a GitHub secret

For Test PyPI, follow the same process on https://test.pypi.org.

### GitHub Actions Workflows

The repository includes two GitHub Actions workflows:

1. **Tests**: Runs on every push and pull request to main/master
   - Runs tests across multiple Python and Django versions
   - Runs linting checks
   - Uploads coverage to Codecov

2. **Publish to PyPI**: Runs when a new release is created
   - Builds the package
   - Publishes to Test PyPI
   - If the commit is tagged, publishes to PyPI

### Creating a Release

To publish a new version to PyPI:

1. Update the version in `django_oauth_guard/__init__.py`
2. Commit the changes
3. Tag the commit with the version: `git tag v0.1.0`
4. Push the tag: `git push origin v0.1.0`
5. Create a new release on GitHub using the tag

The publish workflow will automatically run when the release is created.

## Troubleshooting

### Common Issues

1. **Users being logged out unexpectedly**:
   - Check your fingerprint similarity threshold, it may be too high
   - Review your validation probability, it may be triggering excessive checks
   - Ensure your token refresh is properly configured

2. **High API usage with OAuth providers**:
   - Adjust the `VALIDATION_PROBABILITY` and `VALIDATION_INTERVAL` settings
   - Ensure caching is properly configured in your Django settings

3. **Token validation errors**:
   - Check provider-specific settings like `FACEBOOK_APP_ID`
   - Verify your OAuth provider settings in django-allauth
   - Look for API rate limiting issues with the OAuth providers

4. **Problems with custom providers**:
   - Verify the import paths in your settings
   - Ensure your validator and refresher functions are correct
   - Check for API changes in the provider's documentation

### Debugging

For detailed debugging, enable logging for the middleware:

```python
# In your Django settings
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'oauth_guard_debug.log',
        },
    },
    'loggers': {
        'django_oauth_guard': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
        },
    },
}
```

### Performance Tuning

For large applications, consider these performance optimizations:

1. **Reduce validation frequency**:
   ```python
   'VALIDATION_PROBABILITY': 0.01,  # 1% of requests
   ```

2. **Increase validation interval**:
   ```python
   'VALIDATION_INTERVAL': 3600,  # 1 hour between checks
   ```

3. **Optimize fingerprint components**:
   ```python
   'FINGERPRINT_COMPONENTS': ['HTTP_USER_AGENT', 'HTTP_ACCEPT_LANGUAGE'],  # Exclude IP
   ```

4. **Tune Django's cache settings**:
   ```python
   CACHES = {
       'default': {
           'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
           'LOCATION': '127.0.0.1:11211',
       }
   }
   ```