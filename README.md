# Django OAuth Guard

[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org)
[![Django](https://img.shields.io/badge/django-4.2%20%7C%205.0-green)](https://www.djangoproject.com)

A comprehensive security middleware for Django applications using OAuth authentication (especially with django-allauth).

## Background

OAuth implementations often lack validation of tokens once a user is authenticated. This creates a security vulnerability: if a user revokes access to your application via their OAuth provider (e.g., Google), they may remain logged in to your application indefinitely.

This package addresses that vulnerability and adds several other security features to enhance session management.

## Features

- **OAuth Token Validation**: Periodically validates OAuth tokens with providers to detect revocation
- **Token Refresh**: Automatically refreshes tokens before they expire for providers that support it
- **Session Fingerprinting**: Detects potential session hijacking by validating browser/device information
- **Activity Tracking**: Enforces re-authentication after periods of inactivity
- **Maximum Session Age**: Enforces a maximum session duration regardless of activity
- **Multi-provider Support**: Built-in support for Google, Facebook, Microsoft, GitHub, and LinkedIn

See [ADVANCED.md](ADVANCED.md) for additional features and customization options.

## Quick Start

### Installation

```bash
# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install django-oauth-guard
```

### Configuration

Add the middleware to your Django settings:

```python
MIDDLEWARE = [
    # ... other middleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # Add the OAuth session validator after auth middleware
    'django_oauth_guard.middleware.OAuthValidationMiddleware',
    # ... other middleware
]
```

That's it! The middleware will now work with default settings. See [ADVANCED.md](ADVANCED.md) for custom configuration options.

## Running Tests

```bash
# Set up a test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate
pip install -e ".[test]"

# Run the tests
python runtests.py
```

## Basic Troubleshooting

If users are being logged out too frequently, you can adjust the settings:

```python
# In your Django settings.py
OAUTH_SESSION_VALIDATOR = {
    'VALIDATION_PROBABILITY': 0.01,  # Reduce from default 0.05 (5%)
    'FINGERPRINT_SIMILARITY_THRESHOLD': 0.8,  # More tolerant fingerprinting
}
```

For detailed configuration options and advanced features, see [ADVANCED.md](ADVANCED.md).

## Requirements

- Python 3.9 or higher
- Django 4.2 or higher
- django-allauth 0.40.0 or higher

## License

MIT License