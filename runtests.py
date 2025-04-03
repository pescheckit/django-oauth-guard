#!/usr/bin/env python
import os
import sys
from django.conf import settings
import django

# Minimum Django settings required to run tests
SETTINGS = {
    'DATABASES': {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        },
    },
    'INSTALLED_APPS': [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'django.contrib.sites',
        
        # Required for django-allauth
        'allauth',
        'allauth.account',
        'allauth.socialaccount',
        'allauth.socialaccount.providers.google',
        'allauth.socialaccount.providers.facebook',
        'allauth.socialaccount.providers.microsoft',
        'allauth.socialaccount.providers.github',
        'allauth.socialaccount.providers.linkedin',
        
        # Our app
        'django_oauth_guard',
    ],
    'MIDDLEWARE': [
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
        
        # This is what we're testing
        'django_oauth_guard.middleware.OAuthValidationMiddleware',
    ],
    'TEMPLATES': [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        },
    ],
    'SITE_ID': 1,
    'SECRET_KEY': 'test-key-not-for-production',
    'ROOT_URLCONF': 'tests.urls',
    'OAUTH_SESSION_VALIDATOR': {
        'VALIDATION_PROBABILITY': 1.0,
        'VALIDATION_INTERVAL': 0,
    },
    'AUTHENTICATION_BACKENDS': (
        'django.contrib.auth.backends.ModelBackend',
        'allauth.account.auth_backends.AuthenticationBackend',
    ),
    'CACHES': {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    },
    'FACEBOOK_APP_ID': 'test-app-id',
    'FACEBOOK_APP_SECRET': 'test-app-secret',
}


def run_tests():
    """Configure Django settings and run tests"""
    settings.configure(**SETTINGS)
    django.setup()
    
    # Use pytest if available, otherwise use Django's test runner
    try:
        import pytest
        sys.exit(pytest.main(['django_oauth_guard/tests']))
    except ImportError:
        from django.test.runner import DiscoverRunner
        test_runner = DiscoverRunner(verbosity=2)
        failures = test_runner.run_tests(['django_oauth_guard.tests'])
        sys.exit(failures)


if __name__ == '__main__':
    run_tests()